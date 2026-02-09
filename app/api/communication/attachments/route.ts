/**
 * Attachments API Route - CONSOLIDATED (Phase 2)
 * 
 * Uses centralized services from Phase 1:
 * - attachmentOps from operations.ts for database operations
 * - broadcastToChannel from broadcast.ts for real-time updates
 * - channelOps.isMember() for membership checks
 */
import { type NextRequest, NextResponse } from "next/server"
import { prisma } from '@/lib/prisma'
import { S3Service } from '@/lib/services/s3-service'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { z } from 'zod'
import { apiLogger as logger } from '@/lib/logger'
// Phase 2: Use centralized services from Phase 1
import { attachmentOps, channelOps } from '@/lib/communication/operations'
import { broadcastToChannel } from '@/lib/communication/broadcast'

// ============================================
// Validation Schemas
// ============================================
const uploadQuerySchema = z.object({
  channel_id: z.string().uuid(),
  message_id: z.string().uuid().optional()
})

// ============================================
// Helper Functions
// ============================================
function createErrorResponse(message: string, status: number, details?: unknown) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details ? { details } : {})
  }, { status })
}

// ============================================
// POST /api/communication/attachments - Upload file(s) for a channel/message
// ============================================
export async function POST(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user } = await genericApiRoutesMiddleware(request, 'communication', 'create')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    // Parse form data
    const formData = await request.formData()
    const channelId = formData.get('channel_id') as string
    const messageId = formData.get('message_id') as string | null
    const files = formData.getAll('files') as File[]

    if (!channelId) {
      return createErrorResponse('channel_id is required', 400)
    }

    // Validate channel_id
    try {
      uploadQuerySchema.parse({ channel_id: channelId, message_id: messageId || undefined })
    } catch (error) {
      return createErrorResponse('Invalid channel_id or message_id format', 400)
    }

    if (!files || files.length === 0) {
      return createErrorResponse('No files provided', 400)
    }

    if (files.length > 30) {
      return createErrorResponse('Maximum 30 files allowed per upload', 400)
    }

    // Check if user is member of the channel
    const isMember = await channelOps.isMember(channelId, session.user.id)
    if (!isMember) {
      return createErrorResponse('Access denied to this channel', 403)
    }

    // Upload files to S3 and create attachment records
    const uploadedAttachments = []
    const errors: string[] = []

    for (const file of files) {
      try {
        // Validate file size
        if (file.size > 25 * 1024 * 1024) {
          errors.push(`${file.name}: File too large (max 25MB)`)
          continue
        }

        // Convert file to buffer
        const buffer = Buffer.from(await file.arrayBuffer())

        // Upload to S3
        const uploadResult = await S3Service.uploadFile({
          file: buffer,
          fileName: file.name,
          contentType: file.type,
          fileType: 'CHAT_ATTACHMENTS',
          userId: session.user.id,
          metadata: {
            channelId,
            uploadSource: 'chat'
          }
        })

        if (!uploadResult.success || !uploadResult.data) {
          errors.push(`${file.name}: ${uploadResult.error || 'Upload failed'}`)
          continue
        }

        // Create attachment record in Supabase
        // Note: message_id is required in schema, but we'll create a placeholder message if needed
        let actualMessageId = messageId

        // If no message_id provided, we'll store without message linkage initially
        // The message creation will update this later
        if (!actualMessageId) {
          // Create a placeholder - this will be linked when the actual message is created
          // For now, we'll need to handle orphan attachments or require message_id
          return createErrorResponse('message_id is required for attachment upload', 400)
        }

        const attachment = await prisma.attachments.create({
          data: {
            message_id: actualMessageId,
            channel_id: channelId,
            mongo_uploader_id: session.user.id,
            file_name: file.name,
            file_url: uploadResult.data.url,
            s3_key: uploadResult.data.key,
            s3_bucket: process.env.AWS_S3_BUCKET_NAME,
            file_size: uploadResult.data.size,
            file_type: uploadResult.data.contentType
          }
        })

        uploadedAttachments.push({
          id: attachment.id,
          file_name: attachment.file_name,
          file_url: attachment.file_url,
          s3_key: attachment.s3_key,
          file_size: attachment.file_size,
          file_type: attachment.file_type,
          created_at: attachment.created_at.toISOString()
        })
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error'
        errors.push(`${file.name}: ${errorMessage}`)
      }
    }

    // Broadcast attachment upload event via real-time (non-blocking)
    if (uploadedAttachments.length > 0) {
      broadcastToChannel({
        channelId,
        event: 'attachments_added',
        payload: {
          channel_id: channelId,
          message_id: messageId,
          attachments: uploadedAttachments
        }
      }).catch(err => logger.error('Failed to broadcast attachment event:', err))
    }

    return NextResponse.json({
      success: true,
      data: {
        attachments: uploadedAttachments,
        errors: errors.length > 0 ? errors : undefined
      },
      message: errors.length > 0 
        ? `${uploadedAttachments.length} files uploaded, ${errors.length} failed`
        : `${uploadedAttachments.length} files uploaded successfully`
    })

  } catch (error: unknown) {
    logger.error('Error uploading attachments:', error)
    const errorMessage = error instanceof Error ? error.message : 'Failed to upload attachments'
    return createErrorResponse(errorMessage, 500)
  }
}

// ============================================
// GET /api/communication/attachments - Get attachments for a channel (CONSOLIDATED)
// Supports: ?channel_id= to list attachments, ?download=id to get download URL
// ============================================
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session } = await genericApiRoutesMiddleware(request, 'communication', 'read')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const searchParams = request.nextUrl.searchParams
    const downloadId = searchParams.get('download')

    // DOWNLOAD MODE: Get presigned download URL for a specific attachment
    if (downloadId) {
      const attachment = await prisma.attachments.findUnique({
        where: { id: downloadId }
      })

      if (!attachment) {
        return createErrorResponse('Attachment not found', 404)
      }

      // Verify user has access to the channel
      if (attachment.channel_id) {
        const isMember = await channelOps.isMember(attachment.channel_id, session.user.id)
        if (!isMember) {
          return createErrorResponse('Access denied', 403)
        }
      }

      // Generate fresh download URL with Content-Disposition header
      if (!attachment.s3_key) {
        return createErrorResponse('File not found in storage', 404)
      }

      const downloadUrl = await S3Service.getPresignedDownloadUrl(
        attachment.s3_key,
        'CHAT_ATTACHMENTS',
        attachment.file_name
      )

      return NextResponse.json({
        success: true,
        downloadUrl,
        fileName: attachment.file_name,
        fileType: attachment.file_type,
        fileSize: attachment.file_size
      })
    }

    // LIST MODE: Get attachments for a channel
    const channelId = searchParams.get('channel_id')
    const limit = parseInt(searchParams.get('limit') || '50')
    const offset = parseInt(searchParams.get('offset') || '0')

    if (!channelId) {
      return createErrorResponse('channel_id is required', 400)
    }

    // Check if user is member of the channel
    const isMember = await channelOps.isMember(channelId, session.user.id)
    if (!isMember) {
      return createErrorResponse('Access denied to this channel', 403)
    }

    // Fetch attachments using attachmentOps
    const attachments = await attachmentOps.getByChannel(channelId, { limit, offset })

    // Get total count
    const total = await prisma.attachments.count({
      where: { channel_id: channelId }
    })

    // Refresh presigned URLs for attachments
    type AttachmentRecord = {
      id: string
      file_url: string | null
      s3_key: string | null
      message_id: string
      file_name: string
      file_type: string | null
      file_size: number | null
      created_at: Date
      mongo_uploader_id?: string
    }
    const enrichedAttachments = await Promise.all(
      attachments.map(async (attachment: AttachmentRecord) => {
        let fileUrl = attachment.file_url

        // Refresh presigned URL if we have an S3 key
        if (attachment.s3_key) {
          try {
            fileUrl = await S3Service.getPresignedUrl(attachment.s3_key, 'CHAT_ATTACHMENTS')
          } catch (error) {
            logger.error('Failed to refresh presigned URL for:', attachment.s3_key)
          }
        }

        return {
          id: attachment.id,
          message_id: attachment.message_id,
          file_name: attachment.file_name,
          file_url: fileUrl,
          file_size: attachment.file_size,
          file_type: attachment.file_type,
          uploaded_by: attachment.mongo_uploader_id || 'Unknown',
          created_at: attachment.created_at.toISOString()
        }
      })
    )

    return NextResponse.json({
      success: true,
      data: enrichedAttachments,
      meta: {
        total,
        limit,
        offset,
        hasMore: offset + attachments.length < total
      }
    })

  } catch (error: unknown) {
    logger.error('Error fetching attachments:', error)
    const errorMessage = error instanceof Error ? error.message : 'Failed to fetch attachments'
    return createErrorResponse(errorMessage, 500)
  }
}
// ============================================
// PATCH /api/communication/attachments - Forward attachment to multiple channels
// Feature 28: Share Attachments to Multiple Chats
// ============================================
const forwardSchema = z.object({
  attachmentId: z.string().uuid(),
  targetChannelIds: z.array(z.string().uuid()).min(1).max(10),
  message: z.string().max(500).optional()
})

export async function PATCH(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session } = await genericApiRoutesMiddleware(request, 'communication', 'create')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const body = await request.json()

    // Validate request body
    const parseResult = forwardSchema.safeParse(body)
    if (!parseResult.success) {
      return createErrorResponse('Invalid request data', 400, parseResult.error.flatten())
    }

    const { attachmentId, targetChannelIds, message } = parseResult.data

    // Verify user has access to the source attachment
    const attachment = await prisma.attachments.findUnique({
      where: { id: attachmentId }
    })

    if (!attachment) {
      return createErrorResponse('Attachment not found', 404)
    }

    if (attachment.channel_id) {
      const hasAccess = await channelOps.isMember(attachment.channel_id, session.user.id)
      if (!hasAccess) {
        return createErrorResponse('Access denied to source attachment', 403)
      }
    }

    // Verify user is a member of all target channels
    const accessChecks = await Promise.all(
      targetChannelIds.map(channelId => channelOps.isMember(channelId, session.user.id))
    )

    const deniedChannels = targetChannelIds.filter((_, i) => !accessChecks[i])
    if (deniedChannels.length > 0) {
      return createErrorResponse(
        `Access denied to target channels: ${deniedChannels.join(', ')}`,
        403
      )
    }

    // Forward the attachment to all target channels
    const results = await attachmentOps.forward({
      attachmentId,
      targetChannelIds,
      senderId: session.user.id,
      optionalMessage: message
    })

    // Fetch and broadcast full message data for each forwarded message
    for (const result of results) {
      try {
        // Get the full message with attachments for proper broadcast
        const fullMessage = await prisma.messages.findUnique({
          where: { id: result.messageId },
          include: { attachments: true }
        })

        if (fullMessage) {
          // Build message object matching what onNewMessage expects
          const messageForBroadcast = {
            id: fullMessage.id,
            channel_id: fullMessage.channel_id,
            mongo_sender_id: fullMessage.mongo_sender_id,
            content: fullMessage.content,
            content_type: fullMessage.content_type,
            sender_name: fullMessage.sender_name || 'Unknown User',
            sender_email: fullMessage.sender_email || '',
            sender_avatar: fullMessage.sender_avatar,
            sender_role: fullMessage.sender_role || 'User',
            created_at: fullMessage.created_at.toISOString(),
            is_edited: fullMessage.is_edited,
            is_trashed: fullMessage.is_trashed,
            attachments: fullMessage.attachments.map(att => ({
              id: att.id,
              file_name: att.file_name,
              file_url: att.file_url,
              file_size: att.file_size,
              file_type: att.file_type
            })),
            reactions: [],
            forwarded: true
          }

          broadcastToChannel({
            channelId: result.channelId,
            event: 'new_message',
            payload: messageForBroadcast
          }).catch(err => logger.error('Failed to broadcast forward event:', err))
        }
      } catch (err) {
        logger.error('Failed to fetch/broadcast forwarded message:', err)
      }
    }

    return NextResponse.json({
      success: true,
      data: results,
      message: `Attachment forwarded to ${results.length} channel(s)`
    })

  } catch (error: unknown) {
    logger.error('Error forwarding attachment:', error)
    const errorMessage = error instanceof Error ? error.message : 'Failed to forward attachment'
    return createErrorResponse(errorMessage, 500)
  }
}