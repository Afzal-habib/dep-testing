/**
 * Messages API Route - CONSOLIDATED (Phase 2)
 * 
 * Uses centralized services from Phase 1:
 * - messageOps from operations.ts for database operations
 * - broadcastToChannel, broadcastNewMessage, sendMentionNotification from broadcast.ts
 * - channelOps.isMember() for membership checks
 */
import { type NextRequest, NextResponse } from "next/server"
import { prisma } from '@/lib/prisma'
import { messageOperations } from '@/lib/db-utils'
import { createMessageSchema, messageQuerySchema } from "@/lib/validations/channel"
import { getClientInfo } from '@/lib/security/error-handler'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { createAPIErrorResponse } from "@/lib/utils/api-responses"
import { apiLogger as logger } from '@/lib/logger'
// Phase 2: Use centralized services from Phase 1
import { channelOps } from '@/lib/communication/operations'
import { 
  broadcastToChannel, 
  broadcastNewMessage, 
  sendMentionNotification,
  broadcastToUser 
} from '@/lib/communication/broadcast'

// NOTE: Supabase broadcasting is now handled by @/lib/communication/broadcast.ts (Phase 1)

// ============================================
// Type Definitions
// ============================================

/** Sender data structure for messages */
interface ISenderData {
  mongo_member_id: string
  name: string
  email: string
  avatar: string
  role: string
  userType: 'User' | 'Client'
  isOnline: boolean
}

/** Message with sender data included */
interface IMessageWithSender {
  id: string
  channel_id: string
  mongo_sender_id: string
  content: string
  content_type: string
  sender_name: string
  sender_email: string
  sender_avatar?: string
  sender_role: string
  created_at: Date
  sender: ISenderData
  [key: string]: unknown // Allow additional Prisma fields
}

/** MongoDB user document (lean) */
interface IMongoUser {
  _id: string
  name?: string
  email?: string
  avatar?: string
  isClient?: boolean
  role?: string | { name?: string } | unknown
}

// ============================================
// Helper Functions
// ============================================

/** Create consistent error responses */
function createErrorResponse(
  message: string, 
  status: number, 
  details?: Record<string, unknown> | string | null
): NextResponse {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details ? { details } : {})
  }, { status })
}

/**
 * Transform a Prisma message to include sender object from denormalized fields.
 * This avoids MongoDB lookups for real-time performance.
 */
function transformMessageWithSender(message: Record<string, unknown>): IMessageWithSender {
  return {
    ...message,
    sender: {
      mongo_member_id: String(message.mongo_sender_id || ''),
      name: String(message.sender_name || 'Unknown User'),
      email: String(message.sender_email || ''),
      avatar: String(message.sender_avatar || ''),
      role: String(message.sender_role || 'User'),
      userType: 'User' as const,
      isOnline: false,
    }
  } as IMessageWithSender
}

/**
 * Extract role name from MongoDB role field.
 * Handles: string, ObjectId, or populated {name: string} object
 */
function extractRoleName(role: unknown): string {
  if (!role) return 'User'
  
  if (typeof role === 'string') {
    return role
  }
  
  if (typeof role === 'object' && role !== null) {
    // Populated role object with name field
    const roleObj = role as { name?: string }
    if (roleObj.name && typeof roleObj.name === 'string') {
      return roleObj.name
    }
  }
  
  // ObjectId or unknown - default to 'User'
  return 'User'
}

// GET /api/communication/messages - Get messages for a channel (CONSOLIDATED)
// Supports: ?channel_id=, ?search=, ?trash=true
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'read')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const searchParams = request.nextUrl.searchParams
    const searchQuery = searchParams.get('search')
    const trashMode = searchParams.get('trash') === 'true'

    // TRASH MODE: Get user's trashed messages
    if (trashMode) {
      const channelId = searchParams.get('channelId') || searchParams.get('channel_id')
      const page = parseInt(searchParams.get('page') || '1')
      const limit = parseInt(searchParams.get('limit') || '20')

      const where: any = {
        mongo_sender_id: session.user.id,
        is_trashed: true
      }

      if (channelId) {
        where.channel_id = channelId
      }

      const [messages, total] = await Promise.all([
        prisma.messages.findMany({
          where,
          orderBy: { trashed_at: 'desc' } as any,
          skip: (page - 1) * limit,
          take: limit,
          include: {
            channels: { select: { id: true, name: true, type: true } },
            attachments: { select: { id: true, file_name: true, file_type: true } }
          }
        }),
        prisma.messages.count({ where })
      ])

      const now = new Date()
      const messagesWithExpiry = (messages as any[]).map(msg => {
        const trashedAt = new Date(msg.trashed_at || now)
        const daysSinceTrashed = Math.floor((now.getTime() - trashedAt.getTime()) / (1000 * 60 * 60 * 24))
        const daysRemaining = Math.max(0, 30 - daysSinceTrashed)
        const expiresAt = new Date(trashedAt.getTime() + 30 * 24 * 60 * 60 * 1000)
        
        return {
          ...transformMessageWithSender(msg),
          trashed_at: msg.trashed_at?.toISOString() || now.toISOString(),
          trashed_by: msg.trashed_by || '',
          trash_reason: msg.trash_reason,
          days_remaining: daysRemaining,
          expires_at: expiresAt.toISOString(),
          is_expiring_soon: daysRemaining <= 7,
          channel: msg.channels
        }
      })

      const totalPages = Math.ceil(total / limit)

      return NextResponse.json({
        success: true,
        data: messagesWithExpiry,
        pagination: { page, limit, total, totalPages, hasMore: page < totalPages }
      })
    }

    // SEARCH MODE: Search messages in a channel
    if (searchQuery) {
      const channelId = searchParams.get('channel_id')
      const limit = parseInt(searchParams.get('limit') || '20')
      const offset = parseInt(searchParams.get('offset') || '0')

      if (!channelId) {
        return createErrorResponse('channel_id is required for search', 400)
      }

      // Check if user is member of the channel
      const isMember = await channelOps.isMember(channelId, session.user.id)
      if (!isMember) {
        return createErrorResponse('Access denied to this channel', 403)
      }

      // Search messages using raw SQL for case-insensitive substring search (ILIKE)
      const messages = await prisma.$queryRaw<any[]>`
        SELECT m.*,
          COALESCE(json_agg(DISTINCT r) FILTER (WHERE r.id IS NOT NULL), '[]'::json) as read_receipts,
          COALESCE(json_agg(DISTINCT a) FILTER (WHERE a.id IS NOT NULL), '[]'::json) as attachments
        FROM messages m
        LEFT JOIN read_receipts r ON r.message_id = m.id
        LEFT JOIN attachments a ON a.message_id = m.id
        WHERE m.channel_id = ${channelId}
        AND m.content ILIKE ${'%' + searchQuery + '%'}
        GROUP BY m.id
        ORDER BY m.created_at DESC
        LIMIT ${limit}
        OFFSET ${offset}
      `

      const totalResult = await prisma.$queryRaw<any[]>`
        SELECT COUNT(*) as count FROM messages
        WHERE channel_id = ${channelId}
        AND content ILIKE ${'%' + searchQuery + '%'}
      `
      const totalCount = parseInt(totalResult[0].count)

      const transformedMessages = messages.map((msg: Record<string, unknown>) => transformMessageWithSender(msg)).filter(Boolean)

      return NextResponse.json({
        success: true,
        data: transformedMessages,
        meta: {
          total: totalCount,
          limit,
          offset,
          query: searchQuery,
          hasMore: offset + messages.length < totalCount
        }
      })
    }

    // DEFAULT MODE: Get channel messages
    const queryParams = {
      channel_id: searchParams.get('channel_id') || '',
      limit: searchParams.get('limit') || '50',
      offset: searchParams.get('offset') || '0',
    }

    const parsedParams = {
      channel_id: queryParams.channel_id,
      limit: parseInt(queryParams.limit),
      offset: parseInt(queryParams.offset),
    }

    const validatedParams = messageQuerySchema.parse(parsedParams)

    // Check if user is member of the channel
    const isMember = await channelOps.isMember(validatedParams.channel_id, session.user.id)
    if (!isMember) {
      return createErrorResponse('Access denied to this channel', 403)
    }

    // Pass currentUserId to filter out messages hidden by this user
    const messages = await messageOperations.getChannelMessages(
      validatedParams.channel_id,
      validatedParams.limit,
      validatedParams.offset,
      session.user.id // Filter hidden messages for this user
    )

    // Transform messages using denormalized sender fields (NO MongoDB lookup needed!)
    const transformedMessages = messages.map((message: any) => transformMessageWithSender(message))

    return NextResponse.json({
      success: true,
      data: transformedMessages.reverse(), // Reverse to show oldest first
      meta: {
        total: transformedMessages.length,
        limit: validatedParams.limit,
        offset: validatedParams.offset
      }
    })
  } catch (error: any) {
    logger.error('Error fetching messages:', error)
    return createAPIErrorResponse('Failed to fetch messages', 500, undefined, getClientInfo(request))
  }
}

// POST /api/communication/messages - Send a new message (CONSOLIDATED)
// Supports: JSON body for regular messages, FormData for file attachments
export async function POST(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'create')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const contentType = request.headers.get('content-type') || ''
    const isFormData = contentType.includes('multipart/form-data')

    let channelId: string
    let content: string
    let msgContentType: string
    let threadId: string | undefined
    let parentMessageId: string | undefined
    let mentionedUserIds: string[] = []
    let files: File[] = []
    let audioAttachment: any = null

    if (isFormData) {
      // Handle FormData (file uploads)
      const formData = await request.formData()
      channelId = formData.get('channel_id') as string
      content = (formData.get('content') as string) || ''
      msgContentType = (formData.get('content_type') as string) || 'text'
      threadId = (formData.get('thread_id') as string) || undefined
      parentMessageId = (formData.get('parent_message_id') as string) || undefined
      const mentionedUserIdsStr = formData.get('mongo_mentioned_user_ids') as string | null
      files = formData.getAll('files') as File[]

      if (mentionedUserIdsStr) {
        try {
          mentionedUserIds = JSON.parse(mentionedUserIdsStr)
        } catch {
          mentionedUserIds = mentionedUserIdsStr.split(',').map(id => id.trim()).filter(Boolean)
        }
      }

      if (!channelId) {
        return createErrorResponse('channel_id is required', 400)
      }

      if (!content.trim() && files.length === 0) {
        return createErrorResponse('Message must have content or at least one file', 400)
      }
    } else {
      // Handle JSON body
      const body = await request.json()
      const validatedData = createMessageSchema.parse(body)

      channelId = validatedData.channel_id
      content = validatedData.content
      msgContentType = validatedData.content_type
      threadId = validatedData.thread_id
      parentMessageId = validatedData.parent_message_id
      mentionedUserIds = validatedData.mongo_mentioned_user_ids || []
      audioAttachment = validatedData.audio_attachment
    }

    // Get channel to check settings
    const channel = await prisma.channels.findUnique({
      where: { id: channelId },
      select: { id: true, admin_only_post: true }
    })

    if (!channel) {
      return createErrorResponse('Channel not found', 404)
    }

    // Check if user is member of the channel and get their role
    const memberRecord = await channelOps.getMember(channelId, session.user.id)
    if (!memberRecord) {
      return createErrorResponse('Access denied to this channel', 403)
    }

    // Check admin-only-post restriction
    if (channel.admin_only_post) {
      if (memberRecord.role !== 'admin' && memberRecord.role !== 'owner') {
        return createErrorResponse('Only admins can post messages in this channel', 403)
      }
    }

    // Use sender info from middleware (already fetched from MongoDB)
    const senderData = user

    // Extract sender details for denormalization (ensure all values are strings)
    const senderName: string = String(senderData?.name || senderData?.email || 'Unknown User')
    const senderEmail: string = String(senderData?.email || '')
    const senderAvatar: string | undefined = senderData?.avatar ? String(senderData.avatar) : undefined
    const senderRole: string = extractRoleName(senderData?.role)

    // Create the message with denormalized sender data (no MongoDB call needed on read)
    const message = await messageOperations.create({
      channel_id: channelId,
      mongo_sender_id: session.user.id,
      content: content,
      content_type: files.length > 0 ? 'file' : msgContentType,
      thread_id: threadId,
      parent_message_id: parentMessageId,
      mongo_mentioned_user_ids: mentionedUserIds,
      // Denormalized sender fields - stored directly in Supabase
      sender_name: senderName,
      sender_email: senderEmail,
      sender_avatar: senderAvatar,
      sender_role: senderRole,
    })

    // Handle audio attachment for voice messages
    let attachments: any[] = []
    if (audioAttachment && msgContentType === 'audio') {
      const audioAttachmentRecord = await prisma.attachments.create({
        data: {
          message_id: message.id,
          channel_id: channelId,
          mongo_uploader_id: session.user.id,
          file_name: audioAttachment.file_name || 'Voice Message',
          file_url: audioAttachment.file_url,
          file_size: audioAttachment.file_size,
          file_type: audioAttachment.file_type || 'audio/webm',
        }
      })
      
      attachments.push({
        ...audioAttachmentRecord,
        durationSeconds: audioAttachment.duration_seconds
      })
    }

    // Update channel's last_message_at
    await prisma.channels.update({
      where: { id: channelId },
      data: { last_message_at: new Date() },
    })

    // Transform message to include sender object (for frontend compatibility)
    const messageWithSender = {
      ...transformMessageWithSender(message),
      attachments
    }

    // Handle file uploads asynchronously (if FormData)
    if (isFormData && files.length > 0) {
      // Import S3Service for file uploads
      const { S3Service } = await import('@/lib/services/s3-service')

      // Send response immediately for fast user experience
      const response = NextResponse.json({
        success: true,
        data: messageWithSender,
        message: 'Message sent, uploading files...'
      })

      // Upload files asynchronously
      setImmediate(async () => {
        const uploadedAttachments = []
        const uploadErrors: string[] = []

        for (const file of files) {
          try {
            if (file.size > 25 * 1024 * 1024) {
              uploadErrors.push(`${file.name}: File too large (max 25MB)`)
              continue
            }

            const buffer = Buffer.from(await file.arrayBuffer())

            const uploadResult = await S3Service.uploadFile({
              file: buffer,
              fileName: file.name,
              contentType: file.type,
              fileType: 'CHAT_ATTACHMENTS',
              userId: session.user.id,
              metadata: {
                channelId,
                messageId: message.id,
                uploadSource: 'chat-inline'
              }
            })

            if (!uploadResult.success || !uploadResult.data) {
              uploadErrors.push(`${file.name}: ${uploadResult.error || 'Upload failed'}`)
              continue
            }

            const attachment = await prisma.attachments.create({
              data: {
                message_id: message.id,
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
              message_id: attachment.message_id,
              file_name: attachment.file_name,
              file_url: attachment.file_url,
              s3_key: attachment.s3_key,
              file_size: attachment.file_size,
              file_type: attachment.file_type,
              created_at: attachment.created_at.toISOString()
            })
          } catch (error: unknown) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error'
            uploadErrors.push(`${file.name}: ${errorMessage}`)
          }
        }

        // Broadcast message update with attachments
        broadcastToChannel({
          channelId,
          event: 'attachments_added',
          payload: {
            messageId: message.id,
            attachments: uploadedAttachments,
            uploadErrors: uploadErrors.length > 0 ? uploadErrors : undefined
          }
        }).catch(err => logger.error('Failed to broadcast attachments update:', err))

        // Broadcast new message
        await broadcastNewMessage(channelId, { ...messageWithSender, attachments: uploadedAttachments })
        logger.debug('Message with attachments broadcasted to channel:', channelId)

        // Broadcast mention notifications
        if (mentionedUserIds.length > 0) {
          const mentionPromises = mentionedUserIds.map((mentionedUserId) =>
            broadcastToUser({
              userId: mentionedUserId,
              event: 'mention_notification',
              payload: {
                type: 'mention',
                message_id: message.id,
                channel_id: channelId,
                sender_name: senderName,
                sender_avatar: senderAvatar,
                content_preview: content.slice(0, 100),
                has_attachments: files.length > 0,
                created_at: message.created_at
              }
            })
          )
          await Promise.all(mentionPromises)
        }
      })

      return response
    }

    // For JSON messages, send response immediately
    const response = NextResponse.json({
      success: true,
      data: messageWithSender,
      message: 'Message sent successfully'
    })

    // Broadcast asynchronously (fire-and-forget for performance)
    setImmediate(async () => {
      try {
        const senderId = session.user.id
        logger.info(`🚀 Starting broadcast. Sender ID: ${senderId}, Channel: ${channelId}`)
        
        // Broadcast the message with sender data to realtime subscribers (active channel)
        // Using Phase 1 broadcastNewMessage convenience function
        const channelBroadcast = await broadcastNewMessage(
          channelId,
          messageWithSender
        )
        if (channelBroadcast) {
          logger.debug('Message broadcasted to channel:', channelId)
        } else {
          logger.warn('Failed to broadcast to channel:', channelId)
        }

        // Broadcast mention notifications to mentioned users
        if (mentionedUserIds && mentionedUserIds.length > 0) {
          // Use Phase 1 sendMentionNotification
          const mentionPromises = mentionedUserIds.map((mentionedUserId) =>
            sendMentionNotification(mentionedUserId, {
              channelId: channelId,
              channelName: '', // Will be resolved by client
              messageId: message.id,
              mentionedBy: senderId,
              mentionedByName: senderName,
              preview: content.slice(0, 100)
            })
          )
          await Promise.all(mentionPromises)
        }

        // Broadcast new message notification to all channel members except sender
        const members = await prisma.channel_members.findMany({
          where: { channel_id: channelId },
          select: { mongo_member_id: true }
        })

        logger.info(`Broadcasting to ${members.length} channel members, sender: ${senderId}`)

        // Filter out sender and broadcast to all other members in parallel
        const recipientMembers = members.filter((member: { mongo_member_id: string }) => String(member.mongo_member_id) !== String(senderId))
        
        const notificationPromises = recipientMembers.map((member: { mongo_member_id: string }) =>
          broadcastToUser({
            userId: member.mongo_member_id,
            event: 'new_message',
            payload: { message: messageWithSender }
          })
        )
        
        await Promise.all(notificationPromises)
        logger.info(`Broadcast complete: sent to ${recipientMembers.length} members for channel ${channelId}`)
      } catch (error) {
        logger.error('Failed to broadcast message:', error)
        // Don't fail the request if broadcast fails
      }
    })

    return response
  } catch (error: unknown) {
    logger.error('Error sending message:', error)
    
    // Extract error details for debugging
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    const errorStack = error instanceof Error ? error.stack : undefined
    
    // Log detailed error for server-side debugging
    logger.error('Detailed error:', {
      message: errorMessage,
      stack: errorStack,
      error
    })
    
    // Return error with details in development (stringify for compatibility)
    const isDev = process.env.NODE_ENV === 'development'
    return createAPIErrorResponse(
      `Failed to send message${isDev ? `: ${errorMessage}` : ''}`, 
      500, 
      undefined, 
      getClientInfo(request)
    )
  }
}