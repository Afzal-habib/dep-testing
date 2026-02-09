/**
 * Messages [messageId] API Route - CONSOLIDATED (Phase 2)
 * 
 * Uses centralized services from Phase 1:
 * - messageOps from operations.ts for database operations
 * - broadcastToChannel, broadcastMessageUpdate, broadcastMessageDelete from broadcast.ts
 */
import { type NextRequest, NextResponse } from "next/server"
import { prisma } from '@/lib/prisma'
import { messageOperations } from '@/lib/db-utils'
import { updateMessageSchema, messageIdSchema } from "@/lib/validations/channel"
import { SecurityUtils } from '@/lib/security/validation'
import { getClientInfo } from '@/lib/security/error-handler'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { createAPIErrorResponse } from "@/lib/utils/api-responses"
import { apiLogger as logger } from '@/lib/logger'
import { executeGenericDbQuery } from '@/lib/mongodb'
import MessageAuditLog from '@/models/MessageAuditLog'
import mongoose from 'mongoose'
import { S3Service } from "@/lib/services/s3-service"
// Phase 2: Use centralized services from Phase 1
import { messageOps } from '@/lib/communication/operations'
import { 
  broadcastToChannel, 
  broadcastMessageUpdate, 
  broadcastMessageDelete 
} from '@/lib/communication/broadcast'

// Delete types for the trash system
type DeleteType = 'trash' | 'self' | 'permanent'

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// NOTE: Broadcast now handled by @/lib/communication/broadcast.ts (Phase 1)

// Type for messages with trash fields (until prisma generate is run)
type MessageWithTrash = {
  id: string
  channel_id: string
  mongo_sender_id: string
  content: string
  is_trashed?: boolean
  trashed_at?: Date | null
  trashed_by?: string | null
  trash_reason?: string | null
  hidden_by_users?: string[]
  original_content?: string | null
  sender_name: string
  sender_email: string
  created_at: Date
}

// PUT /api/communication/messages/[messageId] - Update message
export async function PUT(
  request: NextRequest,
  { params: paramsPromise }: { params: Promise<{ messageId: string }> }
) {
  try {
    const params = await paramsPromise
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'update')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    // Validate message ID
    const validatedParams = messageIdSchema.parse(params)

    // Check if user owns the message
    const message = await prisma.messages.findUnique({
      where: { id: validatedParams.messageId },
    })

    if (!message) {
      return createErrorResponse('Message not found', 404)
    }

    if (message.mongo_sender_id !== session.user.id && !isSuperAdmin) {
      return createErrorResponse('Access denied - you can only edit your own messages', 403)
    }

    // Check if request has form data (for file uploads) or JSON
    const contentType = request.headers.get('content-type') || ''
    let validatedData: any
    let files: File[] = []

    if (contentType.includes('multipart/form-data')) {
      // Handle form data with potential file uploads
      const formData = await request.formData()
      const content = formData.get('content') as string
      const attachmentsToRemove = formData.get('attachments_to_remove') as string
      files = formData.getAll('files') as File[]

      // Parse attachments to remove
      let parsedAttachmentsToRemove: string[] = []
      if (attachmentsToRemove) {
        try {
          parsedAttachmentsToRemove = JSON.parse(attachmentsToRemove)
        } catch {
          // If not JSON, try comma-separated
          parsedAttachmentsToRemove = attachmentsToRemove.split(',').map(id => id.trim()).filter(Boolean)
        }
      }

      validatedData = {
        content: content || '',
        attachments_to_remove: parsedAttachmentsToRemove
      }
    } else {
      // Handle JSON data
      const body = await request.json()
      validatedData = updateMessageSchema.parse(body)
    }

    // Handle attachment removal if specified
    if (validatedData.attachments_to_remove && validatedData.attachments_to_remove.length > 0) {
      // Delete attachments from database and S3
      for (const attachmentId of validatedData.attachments_to_remove) {
        try {
          // Get attachment details
          const attachment = await prisma.attachments.findUnique({
            where: { id: attachmentId }
          })

          if (attachment && attachment.message_id === validatedParams.messageId) {
            // Delete from S3
            if (attachment.s3_key) {
              await S3Service.deleteFile(attachment.s3_key)
            }

            // Delete from database
            await prisma.attachments.delete({
              where: { id: attachmentId }
            })
          }
        } catch (error) {
          logger.error(`Failed to delete attachment ${attachmentId}:`, error)
          // Continue with other attachments
        }
      }
    }

    // Handle new file uploads if any
    const uploadedAttachments = []
    if (files && files.length > 0) {
      for (const file of files) {
        try {
          // Validate file size
          if (file.size > 25 * 1024 * 1024) {
            return createErrorResponse(`${file.name}: File too large (max 25MB)`, 400)
          }

          // Upload to S3
          const uploadResult = await S3Service.uploadFile({
            file: Buffer.from(await file.arrayBuffer()),
            fileName: file.name,
            contentType: file.type,
            fileType: 'CHAT_ATTACHMENTS',
            userId: session.user.id,
          })

          // Create attachment record
          const attachment = await prisma.attachments.create({
            data: {
              id: crypto.randomUUID(),
              message_id: validatedParams.messageId,
              channel_id: message.channel_id,
              mongo_uploader_id: session.user.id,
              file_name: file.name,
              file_url: uploadResult.data?.url || '',
              s3_key: uploadResult.data?.key || '',
              file_size: file.size,
              file_type: file.type,
            }
          })

          uploadedAttachments.push(attachment)
        } catch (error) {
          logger.error(`Failed to upload file ${file.name}:`, error)
          return createErrorResponse(`Failed to upload ${file.name}`, 500)
        }
      }
    }

    // Update message using messageOperations
    const updatedMessage = await messageOperations.update(validatedParams.messageId, validatedData.content)

    // Broadcast message update using Phase 1 function
    broadcastMessageUpdate(message.channel_id, validatedParams.messageId, {
      content: validatedData.content,
      attachmentsAdded: uploadedAttachments.length,
      attachmentsRemoved: validatedData.attachments_to_remove?.length || 0
    }).catch(err => logger.error('Failed to broadcast message update:', err))

    return NextResponse.json({
      success: true,
      data: {
        ...updatedMessage,
        attachments: uploadedAttachments
      },
      message: 'Message updated successfully'
    })
  } catch (error: any) {
    logger.error('Error updating message:', error)
    return createAPIErrorResponse('Failed to update message', 500, undefined, getClientInfo(request))
  }
}

// DELETE /api/communication/messages/[messageId] - Trash or hide message
// Query params:
//   - deleteType: 'trash' (default) | 'self' | 'permanent'
//   - reason: optional reason for trashing
export async function DELETE(
  request: NextRequest,
  { params: paramsPromise }: { params: Promise<{ messageId: string }> }
) {
  try {
    const params = await paramsPromise
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'delete')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    // Validate message ID
    const validatedParams = messageIdSchema.parse(params)
    const messageId = validatedParams.messageId

    // Parse query params for delete type and reason
    const searchParams = request.nextUrl.searchParams
    const deleteType = (searchParams.get('deleteType') || 'trash') as DeleteType
    const reason = searchParams.get('reason') || ''

    // Fetch the message
    const messageRaw = await prisma.messages.findUnique({
      where: { id: messageId },
    })

    if (!messageRaw) {
      return createErrorResponse('Message not found', 404)
    }

    // Type assertion for trash fields (until prisma generate runs after migration)
    const message = messageRaw as unknown as MessageWithTrash

    // Check if already trashed (for trash operation)
    if (deleteType === 'trash' && message.is_trashed) {
      return createErrorResponse('Message is already in trash', 400)
    }

    const userId = session.user.id
    const isOwner = message.mongo_sender_id === userId

    // Permission check - only owner or admin can trash/delete
    if (!isOwner && !isSuperAdmin) {
      return createErrorResponse('You can only delete your own messages', 403)
    }

    // "Hide for Me" - just add user to hidden_by_users array
    if (deleteType === 'self') {
      // Check if already hidden for this user
      const hiddenUsers = message.hidden_by_users || []
      if (hiddenUsers.includes(userId)) {
        return createErrorResponse('Message is already hidden', 400)
      }

      await prisma.messages.update({
        where: { id: messageId },
        data: {
          hidden_by_users: {
            push: userId
          }
        } as any // Type assertion for new field
      })

      // Broadcast hide event (only to the user who hid it - via notifications channel)
      broadcastToChannel({
        channelId: message.channel_id,
        event: 'message_hidden',
        payload: {
          messageId,
          channelId: message.channel_id,
          hiddenBy: userId
        }
      }).catch(err => logger.error('Failed to broadcast message hidden:', err))

      return NextResponse.json({ 
        success: true, 
        deleteType: 'self',
        message: 'Message hidden successfully'
      })
    }

    // "Move to Trash" - can be restored within 30 days
    if (deleteType === 'trash') {
      await prisma.messages.update({
        where: { id: messageId },
        data: {
          is_trashed: true,
          trashed_at: new Date(),
          trashed_by: userId,
          trash_reason: reason || null,
          original_content: message.content // Preserve for restoration
        } as any // Type assertion for new fields
      })

      // Create audit log in MongoDB (for compliance)
      await executeGenericDbQuery(async () => {
        return await MessageAuditLog.create({
          supabase_message_id: messageId,
          supabase_channel_id: message.channel_id,
          action: 'trashed',
          actor_id: new mongoose.Types.ObjectId(userId),
          actor_name: (session.user as any).name || 'Unknown',
          actor_email: (session.user as any).email || '',
          actor_role: isSuperAdmin ? 'super_admin' : 'user',
          previous_content: message.content,
          metadata: {
            trash_reason: reason || undefined,
            message_created_at: message.created_at,
            sender_mongo_id: message.mongo_sender_id,
            sender_name: message.sender_name,
            sender_email: message.sender_email
          }
        })
      })

      // Broadcast via Supabase Realtime using Phase 1 function
      broadcastToChannel({
        channelId: message.channel_id,
        event: 'message_trash',
        payload: {
          messageId,
          channelId: message.channel_id,
          trashedBy: userId
        }
      }).catch(err => logger.error('Failed to broadcast message trash:', err))

      return NextResponse.json({ 
        success: true, 
        deleteType: 'trash',
        message: 'Message moved to trash. You can restore it within 30 days.'
      })
    }

    // "Permanent Delete" - only for super admins or already trashed messages
    if (deleteType === 'permanent') {
      if (!isSuperAdmin && !message.is_trashed) {
        return createErrorResponse('Only trashed messages can be permanently deleted', 403)
      }

      // Get all attachments for this message before deleting
      const attachments = await prisma.attachments.findMany({
        where: { message_id: messageId },
        select: { id: true, s3_key: true, file_name: true }
      })

      // Delete files from S3
      type AttachmentWithS3 = { id: string; s3_key: string | null; file_name: string }
      const s3DeletePromises = attachments
        .filter((att: AttachmentWithS3) => att.s3_key) // Only delete if s3_key exists
        .map((att: AttachmentWithS3) => S3Service.deleteFile(att.s3_key!))

      const s3DeleteResults = await Promise.allSettled(s3DeletePromises)
      const s3DeleteErrors = s3DeleteResults
        .filter((result: PromiseSettledResult<unknown>) => result.status === 'rejected')
        .map((result: PromiseSettledResult<unknown>, index: number) => ({
          file: attachments.filter((att: AttachmentWithS3) => att.s3_key)[index]?.file_name || 'unknown',
          error: (result as PromiseRejectedResult).reason
        }))

      // Log S3 deletion errors but don't fail the operation
      if (s3DeleteErrors.length > 0) {
        logger.warn('Some files could not be deleted from S3 during message permanent deletion:', s3DeleteErrors)
      }

      // Create final audit log before permanent deletion
      await executeGenericDbQuery(async () => {
        return await MessageAuditLog.create({
          supabase_message_id: messageId,
          supabase_channel_id: message.channel_id,
          action: 'permanently_deleted',
          actor_id: new mongoose.Types.ObjectId(userId),
          actor_name: (session.user as any).name || 'Unknown',
          actor_email: (session.user as any).email || '',
          actor_role: isSuperAdmin ? 'super_admin' : 'user',
          previous_content: message.original_content || message.content,
          metadata: {
            trashed_at: message.trashed_at,
            trashed_by: message.trashed_by,
            trash_reason: message.trash_reason,
            message_created_at: message.created_at,
            sender_mongo_id: message.mongo_sender_id,
            sender_name: message.sender_name,
            sender_email: message.sender_email,
            attachments_deleted: attachments.length,
            s3_delete_errors: s3DeleteErrors.length
          }
        })
      })

      // Delete message permanently (cascade deletes reactions, attachments, etc.)
      await messageOperations.delete(messageId)

      // Broadcast permanent deletion using Phase 1 function
      broadcastMessageDelete(message.channel_id, messageId, userId)
        .catch(err => logger.error('Failed to broadcast message deletion:', err))

      return NextResponse.json({
        success: true,
        deleteType: 'permanent',
        message: 'Message permanently deleted',
        attachmentsDeleted: attachments.length,
        s3DeleteErrors: s3DeleteErrors.length > 0 ? s3DeleteErrors : undefined
      })
    }

    return createErrorResponse('Invalid delete type', 400)
  } catch (error: any) {
    logger.error('Error deleting message:', error)
    return createAPIErrorResponse('Failed to delete message', 500, undefined, getClientInfo(request))
  }
}

// POST /api/communication/messages/[messageId] - Restore message (CONSOLIDATED)
// Supports: ?action=restore
export async function POST(
  request: NextRequest,
  { params: paramsPromise }: { params: Promise<{ messageId: string }> }
) {
  try {
    const params = await paramsPromise
    const { session, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'update')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const validatedParams = messageIdSchema.parse(params)
    const messageId = validatedParams.messageId

    const searchParams = request.nextUrl.searchParams
    const action = searchParams.get('action')

    // Action: restore - Restore message from trash
    if (action === 'restore') {
      const message = await prisma.messages.findUnique({
        where: { id: messageId },
        include: {
          channels: { select: { id: true, name: true, type: true } },
          reactions: true,
          attachments: true,
          read_receipts: true
        }
      })

      if (!message) {
        return createErrorResponse('Message not found', 404)
      }

      const messageWithTrash = message as typeof message & {
        is_trashed?: boolean
        trashed_at?: Date | null
      }

      if (!messageWithTrash.is_trashed) {
        return createErrorResponse('Message is not in trash', 400)
      }

      const userId = session.user.id
      const isOwner = message.mongo_sender_id === userId

      if (!isOwner && !isSuperAdmin) {
        return createErrorResponse('You can only restore your own messages', 403)
      }

      // Check 30-day window
      const trashedAt = new Date(messageWithTrash.trashed_at!)
      const now = new Date()
      const daysSinceTrashed = Math.floor((now.getTime() - trashedAt.getTime()) / (1000 * 60 * 60 * 24))

      if (daysSinceTrashed > 30) {
        return createErrorResponse('Message cannot be restored. It has been in trash for more than 30 days.', 400)
      }

      // Restore message
      const restoredMessage = await prisma.messages.update({
        where: { id: messageId },
        data: {
          is_trashed: false,
          trashed_at: null,
          trashed_by: null,
          trash_reason: null
        } as any,
        include: {
          channels: { select: { id: true, name: true, type: true } },
          reactions: true,
          attachments: true,
          read_receipts: true
        }
      })

      // Create audit log in MongoDB
      await executeGenericDbQuery(async () => {
        return await MessageAuditLog.create({
          supabase_message_id: messageId,
          supabase_channel_id: message.channel_id,
          action: 'restored',
          actor_id: new mongoose.Types.ObjectId(userId),
          actor_name: (session.user as any).name || 'Unknown',
          actor_email: (session.user as any).email || '',
          actor_role: isSuperAdmin ? 'super_admin' : 'user',
          new_content: message.content,
          metadata: { days_in_trash: daysSinceTrashed }
        })
      })

      // Transform for response
      const transformedMessage = {
        ...restoredMessage,
        sender: {
          mongo_member_id: restoredMessage.mongo_sender_id,
          name: restoredMessage.sender_name || 'Unknown User',
          email: restoredMessage.sender_email || '',
          avatar: restoredMessage.sender_avatar || '',
          role: restoredMessage.sender_role || 'User',
          userType: 'User' as const,
          isOnline: false
        }
      }

      // Broadcast restoration
      broadcastToChannel({
        channelId: message.channel_id,
        event: 'message_restore',
        payload: { messageId, channelId: message.channel_id, restoredBy: userId, message: transformedMessage }
      }).catch(err => logger.error('Failed to broadcast message restoration:', err))

      return NextResponse.json({ 
        success: true, 
        data: transformedMessage,
        message: 'Message restored successfully'
      })
    }

    return createErrorResponse('Invalid action. Use restore', 400)
  } catch (error: any) {
    logger.error('Error in POST message:', error)
    return createAPIErrorResponse('Failed to process request', 500, undefined, getClientInfo(request))
  }
}
