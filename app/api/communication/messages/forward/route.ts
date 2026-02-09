/**
 * Message Forward API Route
 * Handles forwarding messages to multiple channels
 */
import { type NextRequest, NextResponse } from "next/server"
import { prisma } from '@/lib/prisma'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { z } from 'zod'
import { apiLogger as logger } from '@/lib/logger'
import { channelOps } from '@/lib/communication/operations'
import { broadcastToChannel } from '@/lib/communication/broadcast'

// Validation schema
const forwardSchema = z.object({
  messageIds: z.array(z.string().uuid()).min(1).max(50),
  targetChannelIds: z.array(z.string().uuid()).min(1).max(10),
  message: z.string().max(500).optional()
})

function createErrorResponse(message: string, status: number, details?: unknown) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details ? { details } : {})
  }, { status })
}

export async function POST(request: NextRequest) {
  try {
    // Apply middleware
    const { session } = await genericApiRoutesMiddleware(request, 'communication', 'create')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const body = await request.json()

    // Validate request
    const parseResult = forwardSchema.safeParse(body)
    if (!parseResult.success) {
      return createErrorResponse('Invalid request data', 400, parseResult.error.flatten())
    }

    const { messageIds, targetChannelIds, message: optionalMessage } = parseResult.data

    // Get original messages
    const originalMessages = await prisma.messages.findMany({
      where: {
        id: { in: messageIds },
        is_trashed: false
      },
      include: {
        attachments: true
      }
    })

    if (originalMessages.length === 0) {
      return createErrorResponse('No valid messages found', 404)
    }

    // Verify user has access to source messages (check channel membership)
    const sourceChannelIds = [...new Set(originalMessages.map(m => m.channel_id))]
    for (const channelId of sourceChannelIds) {
      const hasAccess = await channelOps.isMember(channelId, session.user.id)
      if (!hasAccess) {
        return createErrorResponse('Access denied to source messages', 403)
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

    // Get sender info for denormalized fields
    const senderInfo = {
      sender_name: (session.user as any).name || 'Unknown User',
      sender_email: (session.user as any).email || '',
      sender_avatar: (session.user as any).image || null,
      sender_role: 'User'
    }

    const results = []

    // Forward each message to each target channel
    for (const targetChannelId of targetChannelIds) {
      const channelMessages = []

      for (const originalMsg of originalMessages) {
        // Build forwarded content - avoid duplicate [Forwarded] labels
        const isAlreadyForwarded = originalMsg.content.startsWith('[Forwarded]')
        const baseContent = isAlreadyForwarded ? originalMsg.content : `[Forwarded]\n${originalMsg.content}`
        let forwardedContent = baseContent
        if (optionalMessage && originalMessages.indexOf(originalMsg) === 0) {
          forwardedContent = `${optionalMessage}\n\n${baseContent}`
        }

        // Create forwarded message
        const forwardedMessage = await prisma.messages.create({
          data: {
            channel_id: targetChannelId,
            mongo_sender_id: session.user.id,
            content: forwardedContent,
            content_type: originalMsg.content_type,
            ...senderInfo
          },
          include: {
            attachments: true
          }
        })

        channelMessages.push(forwardedMessage.id)

        // Copy attachments if any
        let copiedAttachments: any[] = []
        if (originalMsg.attachments.length > 0) {
          await prisma.attachments.createMany({
            data: originalMsg.attachments.map(att => ({
              message_id: forwardedMessage.id,
              channel_id: targetChannelId,
              mongo_uploader_id: session.user.id,
              file_name: att.file_name,
              file_url: att.file_url,
              s3_key: att.s3_key,
              s3_bucket: att.s3_bucket,
              file_size: att.file_size,
              file_type: att.file_type
            }))
          })

          // Fetch the created attachments
          copiedAttachments = await prisma.attachments.findMany({
            where: { message_id: forwardedMessage.id }
          })
        }

        // Build full message object for broadcast (matching what onNewMessage expects)
        const messageForBroadcast = {
          id: forwardedMessage.id,
          channel_id: forwardedMessage.channel_id,
          mongo_sender_id: forwardedMessage.mongo_sender_id,
          content: forwardedMessage.content,
          content_type: forwardedMessage.content_type,
          sender_name: forwardedMessage.sender_name,
          sender_email: forwardedMessage.sender_email,
          sender_avatar: forwardedMessage.sender_avatar,
          sender_role: forwardedMessage.sender_role,
          created_at: forwardedMessage.created_at.toISOString(),
          is_edited: forwardedMessage.is_edited,
          is_trashed: forwardedMessage.is_trashed,
          attachments: copiedAttachments.map(att => ({
            id: att.id,
            file_name: att.file_name,
            file_url: att.file_url,
            file_size: att.file_size,
            file_type: att.file_type
          })),
          reactions: [],
          forwarded: true
        }

        // Broadcast new message with full payload
        broadcastToChannel({
          channelId: targetChannelId,
          event: 'new_message',
          payload: messageForBroadcast
        }).catch((err: Error) => logger.error('Failed to broadcast forwarded message:', err))
      }

      // Update channel's last_message_at
      await prisma.channels.update({
        where: { id: targetChannelId },
        data: { last_message_at: new Date() }
      })

      results.push({
        channelId: targetChannelId,
        messageIds: channelMessages
      })
    }

    return NextResponse.json({
      success: true,
      data: results,
      message: `${originalMessages.length} message(s) forwarded to ${targetChannelIds.length} channel(s)`
    })

  } catch (error: unknown) {
    logger.error('Error forwarding messages:', error)
    const errorMessage = error instanceof Error ? error.message : 'Failed to forward messages'
    return createErrorResponse(errorMessage, 500)
  }
}
