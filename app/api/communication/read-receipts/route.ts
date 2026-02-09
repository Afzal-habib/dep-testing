/**
 * Read Receipts API Route - CONSOLIDATED (Phase 2)
 * 
 * Uses centralized services from Phase 1:
 * - readReceiptOps from operations.ts for database operations
 * - broadcastReadReceipt, broadcastBulkReadReceipt from broadcast.ts for real-time updates
 * - channelOps.isMember() for membership checks
 */
import { NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { apiLogger as logger } from '@/lib/logger'
// Phase 2: Use centralized services from Phase 1
import { readReceiptOps, channelOps } from '@/lib/communication/operations'
import { broadcastReadReceipt, broadcastBulkReadReceipt } from '@/lib/communication/broadcast'

// ============================================
// Helper Functions
// ============================================
function createErrorResponse(message: string, status: number) {
  return NextResponse.json({ error: message }, { status })
}

// ============================================
// POST /api/communication/read-receipts - Mark message(s) as read
// ============================================
// Supports:
// - Single message: { message_id, channel_id }
// - All channel messages: { channel_id, mark_all: true }
export async function POST(request: NextRequest) {
  try {
    const { session } = await genericApiRoutesMiddleware(request, 'communication', 'create')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const body = await request.json()
    const { message_id, channel_id, mark_all } = body
    const userId = session.user.id

    // Validate input
    if (!message_id && !mark_all) {
      return createErrorResponse('Either message_id or mark_all with channel_id is required', 400)
    }

    if (mark_all && !channel_id) {
      return createErrorResponse('channel_id is required when using mark_all', 400)
    }

    // Check if user is member of the channel
    if (channel_id) {
      const isMember = await channelOps.isMember(channel_id, userId)
      if (!isMember) {
        return createErrorResponse('Access denied to this channel', 403)
      }
    }

    // Mark all unread messages in the channel as read
    if (mark_all && channel_id) {
      const result = await readReceiptOps.markAllInChannel(channel_id, userId)

      if (result.markedCount === 0) {
        return NextResponse.json({ 
          success: true,
          count: 0,
          message: 'No unread messages to mark as read'
        })
      }

      logger.debug(`Marked ${result.markedCount} messages as read in channel ${channel_id} for user ${userId}`)

      // Broadcast bulk read receipt (non-blocking)
      broadcastBulkReadReceipt(channel_id, {
        userId,
        messageCount: result.markedCount
      }).catch(err => logger.error('Failed to broadcast bulk read receipt:', err))

      return NextResponse.json({ 
        success: true,
        count: result.markedCount,
        message: `Marked ${result.markedCount} messages as read`
      })
    }

    // Mark single message as read
    const receipt = await readReceiptOps.mark(message_id, userId)

    // Broadcast read receipt (non-blocking)
    if (channel_id) {
      broadcastReadReceipt(channel_id, {
        messageId: message_id,
        userId,
        readAt: new Date().toISOString()
      }).catch(err => logger.error('Failed to broadcast read receipt:', err))
    }

    return NextResponse.json({ success: true, receipt })
  } catch (error) {
    logger.error('Error marking message as read:', error)
    return createErrorResponse('Internal server error', 500)
  }
}

// ============================================
// GET /api/communication/read-receipts - Get read receipts for a message
// ============================================
export async function GET(request: NextRequest) {
  try {
    const { session } = await genericApiRoutesMiddleware(request, 'communication', 'read')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const { searchParams } = new URL(request.url)
    const messageId = searchParams.get('message_id')
    const channelId = searchParams.get('channel_id')

    if (!messageId && !channelId) {
      return createErrorResponse('message_id or channel_id is required', 400)
    }

    // If channel_id provided, check membership
    if (channelId) {
      const isMember = await channelOps.isMember(channelId, session.user.id)
      if (!isMember) {
        return createErrorResponse('Access denied', 403)
      }
    }

    if (messageId) {
      // Check access to message via its channel
      const message = await prisma.messages.findUnique({
        where: { id: messageId },
        select: { channel_id: true }
      })

      if (!message) {
        return createErrorResponse('Message not found', 404)
      }

      const isMember = await channelOps.isMember(message.channel_id, session.user.id)
      if (!isMember) {
        return createErrorResponse('Access denied', 403)
      }

      const receipts = await readReceiptOps.getByMessage(messageId)
      return NextResponse.json({ success: true, receipts })
    }

    // Get unread count for channel
    if (channelId) {
      const unreadCount = await readReceiptOps.getUnreadCount(channelId, session.user.id)
      return NextResponse.json({ success: true, unreadCount })
    }

    return createErrorResponse('Invalid request', 400)
  } catch (error) {
    logger.error('Error fetching read receipts:', error)
    return createErrorResponse('Internal server error', 500)
  }
}