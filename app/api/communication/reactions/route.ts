import { type NextRequest, NextResponse } from "next/server"
import { prisma } from '@/lib/prisma'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { z } from 'zod'
import { apiLogger as logger } from '@/lib/logger'
// Phase 2: Use centralized services from Phase 1
import { reactionOps, channelOps } from '@/lib/communication/operations'
import { broadcastReaction } from '@/lib/communication/broadcast'

// Reaction type (matching Prisma schema)
type Reaction = {
  id: string
  message_id: string
  channel_id: string
  mongo_user_id: string
  user_name: string
  emoji: string
  created_at: Date
}

// ============================================
// Validation Schemas
// ============================================
const addReactionSchema = z.object({
  message_id: z.string().uuid(),
  channel_id: z.string().uuid(),
  emoji: z.string().min(1).max(50) // Emoji can be multi-codepoint (flags, ZWJ sequences, skin tones)
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
// POST /api/communication/reactions - Add/Toggle reaction to a message
// ============================================
export async function POST(request: NextRequest) {
  try {
    const { session } = await genericApiRoutesMiddleware(request, 'communication', 'create')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const body = await request.json()
    
    // Validate request body
    const validationResult = addReactionSchema.safeParse(body)
    if (!validationResult.success) {
      logger.debug('Reaction validation failed:', validationResult.error)
      return createErrorResponse('Invalid request data', 400, validationResult.error)
    }

    const { message_id, channel_id, emoji } = validationResult.data
    const userId = session.user.id
    const userName = (session.user as any)?.name || (session.user as any)?.email || 'Unknown'
    
    // Additional emoji validation to prevent UUID corruption
    if (!emoji || emoji.length > 10 || emoji.includes('-')) {
      logger.error('Invalid emoji received in API:', emoji)
      return createErrorResponse('Invalid emoji provided', 400, { receivedEmoji: emoji })
    }

    // Check if user is member of the channel - using channelOps
    const isMember = await channelOps.isMember(channel_id, userId)
    if (!isMember) {
      return createErrorResponse('Access denied - not a channel member', 403)
    }

    // Check if message exists in the channel
    const message = await prisma.messages.findFirst({
      where: { id: message_id, channel_id }
    })

    if (!message) {
      return createErrorResponse('Message not found', 404)
    }

    // Toggle reaction using reactionOps
    const result = await reactionOps.toggle({
      messageId: message_id,
      channelId: channel_id,
      userId,
      userName,
      emoji
    })

    // Broadcast reaction change (non-blocking)
    broadcastReaction(channel_id, result.action, {
      messageId: message_id,
      emoji,
      userId,
      userName,
      reactionId: result.reaction.id
    }).catch(err => logger.error('Failed to broadcast reaction:', err))

    return NextResponse.json({
      success: true,
      action: result.action,
      data: result.reaction,
      message: `Reaction ${result.action} successfully`
    })

  } catch (error: unknown) {
    logger.error('Error toggling reaction:', error)
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    return createErrorResponse('Failed to toggle reaction', 500, { message: errorMessage })
  }
}

// ============================================
// DELETE /api/communication/reactions - Remove a reaction
// ============================================
export async function DELETE(request: NextRequest) {
  try {
    const { session } = await genericApiRoutesMiddleware(request, 'communication', 'delete')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const { searchParams } = new URL(request.url)
    const reactionId = searchParams.get('reaction_id')
    const messageId = searchParams.get('message_id')
    const emoji = searchParams.get('emoji')
    const userId = session.user.id
    const userName = (session.user as any)?.name || (session.user as any)?.email || 'Unknown'

    // Find the reaction first to verify ownership
    let reaction
    if (reactionId) {
      reaction = await prisma.reactions.findUnique({ where: { id: reactionId } })
    } else if (messageId && emoji) {
      reaction = await prisma.reactions.findFirst({
        where: {
          message_id: messageId,
          mongo_user_id: userId,
          emoji
        }
      })
    }

    if (!reaction) {
      return createErrorResponse('Reaction not found', 404)
    }

    // Only allow user to delete their own reactions
    if (reaction.mongo_user_id !== userId) {
      return createErrorResponse('Cannot delete other users reactions', 403)
    }

    // Delete using reactionOps
    await reactionOps.remove({ reactionId: reaction.id })

    // Broadcast reaction removed (non-blocking)
    broadcastReaction(reaction.channel_id, 'removed', {
      messageId: reaction.message_id,
      emoji: reaction.emoji,
      userId,
      userName,
      reactionId: reaction.id
    }).catch(err => logger.error('Failed to broadcast reaction removal:', err))

    return NextResponse.json({
      success: true,
      message: 'Reaction removed successfully'
    })

  } catch (error: unknown) {
    logger.error('Error removing reaction:', error)
    return createErrorResponse('Failed to remove reaction', 500)
  }
}

// ============================================
// GET /api/communication/reactions - Get reactions for a message or channel
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

    // Use reactionOps for single message, or direct query for channel-wide
    let reactions: Reaction[]
    if (messageId && !channelId) {
      reactions = await reactionOps.getByMessage(messageId)
    } else {
      const where: { message_id?: string; channel_id?: string } = {}
      if (messageId) where.message_id = messageId
      if (channelId) where.channel_id = channelId

      reactions = await prisma.reactions.findMany({
        where,
        orderBy: { created_at: 'asc' }
      })
    }

    // Type for grouped reaction accumulator
    type GroupedReaction = {
      message_id: string
      emoji: string
      count: number
      users: { id: string; mongo_user_id: string; name: string }[]
      hasCurrentUserReacted: boolean
    }

    // Group reactions by emoji with user counts
    const groupedReactions = reactions.reduce(
      (acc: Record<string, GroupedReaction>, reaction: Reaction) => {
        const key = `${reaction.message_id}_${reaction.emoji}`
        if (!acc[key]) {
          acc[key] = {
            message_id: reaction.message_id,
            emoji: reaction.emoji,
            count: 0,
            users: [],
            hasCurrentUserReacted: false
          }
        }
        acc[key].count++
        acc[key].users.push({
          id: reaction.id,
          mongo_user_id: reaction.mongo_user_id,
          name: reaction.user_name
        })
        if (reaction.mongo_user_id === session.user.id) {
          acc[key].hasCurrentUserReacted = true
        }
      return acc
    }, {})

    return NextResponse.json({
      success: true,
      data: {
        reactions,
        grouped: Object.values(groupedReactions)
      }
    })

  } catch (error: unknown) {
    logger.error('Error fetching reactions:', error)
    return createErrorResponse('Failed to fetch reactions', 500)
  }
}
