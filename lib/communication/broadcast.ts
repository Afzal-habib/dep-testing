/**
 * Centralized Supabase Broadcast Service
 * 
 * SERVER-SIDE ONLY - This service runs in API routes and uses the SERVICE_ROLE_KEY
 * to send broadcasts to Supabase Realtime channels.
 * 
 * Architecture Note:
 * - broadcast.ts (this file) → SENDS broadcasts from API routes using SERVICE_ROLE_KEY
 * - realtime-manager.ts → RECEIVES broadcasts in browser using ANON_KEY
 * 
 * ⚠️ NEVER import this file in React components - it would expose the service role key
 */
import { createClient, SupabaseClient, RealtimeChannel } from '@supabase/supabase-js'
import { apiLogger as logger } from '@/lib/logger'

// ============================================
// Singleton Admin Client
// ============================================

let supabaseAdminClient: SupabaseClient | null = null

function getSupabaseAdmin(): SupabaseClient {
  if (!supabaseAdminClient) {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY

    if (!url || !key) {
      throw new Error('Missing Supabase configuration: NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY')
    }

    supabaseAdminClient = createClient(url, key, {
      realtime: {
        params: { eventsPerSecond: 100 }
      }
    })
  }
  return supabaseAdminClient
}

// ============================================
// Type Definitions
// ============================================

/**
 * Broadcast events for channel communication
 * NOTE: Typing events (typing_start/typing_stop) are CLIENT-SIDE only via realtime-manager.ts
 */
export type BroadcastEvent =
  // Message events
  | 'new_message'
  | 'message_update'
  | 'message_delete'
  | 'message_trash'
  | 'message_restore'
  | 'message_hidden'
  // Reaction events
  | 'reaction_added'
  | 'reaction_removed'
  // Read receipt events
  | 'message_read'
  | 'bulk_message_read'
  // Channel events
  | 'channel_updated'
  | 'channel_archived'
  | 'new_channel'
  | 'user_pin_update'
  // Member events
  | 'member_joined'
  | 'member_left'
  | 'member_updated'
  | 'member_role_changed'
  // Attachment events
  | 'attachments_added'

/**
 * Notification-specific events (sent to user notification channel)
 */
export type NotificationEvent =
  | 'mention_notification'
  | 'dm_notification'
  | 'new_message'

export interface BroadcastOptions {
  channelId: string
  event: BroadcastEvent
  payload: Record<string, unknown>
  timeout?: number
}

export interface NotificationOptions {
  userId: string
  event: NotificationEvent
  payload: Record<string, unknown>
  timeout?: number
}

// ============================================
// Broadcast Functions
// ============================================

/**
 * Broadcast a message to a Supabase channel with proper connection handling.
 * Uses ACK mode for reliable delivery confirmation.
 */
export async function broadcastToChannel({
  channelId,
  event,
  payload,
  timeout = 5000
}: BroadcastOptions): Promise<boolean> {
  const supabase = getSupabaseAdmin()
  const channelName = `rt_${channelId}`

  return new Promise((resolve) => {
    let resolved = false
    let channel: RealtimeChannel | null = null

    const timeoutId = setTimeout(() => {
      if (!resolved) {
        resolved = true
        if (channel) {
          supabase.removeChannel(channel)
        }
        logger.warn(`Broadcast to ${channelName}/${event} timed out after ${timeout}ms`)
        resolve(false)
      }
    }, timeout)

    channel = supabase.channel(channelName, {
      config: { broadcast: { self: false, ack: true } }
    })

    channel.subscribe(async (status) => {
      if (status === 'SUBSCRIBED') {
        try {
          const result = await channel!.send({
            type: 'broadcast',
            event,
            payload
          })

          if (!resolved) {
            resolved = true
            clearTimeout(timeoutId)
            supabase.removeChannel(channel!)
            
            if (result === 'ok') {
              logger.debug(`Broadcast ${event} to ${channelName} succeeded`)
            } else {
              logger.warn(`Broadcast ${event} to ${channelName} returned: ${result}`)
            }
            resolve(result === 'ok')
          }
        } catch (error) {
          if (!resolved) {
            resolved = true
            clearTimeout(timeoutId)
            supabase.removeChannel(channel!)
            logger.error(`Broadcast error to ${channelName}/${event}:`, error)
            resolve(false)
          }
        }
      } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
        if (!resolved) {
          resolved = true
          clearTimeout(timeoutId)
          if (channel) {
            supabase.removeChannel(channel)
          }
          logger.error(`Channel ${channelName} subscription failed: ${status}`)
          resolve(false)
        }
      }
    })
  })
}

/**
 * Broadcast to user-specific notification channel.
 * Used for @mentions and DM notifications.
 */
export async function broadcastToUser({
  userId,
  event,
  payload,
  timeout = 3000
}: NotificationOptions): Promise<boolean> {
  const supabase = getSupabaseAdmin()
  const channelName = `notifications_${userId}`

  return new Promise((resolve) => {
    let resolved = false
    let channel: RealtimeChannel | null = null

    const timeoutId = setTimeout(() => {
      if (!resolved) {
        resolved = true
        if (channel) {
          supabase.removeChannel(channel)
        }
        logger.debug(`User notification to ${userId}/${event} timed out`)
        resolve(false)
      }
    }, timeout)

    channel = supabase.channel(channelName)

    channel.subscribe(async (status) => {
      if (status === 'SUBSCRIBED') {
        try {
          const result = await channel!.send({
            type: 'broadcast',
            event,
            payload
          })

          if (!resolved) {
            resolved = true
            clearTimeout(timeoutId)
            supabase.removeChannel(channel!)
            resolve(result === 'ok')
          }
        } catch (error) {
          if (!resolved) {
            resolved = true
            clearTimeout(timeoutId)
            supabase.removeChannel(channel!)
            logger.debug(`User notification error ${userId}/${event}:`, error)
            resolve(false)
          }
        }
      } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
        if (!resolved) {
          resolved = true
          clearTimeout(timeoutId)
          if (channel) {
            supabase.removeChannel(channel)
          }
          resolve(false)
        }
      }
    })
  })
}

/**
 * Broadcast to multiple channels in parallel.
 * Returns a map of channelId -> success status.
 */
export async function broadcastToMultipleChannels(
  broadcasts: BroadcastOptions[]
): Promise<Map<string, boolean>> {
  const results = new Map<string, boolean>()

  await Promise.all(
    broadcasts.map(async (broadcast) => {
      const success = await broadcastToChannel(broadcast)
      results.set(broadcast.channelId, success)
    })
  )

  return results
}

/**
 * Broadcast to multiple users in parallel (for @everyone mentions).
 * Returns a map of userId -> success status.
 */
export async function broadcastToMultipleUsers(
  notifications: NotificationOptions[]
): Promise<Map<string, boolean>> {
  const results = new Map<string, boolean>()

  await Promise.all(
    notifications.map(async (notification) => {
      const success = await broadcastToUser(notification)
      results.set(notification.userId, success)
    })
  )

  return results
}

// ============================================
// Convenience Functions for Common Operations
// ============================================

/**
 * Broadcast a new message to channel subscribers
 */
export async function broadcastNewMessage(
  channelId: string,
  message: Record<string, unknown>
): Promise<boolean> {
  return broadcastToChannel({
    channelId,
    event: 'new_message',
    payload: message
  })
}

/**
 * Broadcast a message update to channel subscribers
 */
export async function broadcastMessageUpdate(
  channelId: string,
  messageId: string,
  updates: Record<string, unknown>
): Promise<boolean> {
  return broadcastToChannel({
    channelId,
    event: 'message_update',
    payload: { id: messageId, ...updates }
  })
}

/**
 * Broadcast message deletion to channel subscribers
 */
export async function broadcastMessageDelete(
  channelId: string,
  messageId: string,
  deletedBy: string
): Promise<boolean> {
  return broadcastToChannel({
    channelId,
    event: 'message_delete',
    payload: { messageId, deletedBy }
  })
}

/**
 * Broadcast reaction toggle to channel subscribers
 */
export async function broadcastReaction(
  channelId: string,
  action: 'added' | 'removed',
  data: {
    messageId: string
    emoji: string
    userId: string
    userName: string
    reactionId?: string
  }
): Promise<boolean> {
  return broadcastToChannel({
    channelId,
    event: action === 'added' ? 'reaction_added' : 'reaction_removed',
    payload: data
  })
}

/**
 * Broadcast read receipt to channel subscribers
 */
export async function broadcastReadReceipt(
  channelId: string,
  data: {
    messageId: string
    userId: string
    readAt: string
  }
): Promise<boolean> {
  return broadcastToChannel({
    channelId,
    event: 'message_read',
    payload: data
  })
}

/**
 * Broadcast bulk read receipts to channel subscribers
 */
export async function broadcastBulkReadReceipt(
  channelId: string,
  data: {
    userId: string
    messageCount: number
    lastReadMessageId?: string
  }
): Promise<boolean> {
  return broadcastToChannel({
    channelId,
    event: 'bulk_message_read',
    payload: data
  })
}

/**
 * Send mention notification to a specific user
 */
export async function sendMentionNotification(
  userId: string,
  data: {
    channelId: string
    channelName: string
    messageId: string
    mentionedBy: string
    mentionedByName: string
    preview: string
  }
): Promise<boolean> {
  return broadcastToUser({
    userId,
    event: 'mention_notification',
    payload: data
  })
}

/**
 * Send DM notification to a specific user
 */
export async function sendDMNotification(
  userId: string,
  data: {
    channelId: string
    messageId: string
    senderName: string
    senderId: string
    preview: string
  }
): Promise<boolean> {
  return broadcastToUser({
    userId,
    event: 'dm_notification',
    payload: data
  })
}

/**
 * Broadcast channel update to all members
 */
export async function broadcastChannelUpdate(
  channelId: string,
  updates: Record<string, unknown>
): Promise<boolean> {
  return broadcastToChannel({
    channelId,
    event: 'channel_updated',
    payload: { channelId, ...updates }
  })
}

/**
 * Broadcast member change to channel
 */
export async function broadcastMemberChange(
  channelId: string,
  action: 'joined' | 'left' | 'updated' | 'role_changed',
  memberData: {
    memberId: string
    memberName: string
    role?: string
    updatedBy?: string
  }
): Promise<boolean> {
  const eventMap = {
    joined: 'member_joined' as const,
    left: 'member_left' as const,
    updated: 'member_updated' as const,
    role_changed: 'member_role_changed' as const
  }

  return broadcastToChannel({
    channelId,
    event: eventMap[action],
    payload: memberData
  })
}

// ============================================
// Export Admin Client Getter (for advanced use)
// ============================================

export { getSupabaseAdmin }
