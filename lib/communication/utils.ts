import { communicationLogger as logger } from '@/lib/logger'

// Helper function to enrich channels with MongoDB user data
export function enrichChannelWithUserData(channel: any, users: any[]) {
  try {
    // Create a map of users by _id for quick lookup
    const userMap = new Map(users.map(user => [user._id.toString(), user]))

    // Enrich channel_members with user data
    const enrichedChannelMembers = channel.channel_members?.map((member: any) => {
      const user = userMap.get(member.mongo_member_id)
      return {
        ...member,
        channelRole: member.role, // Rename role to channelRole
        userRole: user ? (typeof user.role === 'string' ? user.role : user.role?.name || 'User') : 'User',
        name: user?.name || user?.email || 'Unknown User',
        email: user?.email || '',
        avatar: user?.avatar || '',
        userType: user?.isClient ? 'Client' : 'User',
        isOnline: member.is_online || false
      }
    }) || []

    return {
      ...channel,
      channel_members: enrichedChannelMembers
    }
  } catch (error) {
    logger.error('Error enriching channel with user data:', error)
    return {
      ...channel,
      channel_members: []
    }
  }
}

/**
 * Transform a message with denormalized sender fields to include sender object.
 * This is the preferred method as it doesn't require MongoDB lookups.
 * Used for messages that already have sender_name, sender_email etc fields.
 */
export function transformMessageWithSender(message: any) {
  if (!message || typeof message !== 'object') {
    logger.error('Invalid message for transformation:', message)
    return null
  }

  return {
    ...message,
    sender: {
      mongo_member_id: message.mongo_sender_id,
      name: message.sender_name || 'Unknown User',
      email: message.sender_email || '',
      avatar: message.sender_avatar || '',
      role: message.sender_role || 'User',
      userType: 'User' as const,
      isOnline: false,
    }
  }
}

/**
 * @deprecated Use transformMessageWithSender instead.
 * This function requires MongoDB user data and should only be used for
 * backward compatibility with messages that don't have denormalized sender fields.
 * 
 * For real-time performance, messages now store sender data directly in Supabase.
 */
export function enrichMessageWithUserData(message: any, users: any[]) {
  if (!message || typeof message !== 'object' || !message.mongo_sender_id) {
    logger.error('Invalid message for enrichment:', message)
    return null
  }
  
  // If message already has denormalized sender fields, use them (no MongoDB lookup)
  if (message.sender_name) {
    return transformMessageWithSender(message)
  }
  
  try {
    // Legacy fallback: Create a map of users by _id for quick lookup
    const userMap = new Map(users.map(user => [user._id.toString(), user]))

    // Find the sender user
    const sender = userMap.get(message.mongo_sender_id)

    // Enrich message with sender data
    const enrichedMessage = {
      ...message,
      sender: sender ? {
        mongo_member_id: sender._id,
        name: sender.name || sender.email || 'Unknown User',
        email: sender.email || '',
        avatar: sender.avatar || '',
        role: typeof sender.role === 'string' ? sender.role : sender.role?.name || 'User',
        userType: sender.isClient ? 'Client' : 'User',
        isOnline: false // TODO: Add real-time status if needed
      } : {
        mongo_member_id: message.mongo_sender_id,
        name: 'Unknown User',
        email: '',
        avatar: '',
        role: 'User',
        userType: 'User',
        isOnline: false
      }
    }

    return enrichedMessage
  } catch (error) {
    logger.error('Error enriching message with user data:', error)
    return null
  }
}