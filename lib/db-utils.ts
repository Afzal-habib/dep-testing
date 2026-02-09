import { prisma } from './prisma'

// Channel operations
export const channelOperations = {
  // Create a new channel
  create: async (data: {
    type: string
    name?: string
    mongo_department_id?: string
    mongo_project_id?: string
    mongo_creator_id: string
    is_private?: boolean
  }) => {
    return await prisma.channels.create({
      data: {
        type: data.type,
        name: data.name,
        mongo_department_id: data.mongo_department_id,
        mongo_project_id: data.mongo_project_id,
        mongo_creator_id: data.mongo_creator_id,
        is_private: data.is_private ?? false,
        member_count: 0,
      },
    })
  },

  // Get channels for a user
  getUserChannels: async (mongo_user_id: string) => {
    return await prisma.channels.findMany({
      where: {
        channel_members: {
          some: {
            mongo_member_id: mongo_user_id,
          },
        },
      },
      include: {
        channel_members: true,
        messages: {
          orderBy: { created_at: 'desc' },
          take: 1,
        },
      },
      orderBy: { updated_at: 'desc' },
    })
  },

  // Add member to channel
  addMember: async (channel_id: string, mongo_member_id: string, role: string = 'member') => {
    return await prisma.channel_members.create({
      data: {
        channel_id,
        mongo_member_id,
        role,
      },
    })
  },
}

// Message operations
export const messageOperations = {
  // Create a new message
  create: async (data: {
    channel_id: string
    mongo_sender_id: string
    content: string
    content_type?: string
    thread_id?: string
    parent_message_id?: string // For replies
    mongo_mentioned_user_ids?: string[]
    // Denormalized sender fields for real-time performance
    sender_name?: string
    sender_email?: string
    sender_avatar?: string
    sender_role?: string
  }) => {
    const message = await prisma.messages.create({
      data: {
        channel_id: data.channel_id,
        mongo_sender_id: data.mongo_sender_id,
        content: data.content,
        content_type: data.content_type ?? 'text',
        thread_id: data.thread_id,
        parent_message_id: data.parent_message_id,
        mongo_mentioned_user_ids: data.mongo_mentioned_user_ids ?? [],
        // Store denormalized sender data
        sender_name: data.sender_name ?? 'Unknown User',
        sender_email: data.sender_email ?? '',
        sender_avatar: data.sender_avatar,
        sender_role: data.sender_role ?? 'User',
      },
    })

    // If this is a reply, increment parent's reply_count
    if (data.parent_message_id) {
      await prisma.messages.update({
        where: { id: data.parent_message_id },
        data: { reply_count: { increment: 1 } },
      })
    }

    return message
  },

  // Update a message (edit)
  update: async (message_id: string, content: string) => {
    return await prisma.messages.update({
      where: { id: message_id },
      data: {
        content,
        is_edited: true,
        edited_at: new Date(),
      },
      include: {
        messages: true, // parent_message
        read_receipts: true,
        reactions: true,
        attachments: true,
      },
    })
  },

  // Delete a message
  delete: async (message_id: string) => {
    const message = await prisma.messages.findUnique({
      where: { id: message_id },
      select: { parent_message_id: true },
    })

    // If this is a reply, decrement parent's reply_count
    if (message?.parent_message_id) {
      await prisma.messages.update({
        where: { id: message.parent_message_id },
        data: { 
          reply_count: { 
            decrement: 1 
          } 
        },
      }).catch(() => {
        // Ignore errors if parent was already deleted
      })
    }

    return await prisma.messages.delete({
      where: { id: message_id },
    })
  },

  // Get messages for a channel with replies (filters out trashed and hidden messages)
  getChannelMessages: async (
    channel_id: string, 
    limit: number = 50, 
    offset: number = 0,
    currentUserId?: string
  ) => {
    // Build where clause to filter out trashed messages
    // and messages hidden by the current user
    const whereClause: any = {
      channel_id,
      parent_message_id: null, // Only get top-level messages (not replies)
      is_trashed: false, // Exclude trashed messages
    }
    
    // If currentUserId provided, also exclude messages hidden by this user
    if (currentUserId) {
      whereClause.NOT = {
        hidden_by_users: {
          has: currentUserId
        }
      }
    }
    
    return await prisma.messages.findMany({
      where: whereClause,
      include: {
        other_messages: { // Get first few replies
          take: 3,
          orderBy: { created_at: 'asc' },
          where: {
            is_trashed: false, // Also exclude trashed replies
          },
          include: {
            read_receipts: true,
            reactions: true,
          },
        },
        read_receipts: true,
        reactions: true,
        attachments: true,
      },
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset,
    })
  },

  // Get replies for a specific message
  getReplies: async (parent_message_id: string, limit: number = 50) => {
    return await prisma.messages.findMany({
      where: {
        parent_message_id,
      },
      include: {
        read_receipts: true,
        reactions: true,
        attachments: true,
      },
      orderBy: { created_at: 'asc' },
      take: limit,
    })
  },

  // Mark message as read
  markAsRead: async (message_id: string, mongo_user_id: string) => {
    return await prisma.read_receipts.upsert({
      where: {
        message_id_mongo_user_id: {
          message_id,
          mongo_user_id,
        },
      },
      update: { read_at: new Date() },
      create: {
        message_id,
        mongo_user_id,
        read_at: new Date(),
      },
    })
  },
}

// Channel member operations
export const memberOperations = {
  // Update online status
  updateOnlineStatus: async (channel_id: string, mongo_member_id: string, is_online: boolean) => {
    return await prisma.channel_members.updateMany({
      where: {
        channel_id,
        mongo_member_id,
      },
      data: {
        is_online,
        last_seen_at: new Date(),
      },
    })
  },

  // Get online members
  getOnlineMembers: async (channel_id: string) => {
    return await prisma.channel_members.findMany({
      where: {
        channel_id,
        is_online: true,
      },
    })
  },
}

// Utility functions
export const dbUtils = {
  // Health check
  healthCheck: async () => {
    try {
      await prisma.$queryRaw`SELECT 1`
      return { status: 'healthy', timestamp: new Date() }
    } catch (error) {
      return { status: 'unhealthy', error: (error as any).message, timestamp: new Date() }
    }
  },

  // Clean up old data (optional)
  cleanup: async (daysOld: number = 30) => {
    const cutoffDate = new Date()
    cutoffDate.setDate(cutoffDate.getDate() - daysOld)

    // This is just an example - implement based on your retention policy
    return {
      deletedMessages: 0,
      deletedReadReceipts: 0,
      timestamp: new Date(),
    }
  },
}