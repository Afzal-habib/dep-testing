/**
 * Unified Communication Database Operations
 * 
 * This module provides a centralized, cached database layer for all
 * communication-related operations. It follows the patterns established
 * in db-utils.ts and enhances them with caching support.
 * 
 * Usage:
 * - Import specific operations: `import { channelOps, messageOps } from '@/lib/communication/operations'`
 * - Or import all: `import * as commOps from '@/lib/communication/operations'`
 */
import { prisma } from '@/lib/prisma'
import { communicationCache } from './cache'
import { apiLogger as logger } from '@/lib/logger'

// Re-export existing operations for backward compatibility
export { channelOperations, messageOperations, memberOperations, dbUtils } from '@/lib/db-utils'

// ============================================
// Channel Operations
// ============================================

export const channelOps = {
  /**
   * Get channel by ID with optional includes
   */
  async getById(channelId: string, options?: { includeMembers?: boolean; includeLastMessages?: number }) {
    const cacheKey = `channel:${channelId}`

    // Check cache first (only for basic queries without includes)
    if (!options?.includeMembers && !options?.includeLastMessages) {
      const cached = communicationCache.get<any>(cacheKey)
      if (cached) return cached
    }

    const channel = await prisma.channels.findUnique({
      where: { id: channelId },
      include: {
        ...(options?.includeMembers !== false && { channel_members: true }),
        ...(options?.includeLastMessages && {
          messages: {
            where: { is_trashed: false },
            orderBy: { created_at: 'desc' },
            take: options.includeLastMessages
          }
        })
      }
    })

    if (channel && !options?.includeLastMessages) {
      communicationCache.set(cacheKey, channel, 60000) // 1 min cache
    }

    return channel
  },

  /**
   * Get user's channels with unread counts and last message
   */
  async getUserChannels(
    userId: string,
    filters?: {
      type?: string
      departmentId?: string
      projectId?: string
      includeArchived?: boolean
    }
  ) {
    return prisma.channels.findMany({
      where: {
        channel_members: {
          some: { mongo_member_id: userId }
        },
        ...(filters?.type && { type: filters.type }),
        ...(filters?.departmentId && { mongo_department_id: filters.departmentId }),
        ...(filters?.projectId && { mongo_project_id: filters.projectId }),
        ...(!filters?.includeArchived && { is_archived: false }),
      },
      include: {
        channel_members: true,
        messages: {
          where: { is_trashed: false },
          orderBy: { created_at: 'desc' },
          take: 1
        }
      },
      orderBy: { updated_at: 'desc' }
    })
  },

  /**
   * Check if user is member of channel
   */
  async isMember(channelId: string, userId: string): Promise<boolean> {
    const membership = await prisma.channel_members.findFirst({
      where: {
        channel_id: channelId,
        mongo_member_id: userId
      }
    })
    return !!membership
  },

  /**
   * Get member role in channel
   */
  async getMemberRole(channelId: string, userId: string): Promise<string | null> {
    const membership = await prisma.channel_members.findFirst({
      where: {
        channel_id: channelId,
        mongo_member_id: userId
      },
      select: { role: true }
    })
    return membership?.role ?? null
  },

  /**
   * Get member record
   */
  async getMember(channelId: string, userId: string) {
    return prisma.channel_members.findFirst({
      where: {
        channel_id: channelId,
        mongo_member_id: userId
      }
    })
  },

  /**
   * Toggle channel pin status for a user
   */
  async togglePin(channelId: string, userId: string, maxPins: number = 5) {
    const member = await prisma.channel_members.findFirst({
      where: { channel_id: channelId, mongo_member_id: userId }
    })

    if (!member) {
      throw new Error('Not a member of this channel')
    }

    if (member.is_pinned) {
      // Unpin
      const updated = await prisma.channel_members.update({
        where: { id: member.id },
        data: { is_pinned: false, pinned_at: null }
      })
      return { action: 'unpinned' as const, member: updated }
    } else {
      // Check pin limit
      const pinnedCount = await prisma.channel_members.count({
        where: { mongo_member_id: userId, is_pinned: true }
      })

      if (pinnedCount >= maxPins) {
        throw new Error(`Maximum ${maxPins} pinned channels allowed`)
      }

      const updated = await prisma.channel_members.update({
        where: { id: member.id },
        data: { is_pinned: true, pinned_at: new Date() }
      })
      return { action: 'pinned' as const, member: updated }
    }
  },

  /**
   * Archive or unarchive channel
   */
  async toggleArchive(
    channelId: string,
    userId: string,
    action: 'archive' | 'unarchive'
  ) {
    // Invalidate cache
    communicationCache.invalidate(`channel:${channelId}`)

    return prisma.channels.update({
      where: { id: channelId },
      data: {
        is_archived: action === 'archive',
        archived_at: action === 'archive' ? new Date() : null,
        archived_by: action === 'archive' ? userId : null
      }
    })
  },

  /**
   * Update channel settings
   */
  async updateSettings(
    channelId: string,
    settings: {
      name?: string
      is_private?: boolean
      auto_sync_enabled?: boolean
      allow_external_members?: boolean
      admin_only_post?: boolean
      admin_only_add?: boolean
    }
  ) {
    // Invalidate cache
    communicationCache.invalidate(`channel:${channelId}`)

    return prisma.channels.update({
      where: { id: channelId },
      data: {
        ...settings,
        updated_at: new Date()
      }
    })
  },

  /**
   * Leave a channel
   */
  async leave(channelId: string, userId: string) {
    // Find and delete membership
    const member = await prisma.channel_members.findFirst({
      where: { channel_id: channelId, mongo_member_id: userId }
    })

    if (!member) {
      throw new Error('Not a member of this channel')
    }

    await prisma.channel_members.delete({
      where: { id: member.id }
    })

    // Update member count
    await prisma.channels.update({
      where: { id: channelId },
      data: { member_count: { decrement: 1 } }
    })

    // Invalidate cache
    communicationCache.invalidate(`channel:${channelId}`)

    return { success: true, memberId: member.id }
  }
}

// ============================================
// Message Operations
// ============================================

export const messageOps = {
  /**
   * Get messages for a channel with pagination and filtering
   */
  async getByChannel(
    channelId: string,
    options: {
      limit?: number
      offset?: number
      includeAttachments?: boolean
      includeReactions?: boolean
      currentUserId?: string
    } = {}
  ) {
    const {
      limit = 50,
      offset = 0,
      includeAttachments = true,
      includeReactions = true,
      currentUserId
    } = options

    // Build where clause
    const whereClause: any = {
      channel_id: channelId,
      is_trashed: false,
      parent_message_id: null // Top-level messages only
    }

    // Exclude messages hidden by current user
    if (currentUserId) {
      whereClause.NOT = {
        hidden_by_users: { has: currentUserId }
      }
    }

    return prisma.messages.findMany({
      where: whereClause,
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset,
      include: {
        ...(includeAttachments && { attachments: true }),
        ...(includeReactions && { reactions: true }),
        read_receipts: true
      }
    })
  },

  /**
   * Create message with sender denormalization
   */
  async create(data: {
    channel_id: string
    mongo_sender_id: string
    content: string
    content_type?: string
    parent_message_id?: string
    mongo_mentioned_user_ids?: string[]
    sender_name: string
    sender_email: string
    sender_avatar?: string
    sender_role?: string
  }) {
    const message = await prisma.messages.create({
      data: {
        channel_id: data.channel_id,
        mongo_sender_id: data.mongo_sender_id,
        content: data.content,
        content_type: data.content_type ?? 'text',
        parent_message_id: data.parent_message_id,
        mongo_mentioned_user_ids: data.mongo_mentioned_user_ids ?? [],
        sender_name: data.sender_name,
        sender_email: data.sender_email,
        sender_avatar: data.sender_avatar,
        sender_role: data.sender_role ?? 'User'
      },
      include: { attachments: true, reactions: true }
    })

    // Update reply count if this is a reply
    if (data.parent_message_id) {
      try {
        await prisma.messages.update({
          where: { id: data.parent_message_id },
          data: { reply_count: { increment: 1 } }
        })
      } catch {
        logger.debug('Parent message not found for reply count update')
      }
    }

    // Update channel's last_message_at
    await prisma.channels.update({
      where: { id: data.channel_id },
      data: { last_message_at: new Date(), updated_at: new Date() }
    })

    // Invalidate channel cache
    communicationCache.invalidate(`channel:${data.channel_id}`)

    return message
  },

  /**
   * Update message content
   */
  async update(
    messageId: string,
    content: string,
    editorInfo?: { editorId: string; editorName: string }
  ) {
    const message = await prisma.messages.findUnique({
      where: { id: messageId },
      select: { content: true, channel_id: true }
    })

    if (!message) {
      throw new Error('Message not found')
    }

    const updated = await prisma.messages.update({
      where: { id: messageId },
      data: {
        content,
        original_content: message.content, // Store original for audit
        is_edited: true,
        edited_at: new Date()
      },
      include: { attachments: true, reactions: true }
    })

    return updated
  },

  /**
   * Search messages in channel
   */
  async search(
    channelId: string,
    query: string,
    options?: { limit?: number; offset?: number }
  ) {
    const { limit = 20, offset = 0 } = options ?? {}

    return prisma.messages.findMany({
      where: {
        channel_id: channelId,
        is_trashed: false,
        content: { contains: query, mode: 'insensitive' }
      },
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset,
      include: { attachments: true }
    })
  },

  /**
   * Move message to trash (soft delete)
   */
  async trash(messageId: string, userId: string, reason?: string) {
    return prisma.messages.update({
      where: { id: messageId },
      data: {
        is_trashed: true,
        trashed_at: new Date(),
        trashed_by: userId,
        trash_reason: reason
      }
    })
  },

  /**
   * Restore message from trash
   */
  async restore(messageId: string) {
    return prisma.messages.update({
      where: { id: messageId },
      data: {
        is_trashed: false,
        trashed_at: null,
        trashed_by: null,
        trash_reason: null
      }
    })
  },

  /**
   * Hide message for specific user (self-delete)
   */
  async hideForUser(messageId: string, userId: string) {
    const message = await prisma.messages.findUnique({
      where: { id: messageId },
      select: { hidden_by_users: true }
    })

    if (!message) {
      throw new Error('Message not found')
    }

    const hiddenBy = message.hidden_by_users || []
    if (hiddenBy.includes(userId)) {
      return { alreadyHidden: true }
    }

    await prisma.messages.update({
      where: { id: messageId },
      data: {
        hidden_by_users: [...hiddenBy, userId]
      }
    })

    return { success: true }
  },

  /**
   * Get trashed messages for user
   */
  async getTrashed(
    userId: string,
    options?: { channelId?: string; limit?: number; offset?: number }
  ) {
    const { channelId, limit = 20, offset = 0 } = options ?? {}

    return prisma.messages.findMany({
      where: {
        is_trashed: true,
        trashed_by: userId,
        ...(channelId && { channel_id: channelId })
      },
      orderBy: { trashed_at: 'desc' },
      take: limit,
      skip: offset
    })
  },

  /**
   * Permanently delete message
   */
  async permanentDelete(messageId: string) {
    const message = await prisma.messages.findUnique({
      where: { id: messageId },
      select: { parent_message_id: true, channel_id: true }
    })

    if (!message) {
      throw new Error('Message not found')
    }

    // Decrement parent reply count if it's a reply
    if (message.parent_message_id) {
      await prisma.messages.update({
        where: { id: message.parent_message_id },
        data: { reply_count: { decrement: 1 } }
      }).catch(() => { })
    }

    // Delete attachments, reactions, read_receipts cascade automatically

    return prisma.messages.delete({
      where: { id: messageId }
    })
  }
}

// ============================================
// Reaction Operations
// ============================================

export const reactionOps = {
  /**
   * Toggle reaction (add if not exists, remove if exists)
   */
  async toggle(data: {
    messageId: string
    channelId: string
    userId: string
    userName: string
    emoji: string
  }) {
    const existing = await prisma.reactions.findFirst({
      where: {
        message_id: data.messageId,
        mongo_user_id: data.userId,
        emoji: data.emoji
      }
    })

    if (existing) {
      await prisma.reactions.delete({ where: { id: existing.id } })
      return { action: 'removed' as const, reaction: existing }
    } else {
      const reaction = await prisma.reactions.create({
        data: {
          message_id: data.messageId,
          channel_id: data.channelId,
          mongo_user_id: data.userId,
          user_name: data.userName,
          emoji: data.emoji
        }
      })
      return { action: 'added' as const, reaction }
    }
  },

  /**
   * Add reaction
   */
  async add(data: {
    messageId: string
    channelId: string
    userId: string
    userName: string
    emoji: string
  }) {
    // Check for existing
    const existing = await prisma.reactions.findFirst({
      where: {
        message_id: data.messageId,
        mongo_user_id: data.userId,
        emoji: data.emoji
      }
    })

    if (existing) {
      return { alreadyExists: true, reaction: existing }
    }

    const reaction = await prisma.reactions.create({
      data: {
        message_id: data.messageId,
        channel_id: data.channelId,
        mongo_user_id: data.userId,
        user_name: data.userName,
        emoji: data.emoji
      }
    })

    return { created: true, reaction }
  },

  /**
   * Remove reaction
   */
  async remove(data: {
    reactionId?: string
    messageId?: string
    userId?: string
    emoji?: string
  }) {
    if (data.reactionId) {
      const reaction = await prisma.reactions.delete({
        where: { id: data.reactionId }
      })
      return { deleted: true, reaction }
    }

    if (data.messageId && data.userId && data.emoji) {
      const reaction = await prisma.reactions.findFirst({
        where: {
          message_id: data.messageId,
          mongo_user_id: data.userId,
          emoji: data.emoji
        }
      })

      if (reaction) {
        await prisma.reactions.delete({ where: { id: reaction.id } })
        return { deleted: true, reaction }
      }
    }

    return { deleted: false }
  },

  /**
   * Get reactions for a message
   */
  async getByMessage(messageId: string) {
    return prisma.reactions.findMany({
      where: { message_id: messageId },
      orderBy: { created_at: 'asc' }
    })
  },

  /**
   * Get reactions for multiple messages
   */
  async getByMessages(messageIds: string[]) {
    return prisma.reactions.findMany({
      where: { message_id: { in: messageIds } },
      orderBy: { created_at: 'asc' }
    })
  }
}

// ============================================
// Read Receipt Operations
// ============================================

export const readReceiptOps = {
  /**
   * Mark single message as read
   */
  async mark(messageId: string, userId: string) {
    return prisma.read_receipts.upsert({
      where: {
        message_id_mongo_user_id: {
          message_id: messageId,
          mongo_user_id: userId
        }
      },
      create: {
        message_id: messageId,
        mongo_user_id: userId,
        read_at: new Date()
      },
      update: {
        read_at: new Date()
      }
    })
  },

  /**
   * Mark all unread messages in channel as read
   */
  async markAllInChannel(channelId: string, userId: string) {
    const unreadMessages = await prisma.messages.findMany({
      where: {
        channel_id: channelId,
        is_trashed: false,
        mongo_sender_id: { not: userId },
        read_receipts: {
          none: { mongo_user_id: userId }
        }
      },
      select: { id: true }
    })

    if (unreadMessages.length === 0) {
      return { markedCount: 0 }
    }

    const messageData: Array<{ message_id: string; mongo_user_id: string }> = []
    for (const msg of unreadMessages) {
      messageData.push({
        message_id: msg.id,
        mongo_user_id: userId
      })
    }

    await prisma.read_receipts.createMany({
      data: messageData,
      skipDuplicates: true
    })

    return { markedCount: unreadMessages.length }
  },

  /**
   * Get read receipts for a message
   */
  async getByMessage(messageId: string) {
    return prisma.read_receipts.findMany({
      where: { message_id: messageId }
    })
  },

  /**
   * Get unread count for channel
   */
  async getUnreadCount(channelId: string, userId: string): Promise<number> {
    return prisma.messages.count({
      where: {
        channel_id: channelId,
        is_trashed: false,
        mongo_sender_id: { not: userId },
        read_receipts: {
          none: { mongo_user_id: userId }
        }
      }
    })
  }
}

// ============================================
// Attachment Operations
// ============================================

export const attachmentOps = {
  /**
   * Create attachment record
   */
  async create(data: {
    messageId: string
    channelId: string
    uploaderId: string
    fileName: string
    fileUrl?: string
    s3Key?: string
    s3Bucket?: string
    fileSize?: number
    fileType?: string
  }) {
    return prisma.attachments.create({
      data: {
        message_id: data.messageId,
        channel_id: data.channelId,
        mongo_uploader_id: data.uploaderId,
        file_name: data.fileName,
        file_url: data.fileUrl,
        s3_key: data.s3Key,
        s3_bucket: data.s3Bucket,
        file_size: data.fileSize,
        file_type: data.fileType
      }
    })
  },

  /**
   * Create multiple attachments
   */
  async createMany(attachments: Array<{
    messageId: string
    channelId: string
    uploaderId: string
    fileName: string
    fileUrl?: string
    s3Key?: string
    s3Bucket?: string
    fileSize?: number
    fileType?: string
  }>) {
    return prisma.attachments.createMany({
      data: attachments.map(a => ({
        message_id: a.messageId,
        channel_id: a.channelId,
        mongo_uploader_id: a.uploaderId,
        file_name: a.fileName,
        file_url: a.fileUrl,
        s3_key: a.s3Key,
        s3_bucket: a.s3Bucket,
        file_size: a.fileSize,
        file_type: a.fileType
      }))
    })
  },

  /**
   * Get attachments for a channel
   */
  async getByChannel(channelId: string, options?: { limit?: number; offset?: number }) {
    const { limit = 50, offset = 0 } = options ?? {}

    return prisma.attachments.findMany({
      where: { channel_id: channelId },
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset
    })
  },

  /**
   * Get attachment by ID
   */
  async getById(attachmentId: string) {
    return prisma.attachments.findUnique({
      where: { id: attachmentId },
      include: { channels: true }
    })
  },

  /**
   * Delete attachment
   */
  async delete(attachmentId: string) {
    return prisma.attachments.delete({
      where: { id: attachmentId }
    })
  },

  /**
   * Forward attachment to multiple channels
   * Creates copies of the attachment record linked to new messages
   */
  async forward(data: {
    attachmentId: string
    targetChannelIds: string[]
    senderId: string
    optionalMessage?: string
  }) {
    const { attachmentId, targetChannelIds, senderId, optionalMessage } = data

    // Get original attachment
    const original = await prisma.attachments.findUnique({
      where: { id: attachmentId }
    })

    if (!original) {
      throw new Error('Attachment not found')
    }

    const results = []

    for (const channelId of targetChannelIds) {
      // Create a forwarded message in the target channel
      // For attachment forwards, we just show the attachment with [Forwarded] prefix
      // The WhatsApp-style rendering will handle showing this properly
      const forwardedContent = optionalMessage
        ? `[Forwarded]\n${optionalMessage}`
        : `[Forwarded]`

      const message = await prisma.messages.create({
        data: {
          channel_id: channelId,
          mongo_sender_id: senderId,
          content: forwardedContent
        }
      })

      // Create attachment copy linked to the new message
      const forwardedAttachment = await prisma.attachments.create({
        data: {
          message_id: message.id,
          channel_id: channelId,
          mongo_uploader_id: senderId,
          file_name: original.file_name,
          file_url: original.file_url,
          s3_key: original.s3_key,
          s3_bucket: original.s3_bucket,
          file_size: original.file_size,
          file_type: original.file_type
        }
      })

      results.push({
        channelId,
        messageId: message.id,
        attachmentId: forwardedAttachment.id
      })
    }

    return results
  },

  /**
   * Get attachments grouped by date for gallery view
   */
  async getGalleryByChannel(
    channelId: string,
    options?: {
      category?: 'all' | 'images' | 'videos' | 'documents' | 'audio'
      limit?: number
      offset?: number
    }
  ) {
    const { category = 'all', limit = 100, offset = 0 } = options ?? {}

    // Build file type filter based on category
    let fileTypeFilter: { contains?: string; startsWith?: string } | undefined

    switch (category) {
      case 'images':
        fileTypeFilter = { startsWith: 'image/' }
        break
      case 'videos':
        fileTypeFilter = { startsWith: 'video/' }
        break
      case 'audio':
        fileTypeFilter = { startsWith: 'audio/' }
        break
      case 'documents':
        // Documents are everything that's not image/video/audio
        break
    }

    const whereClause: { channel_id: string; file_type?: { startsWith?: string; not?: { startsWith: string }; AND?: Array<{ not: { startsWith: string } }> } } = {
      channel_id: channelId
    }

    if (category === 'documents') {
      // Exclude images, videos, and audio
      whereClause.file_type = {
        AND: [
          { not: { startsWith: 'image/' } },
          { not: { startsWith: 'video/' } },
          { not: { startsWith: 'audio/' } }
        ]
      } as any
    } else if (fileTypeFilter) {
      whereClause.file_type = fileTypeFilter
    }

    const attachments = await prisma.attachments.findMany({
      where: whereClause,
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset,
      include: {
        messages: {
          select: {
            mongo_sender_id: true,
            created_at: true
          }
        }
      }
    })

    return attachments
  }
}

// ============================================
// Audit Log Operations
// NOTE: These operations require the message_audit_logs table
// which may need to be added to the Prisma schema if not present.
// For now, we export a placeholder that can be enabled when ready.
// ============================================

export const auditOps = {
  /**
   * Create audit log entry
   * NOTE: Requires message_audit_logs table in Prisma schema
   */
  async log(data: {
    messageId: string
    channelId: string
    actorId: string
    actorName: string
    actorEmail: string
    action: 'created' | 'edited' | 'trashed' | 'restored' | 'permanently_deleted'
    previousContent?: string
    newContent?: string
    metadata?: Record<string, unknown>
  }) {
    // This feature requires message_audit_logs table
    // Return a mock result for now
    logger.debug('Audit log requested but table not yet available:', data.action, data.messageId)
    return {
      id: 'pending',
      message_id: data.messageId,
      channel_id: data.channelId,
      actor_id: data.actorId,
      action: data.action,
      created_at: new Date()
    }
  },

  /**
   * Get audit logs with filters
   * NOTE: Requires message_audit_logs table in Prisma schema
   */
  async get(_filters: {
    channelId?: string
    messageId?: string
    actorId?: string
    action?: string
    startDate?: Date
    endDate?: Date
    limit?: number
    offset?: number
  }) {
    // This feature requires message_audit_logs table
    logger.debug('Audit log query requested but table not yet available')
    return []
  },

  /**
   * Count audit logs
   * NOTE: Requires message_audit_logs table in Prisma schema
   */
  async count(_filters: {
    channelId?: string
    messageId?: string
    actorId?: string
    action?: string
    startDate?: Date
    endDate?: Date
  }) {
    // This feature requires message_audit_logs table
    return 0
  }
}

// ============================================
// Pinned User Operations
// ============================================

export const pinnedUserOps = {
  /**
   * Toggle user pin status
   */
  async toggle(pinnerId: string, targetUserId: string, maxPins: number = 5) {
    const existing = await prisma.pinnedUser.findFirst({
      where: {
        pinner_id: pinnerId,
        pinned_user_id: targetUserId
      }
    })

    if (existing) {
      await prisma.pinnedUser.delete({ where: { id: existing.id } })
      return { action: 'unpinned' as const }
    }

    // Check pin limit
    const pinnedCount = await prisma.pinnedUser.count({
      where: { pinner_id: pinnerId }
    })

    if (pinnedCount >= maxPins) {
      throw new Error(`Maximum ${maxPins} pinned users allowed`)
    }

    const pinned = await prisma.pinnedUser.create({
      data: {
        pinner_id: pinnerId,
        pinned_user_id: targetUserId
      }
    })

    return { action: 'pinned' as const, pin: pinned }
  },

  /**
   * Get pinned users for a user
   */
  async getPinned(pinnerId: string) {
    return prisma.pinnedUser.findMany({
      where: { pinner_id: pinnerId },
      orderBy: { created_at: 'desc' }
    })
  },

  /**
   * Check if user is pinned
   */
  async isPinned(pinnerId: string, targetUserId: string): Promise<boolean> {
    const pin = await prisma.pinnedUser.findFirst({
      where: {
        pinner_id: pinnerId,
        pinned_user_id: targetUserId
      }
    })
    return !!pin
  }
}

// ============================================
// Member Operations
// ============================================

export const memberOps = {
  /**
   * Add member to channel
   */
  async add(
    channelId: string,
    userId: string,
    options?: {
      role?: 'member' | 'admin' | 'owner'
    }
  ) {
    const member = await prisma.channel_members.create({
      data: {
        channel_id: channelId,
        mongo_member_id: userId,
        role: options?.role ?? 'member'
      }
    })

    // Update member count
    await prisma.channels.update({
      where: { id: channelId },
      data: { member_count: { increment: 1 } }
    })

    // Invalidate cache
    communicationCache.invalidate(`channel:${channelId}`)

    return member
  },

  /**
   * Add multiple members
   */
  async addMany(
    channelId: string,
    userIds: string[],
    options?: { role?: 'member' | 'admin' }
  ) {
    const result = await prisma.channel_members.createMany({
      data: userIds.map(userId => ({
        channel_id: channelId,
        mongo_member_id: userId,
        role: options?.role ?? 'member'
      })),
      skipDuplicates: true
    })

    // Update member count
    await prisma.channels.update({
      where: { id: channelId },
      data: { member_count: { increment: result.count } }
    })

    // Invalidate cache
    communicationCache.invalidate(`channel:${channelId}`)

    return result
  },

  /**
   * Remove member from channel
   */
  async remove(channelId: string, userId: string) {
    const member = await prisma.channel_members.findFirst({
      where: { channel_id: channelId, mongo_member_id: userId }
    })

    if (!member) {
      throw new Error('Member not found')
    }

    await prisma.channel_members.delete({
      where: { id: member.id }
    })

    // Update member count
    await prisma.channels.update({
      where: { id: channelId },
      data: { member_count: { decrement: 1 } }
    })

    // Invalidate cache
    communicationCache.invalidate(`channel:${channelId}`)

    return { success: true, memberId: member.id }
  },

  /**
   * Update member role
   */
  async updateRole(channelId: string, userId: string, role: 'member' | 'admin' | 'owner') {
    const member = await prisma.channel_members.findFirst({
      where: { channel_id: channelId, mongo_member_id: userId }
    })

    if (!member) {
      throw new Error('Member not found')
    }

    return prisma.channel_members.update({
      where: { id: member.id },
      data: { role }
    })
  },

  /**
   * Get members of a channel
   */
  async getByChannel(channelId: string) {
    return prisma.channel_members.findMany({
      where: { channel_id: channelId }
    })
  },

  /**
   * Update member online status
   */
  async updateOnlineStatus(channelId: string, userId: string, isOnline: boolean) {
    return prisma.channel_members.updateMany({
      where: {
        channel_id: channelId,
        mongo_member_id: userId
      },
      data: {
        is_online: isOnline,
        last_seen_at: new Date()
      }
    })
  }
}

// ============================================
// Type Exports
// ============================================

export type ChannelWithMembers = Awaited<ReturnType<typeof channelOps.getById>>
export type MessageWithDetails = Awaited<ReturnType<typeof messageOps.create>>
export type ReactionToggleResult = Awaited<ReturnType<typeof reactionOps.toggle>>
