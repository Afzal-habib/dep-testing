/**
 * Channel Sync Manager
 * 
 * Handles automatic synchronization of channel members when:
 * - New user is created/updated with a department
 * - Task assignee is set on a project task
 * - User's department changes (remove from old, add to new)
 * 
 * Uses immediate sync + Supabase real-time broadcast pattern.
 * 
 * NOTE: Requires Prisma migration to be run first:
 * npx prisma migrate dev --name add_advanced_channel_features
 */

import { prisma } from '@/lib/prisma'
import { executeGenericDbQuery } from '@/lib/mongodb'
import User from '@/models/User'
import { supabase } from '@/lib/supabase'
import { enrichChannelWithUserData } from '@/lib/communication/utils'
import { communicationLogger as logger } from '@/lib/logger'

export interface SyncResult {
  success: boolean
  channelsSynced: number
  errors: string[]
}

interface UserData {
  _id: string
  name: string
  email: string
  avatar?: string
  role?: string
}

// Type for channel with members included
type ChannelWithMembers = Awaited<ReturnType<typeof prisma.channels.findFirst>> & {
  channel_members: Array<{
    id: string
    channel_id: string
    mongo_member_id: string
    role: string
    joined_at: Date
    last_seen_at: Date | null
    is_online: boolean
    notifications_enabled: boolean
    added_by?: string | null
    added_via?: string | null
  }>
}

class ChannelSyncManager {
  /**
   * Sync a user to all auto-sync enabled department channels
   * Called when: user is created with a department OR user's department is updated
   */
  async syncUserToDepartmentChannels(
    userId: string,
    departmentId: string,
    addedBy?: string
  ): Promise<SyncResult> {
    const errors: string[] = []
    let channelsSynced = 0

    try {
      // Find all auto-sync enabled channels for this department
      // Using raw query approach for new fields until Prisma client is regenerated
      const channels = await prisma.channels.findMany({
        where: {
          OR: [
            { mongo_department_id: departmentId, type: 'department' },
            { mongo_department_id: departmentId, type: 'department-category' }
          ],
          is_archived: false
        },
        include: {
          channel_members: true
        }
      }) as unknown as ChannelWithMembers[]
      
      // Filter for auto_sync_enabled channels (handle case where field might not exist)
      const syncChannels = channels.filter((ch: any) => ch.auto_sync_enabled !== false)

      if (syncChannels.length === 0) {
        logger.debug('No auto-sync channels found for department', departmentId)
        return { success: true, channelsSynced: 0, errors: [] }
      }

      // Get user data from MongoDB
      const user = await executeGenericDbQuery(async () => {
        return await User.findById(userId)
          .select('_id name email avatar role')
          .lean()
      }) as UserData | null

      if (!user) {
        return { success: false, channelsSynced: 0, errors: ['User not found'] }
      }

      // Add user to each channel
      for (const channel of syncChannels) {
        try {
          // Check if already a member
          const existingMember = channel.channel_members?.find(
            (m: any) => m.mongo_member_id === userId
          )
          
          if (existingMember) {
            logger.debug('User already a member of channel', { userId, channelId: channel.id })
            continue
          }

          // Add member - use any to bypass type checking until migration is run
          await prisma.channel_members.create({
            data: {
              id: crypto.randomUUID(),
              channel_id: channel.id,
              mongo_member_id: userId,
              role: 'member',
              joined_at: new Date(),
              added_by: addedBy || null,
              added_via: 'auto_sync'
            } as any
          })

          // Update member count
          await prisma.channels.update({
            where: { id: channel.id },
            data: { 
              member_count: { increment: 1 },
              updated_at: new Date()
            }
          })

          // Broadcast to user's personal channel for real-time notification
          await this.broadcastChannelToUser(userId, channel.id, 'new_channel')
          
          // Broadcast member_added to channel for other members
          await this.broadcastMemberUpdate(channel.id, userId, 'member_added', user)

          channelsSynced++
          logger.info('ChannelSyncManager: User synced to channel', { userId, channelId: channel.id })
        } catch (err: any) {
          errors.push(`Failed to sync to channel ${channel.id}: ${err.message}`)
          logger.error('ChannelSyncManager: Failed to sync user to channel', err)
        }
      }

      return { success: errors.length === 0, channelsSynced, errors }
    } catch (error: any) {
      logger.error('ChannelSyncManager.syncUserToDepartmentChannels failed:', error)
      return { success: false, channelsSynced: 0, errors: [error.message] }
    }
  }

  /**
   * Sync a task assignee to the project's channel
   * Called when: task is created with assignee OR task assignee is updated
   */
  async syncAssigneeToProjectChannel(
    assigneeId: string,
    projectId: string,
    addedBy?: string
  ): Promise<SyncResult> {
    try {
      // Find the project channel with auto-sync enabled
      const channel = await prisma.channels.findFirst({
        where: {
          mongo_project_id: projectId,
          type: 'project',
          is_archived: false
        },
        include: {
          channel_members: true
        }
      }) as unknown as ChannelWithMembers | null
      
      // Check if auto_sync is enabled (handle case where field might not exist)
      if (!channel || (channel as any).auto_sync_enabled === false) {
        // No project channel exists or auto-sync disabled
        logger.debug('No auto-sync project channel found', projectId)
        return { success: true, channelsSynced: 0, errors: [] }
      }

      // Check if already a member
      const existingMember = channel.channel_members?.find(
        (m: any) => m.mongo_member_id === assigneeId
      )

      if (existingMember) {
        logger.debug('Assignee already a member of project channel', { assigneeId, channelId: channel.id })
        return { success: true, channelsSynced: 0, errors: [] }
      }

      // Get user data from MongoDB
      const user = await executeGenericDbQuery(async () => {
        return await User.findById(assigneeId)
          .select('_id name email avatar role')
          .lean()
      }) as UserData | null

      if (!user) {
        return { success: false, channelsSynced: 0, errors: ['Assignee user not found'] }
      }

      // Add member - use any to bypass type checking until migration is run
      await prisma.channel_members.create({
        data: {
          id: crypto.randomUUID(),
          channel_id: channel.id,
          mongo_member_id: assigneeId,
          role: 'member',
          joined_at: new Date(),
          added_by: addedBy || null,
          added_via: 'auto_sync'
        } as any
      })

      // Update member count
      await prisma.channels.update({
        where: { id: channel.id },
        data: { 
          member_count: { increment: 1 },
          updated_at: new Date()
        }
      })

      // Broadcast to user's personal channel
      await this.broadcastChannelToUser(assigneeId, channel.id, 'new_channel')
      
      // Broadcast member_added to channel
      await this.broadcastMemberUpdate(channel.id, assigneeId, 'member_added', user)

      logger.info('Assignee synced to project channel', { assigneeId, channelId: channel.id })
      return { success: true, channelsSynced: 1, errors: [] }
    } catch (error: any) {
      logger.error('syncAssigneeToProjectChannel failed:', error)
      return { success: false, channelsSynced: 0, errors: [error.message] }
    }
  }

  /**
   * Remove user from department channels when department changes
   * Called when: user's department is updated to a different department
   */
  async removeUserFromDepartmentChannels(
    userId: string,
    oldDepartmentId: string
  ): Promise<SyncResult> {
    try {
      const channels = await prisma.channels.findMany({
        where: {
          mongo_department_id: oldDepartmentId,
          is_archived: false
        }
      })
      
      // Filter for auto_sync enabled channels
      const syncChannels = channels.filter((ch: any) => ch.auto_sync_enabled !== false)

      let removed = 0
      const errors: string[] = []

      for (const channel of syncChannels) {
        try {
          // Don't remove if user is owner/admin
          const member = await prisma.channel_members.findFirst({
            where: {
              channel_id: channel.id,
              mongo_member_id: userId
            }
          }) as any

          if (member && member.role === 'member' && member.added_via === 'auto_sync') {
            await prisma.channel_members.delete({
              where: { id: member.id }
            })

            await prisma.channels.update({
              where: { id: channel.id },
              data: { member_count: { decrement: 1 } }
            })

            // Broadcast removal to user
            await this.broadcastChannelToUser(userId, channel.id, 'channel_removed')
            
            // Broadcast removal to channel
            await this.broadcastMemberUpdate(channel.id, userId, 'member_removed')
            removed++
          }
        } catch (err: any) {
          errors.push(`Failed to remove from channel ${channel.id}: ${err.message}`)
        }
      }

      logger.info('ChannelSyncManager: User removed from department channels', { userId, removed })
      return { success: errors.length === 0, channelsSynced: removed, errors }
    } catch (error: any) {
      logger.error('ChannelSyncManager.removeUserFromDepartmentChannels failed:', error)
      return { success: false, channelsSynced: 0, errors: [error.message] }
    }
  }

  /**
   * Broadcast channel update to a specific user
   */
  private async broadcastChannelToUser(
    userId: string,
    channelId: string,
    eventType: 'new_channel' | 'channel_removed'
  ): Promise<void> {
    try {
      // Fetch full channel with members for the broadcast
      const channel = await prisma.channels.findUnique({
        where: { id: channelId },
        include: { channel_members: true }
      })

      if (!channel) return

      // Get all users for enrichment
      const allUsers = await executeGenericDbQuery(async () => {
        return await User.find({ isDeleted: { $ne: true } })
          .select('_id name email avatar isClient role')
          .lean()
      })

      const enrichedChannel = await enrichChannelWithUserData(channel, allUsers)

      // Create and subscribe to the channel first, then broadcast
      const rtChannel = supabase.channel(`user:${userId}:channels`)
      
      // Subscribe first (required for broadcast to work)
      await new Promise<void>((resolve, reject) => {
        rtChannel.subscribe((status, err) => {
          if (err) {
            reject(err)
            return
          }
          if (status === 'SUBSCRIBED') {
            resolve()
          }
        })
      })

      // Now send the broadcast
      await rtChannel.send({
        type: 'broadcast',
        event: 'channel_update',
        payload: {
          id: channelId,
          type: eventType,
          channel: enrichedChannel
        }
      })

      // Clean up
      await supabase.removeChannel(rtChannel)
      logger.info('ChannelSyncManager: Broadcasted channel update to user', { userId, channelId, eventType })
    } catch (error) {
      logger.warn('ChannelSyncManager: Failed to broadcast channel to user:', error)
    }
  }

  /**
   * Broadcast member update to all channel members
   */
  private async broadcastMemberUpdate(
    channelId: string,
    memberId: string,
    eventType: 'member_added' | 'member_removed' | 'member_updated',
    userData?: UserData
  ): Promise<void> {
    try {
      const rtChannel = supabase.channel(`rt_${channelId}`)
      
      // Subscribe first (required for broadcast to work)
      await new Promise<void>((resolve, reject) => {
        rtChannel.subscribe((status, err) => {
          if (err) {
            reject(err)
            return
          }
          if (status === 'SUBSCRIBED') {
            resolve()
          }
        })
      })

      // Now send the broadcast
      await rtChannel.send({
        type: 'broadcast',
        event: 'member_update',
        payload: {
          channelId,
          memberId,
          type: eventType,
          user: userData ? {
            mongo_member_id: userData._id.toString(),
            name: userData.name,
            email: userData.email,
            avatar: userData.avatar
          } : undefined
        }
      })

      // Clean up
      await supabase.removeChannel(rtChannel)
      logger.info('ChannelSyncManager: Broadcasted member update', { channelId, memberId, eventType })
    } catch (error) {
      logger.warn('ChannelSyncManager: Failed to broadcast member update:', error)
    }
  }
}

export const channelSyncManager = new ChannelSyncManager()
