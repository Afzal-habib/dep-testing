import { broadcastToUser } from '@/lib/communication/broadcast'
import { executeGenericDbQuery, clearCache } from '@/lib/mongodb'
import SystemNotification from '@/models/SystemNotification'
import User from '@/models/User'
import Department from '@/models/Department'
import Project from '@/models/Project'
import Task from '@/models/Task'
import { createSystemNotificationSchema } from '@/lib/validations/system-notification'
import { z } from 'zod'

export interface NotificationPayload {
  type: 'project_created' | 'task_assigned' | 'project_approved' | 'task_completed' | 'project_status_changed' | 'department_assigned'
  category: 'project' | 'task' | 'system' | 'department'
  recipientId: string
  senderId: string
  senderName: string
  senderAvatar?: string
  title: string
  message: string
  contentPreview?: string
  entityType: 'project' | 'task' | 'department' | 'user'
  entityId: string
  entityName?: string
  actionType: 'created' | 'updated' | 'assigned' | 'approved' | 'completed' | 'status_changed'
  actionUrl?: string
  priority?: 1 | 2 | 3 | 4
  metadata?: Record<string, any>
  expiresAt?: Date
}

export class NotificationService {
  /**
   * Create and broadcast notification using MongoDB + Supabase realtime
   */
  static async createNotification(payload: NotificationPayload): Promise<void> {
    try {
      // Validate payload
      const validatedPayload = createSystemNotificationSchema.parse(payload)
      
      // Create notification in MongoDB using executeGenericDbQuery
      const notification = await executeGenericDbQuery(async () => {
        const newNotification = new SystemNotification(validatedPayload)
        return await newNotification.save()
      })

      // Broadcast to user via Supabase realtime (async for performance)
      setImmediate(async () => {
        try {
          await broadcastToUser({
            userId: payload.recipientId,
            event: 'dm_notification',
            payload: {
              id: notification._id.toString(),
              type: notification.type,
              category: notification.category,
              title: notification.title,
              message: notification.message,
              contentPreview: notification.contentPreview,
              entityType: notification.entityType,
              entityId: notification.entityId.toString(),
              entityName: notification.entityName,
              actionType: notification.actionType,
              actionUrl: notification.actionUrl,
              senderName: notification.senderName,
              senderAvatar: notification.senderAvatar,
              priority: notification.priority,
              createdAt: notification.createdAt.toISOString(),
              metadata: notification.metadata
            }
          })
          
          console.log(`✅ System notification sent to user ${payload.recipientId}:`, payload.title)
        } catch (broadcastError) {
          console.error('❌ Failed to broadcast notification:', broadcastError)
          // Note: We don't throw here to avoid blocking the main operation
        }
      })
      
      // Clear related cache patterns
      clearCache(`user-notifications-${payload.recipientId}`)
      clearCache(`unread-system-notifications-${payload.recipientId}`)
      
    } catch (error) {
      if (error instanceof z.ZodError) {
        console.error('❌ Notification validation failed:', error.errors)
        throw new Error(`Invalid notification payload: ${error.errors.map(e => e.message).join(', ')}`)
      }
      
      console.error('❌ Failed to create system notification:', error)
      throw new Error('Failed to create system notification')
    }
  }

  /**
   * Get user notifications with pagination
   */
  static async getUserNotifications(userId: string, options: {
    limit?: number
    offset?: number
    unreadOnly?: boolean
  } = {}): Promise<any[]> {
    const { limit = 50, offset = 0, unreadOnly = false } = options
    
    return executeGenericDbQuery(async () => {
      const query: any = { recipientId: userId }
      
      if (unreadOnly) {
        query.isRead = false
      }
      
      return await SystemNotification
        .find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(offset)
        .populate('sender', 'name email avatar')
        .lean()
    }, `user-notifications-${userId}-${limit}-${offset}-${unreadOnly}`, 30000)
  }

  /**
   * Mark notifications as read
   */
  static async markAsRead(notificationIds: string[], userId: string): Promise<void> {
    await executeGenericDbQuery(async () => {
      return await SystemNotification.updateMany(
        {
          _id: { $in: notificationIds },
          recipientId: userId
        },
        {
          $set: {
            isRead: true,
            readAt: new Date()
          }
        }
      )
    })
    
    // Clear related cache
    clearCache(`user-notifications-${userId}`)
    clearCache(`unread-system-notifications-${userId}`)
  }

  /**
   * Mark all notifications as read for a user
   */
  static async markAllAsRead(userId: string): Promise<void> {
    await executeGenericDbQuery(async () => {
      return await SystemNotification.updateMany(
        {
          recipientId: userId,
          isRead: false
        },
        {
          $set: {
            isRead: true,
            readAt: new Date()
          }
        }
      )
    })
    
    // Clear related cache
    clearCache(`user-notifications-${userId}`)
    clearCache(`unread-system-notifications-${userId}`)
  }

  /**
   * Get notification recipients based on rules
   */
  static async getNotificationRecipients(params: {
    type: string
    entityType: string
    entityId: string
    departmentId?: string
    projectId?: string
  }): Promise<string[]> {
    const recipients: string[] = []
    
    try {
      switch (params.type) {
        case 'project_created':
        case 'project_approved':
        case 'project_status_changed':
          // Notify department heads and managers
          if (params.departmentId) {
            const departmentHeads = await executeGenericDbQuery(async () => {
              return await User.find({
                departmentId: params.departmentId,
                role: { $in: ['department_head', 'manager'] },
                status: 'active'
              }).select('_id').lean()
            })
            recipients.push(...departmentHeads.map(u => u._id.toString()))
          }
          break
          
        case 'task_assigned':
        case 'task_completed':
          // Notify task assignee and project creator
          if (params.entityId) {
            const task = await executeGenericDbQuery(async () => {
              return await Task.findById(params.entityId)
                .populate('project', 'createdBy')
                .lean()
            }) as any
            
            if (task?.assigneeId) {
              recipients.push(task.assigneeId.toString())
            }
            
            if (task?.project?.createdBy) {
              recipients.push(task.project.createdBy.toString())
            }
          }
          break
          
        case 'department_assigned':
          // Notify department members
          if (params.departmentId) {
            const departmentMembers = await executeGenericDbQuery(async () => {
              return await User.find({
                departmentId: params.departmentId,
                status: 'active'
              }).select('_id').lean()
            })
            recipients.push(...departmentMembers.map(u => u._id.toString()))
          }
          break
      }
    } catch (error) {
      console.error('Failed to get notification recipients:', error)
    }
    
    return [...new Set(recipients)] // Remove duplicates
  }

  /**
   * Project-specific notifications
   */
  static async notifyProjectCreated(projectId: string, creatorId: string): Promise<void> {
    try {
      const project = await executeGenericDbQuery(async () => {
        return await Project.findById(projectId)
          .populate('createdBy', 'name avatar')
          .populate('client', 'name')
          .lean()
      }) as any
      
      if (!project) return
      
      const recipients = await this.getNotificationRecipients({
        type: 'project_created',
        entityType: 'project',
        entityId: projectId,
        departmentId: project.departmentIds?.[0]?.toString()
      })
      
      // Send notification to each recipient
      for (const recipientId of recipients) {
        if (recipientId !== creatorId) { // Don't notify creator
          await this.createNotification({
            type: 'project_created',
            category: 'project',
            recipientId,
            senderId: creatorId,
            senderName: project.createdBy?.name || 'Unknown User',
            senderAvatar: project.createdBy?.avatar,
            title: 'New Project Created',
            message: `A new project "${project.name}" has been created for client ${project.client?.name || 'Unknown Client'}`,
            contentPreview: project.description?.substring(0, 100),
            entityType: 'project',
            entityId: projectId,
            entityName: project.name,
            actionType: 'created',
            actionUrl: `/projects/${projectId}`,
            priority: 2
          })
        }
      }
    } catch (error) {
      console.error('Failed to notify project created:', error)
    }
  }

  static async notifyProjectApproved(projectId: string, approverId: string): Promise<void> {
    try {
      const project = await executeGenericDbQuery(async () => {
        return await Project.findById(projectId)
          .populate('createdBy', 'name')
          .populate('approver', 'name avatar')
          .lean()
      }) as any
      
      if (!project || !project.createdBy) return
      
      await this.createNotification({
        type: 'project_approved',
        category: 'project',
        recipientId: project.createdBy._id.toString(),
        senderId: approverId,
        senderName: project.approver?.name || 'System',
        senderAvatar: project.approver?.avatar,
        title: 'Project Approved',
        message: `Your project "${project.name}" has been approved and is now active`,
        contentPreview: 'Project approved for development',
        entityType: 'project',
        entityId: projectId,
        entityName: project.name,
        actionType: 'approved',
        actionUrl: `/projects/${projectId}`,
        priority: 3
      })
    } catch (error) {
      console.error('Failed to notify project approved:', error)
    }
  }

  static async notifyTaskAssigned(taskId: string, assignerId: string, assigneeId: string): Promise<void> {
    try {
      const task = await executeGenericDbQuery(async () => {
        return await Task.findById(taskId)
          .populate('project', 'name')
          .populate('creator', 'name avatar')
          .lean()
      }) as any
      
      if (!task || assignerId === assigneeId) return
      
      const assigner = await executeGenericDbQuery(async () => {
        return await User.findById(assignerId).select('name avatar').lean()
      }) as any
      
      await this.createNotification({
        type: 'task_assigned',
        category: 'task',
        recipientId: assigneeId,
        senderId: assignerId,
        senderName: assigner?.name || 'Unknown User',
        senderAvatar: assigner?.avatar,
        title: 'Task Assigned',
        message: `You have been assigned a new task: "${task.title}"`,
        contentPreview: task.description?.substring(0, 100),
        entityType: 'task',
        entityId: taskId,
        entityName: task.title,
        actionType: 'assigned',
        actionUrl: `/projects/${task.projectId}?task=${taskId}`,
        priority: task.priority === 'urgent' ? 4 : task.priority === 'high' ? 3 : 2
      })
    } catch (error) {
      console.error('Failed to notify task assigned:', error)
    }
  }

  /**
   * Cleanup expired notifications (run via cron job)
   */
  static async cleanupExpiredNotifications(): Promise<void> {
    try {
      await executeGenericDbQuery(async () => {
        return await SystemNotification.deleteMany({
          expiresAt: { $lt: new Date() }
        })
      })
    } catch (error) {
      console.error('Failed to cleanup expired notifications:', error)
    }
  }

  /**
   * Get unread notification count for a user
   */
  static async getUnreadCount(userId: string): Promise<number> {
    return executeGenericDbQuery(async () => {
      return await SystemNotification.countDocuments({
        recipientId: userId,
        isRead: false
      })
    }, `unread-count-${userId}`, 10000) // Cache for 10 seconds
  }
}