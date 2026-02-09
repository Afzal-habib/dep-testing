# Realtime Notifications & Task Operations Implementation Plan

**Created:** January 5, 2026  
**Status:** 🟡 Planning Phase  
**Architecture:** Hybrid (MongoDB Primary + Supabase Realtime)

## 📋 Overview

This plan extends the existing communication module's realtime capabilities to create a generic notification system and realtime task operations experience. We'll leverage the current Supabase realtime infrastructure for broadcasting while maintaining MongoDB as the primary database for all business logic including system notifications.

## 🏗️ Current Architecture Analysis

### Existing Infrastructure
```
✅ AVAILABLE:
├── Supabase Realtime (broadcast.ts, realtime-manager.ts)
├── Message Notification System (message-notification.tsx)
├── MongoDB Task Operations (useTasks hook, TaskCategorization)
├── Project Management (useProjects, ProjectCategorization)
├── User Management & Permissions (useUsers, usePermissions)
├── Redux Store with Communication Slice
└── Generic CRUD Patterns (COMPLETE-CRUD-IMPLEMENTATION)

🎯 TO BUILD:
├── Generic Notification System
├── Realtime Task Operations
├── Project-related Notifications
└── Task Board Realtime Experience
```

## 🎯 Phase 1: Generic Realtime Notification System

### 1.1 Database Schema Extension (MongoDB)

**New Mongoose Models Required:**

**File: `models/SystemNotification.ts`**
```typescript
import mongoose, { Document, Schema } from 'mongoose'

export interface ISystemNotification extends Document {
  // Core notification data
  type: 'project_created' | 'task_assigned' | 'project_approved' | 'task_completed' | 'project_status_changed' | 'department_assigned'
  category: 'project' | 'task' | 'system' | 'department'
  
  // Recipient info
  recipientId: mongoose.Types.ObjectId // MongoDB user ID
  recipientRole?: string // Optional: specific role requirement
  
  // Sender info
  senderId: mongoose.Types.ObjectId // MongoDB user ID
  senderName: string
  senderAvatar?: string
  
  // Notification content
  title: string
  message: string
  contentPreview?: string // Short description
  
  // Related entity data
  entityType: 'project' | 'task' | 'department' | 'user'
  entityId: mongoose.Types.ObjectId // MongoDB entity ID
  entityName?: string
  
  // Action data
  actionType: 'created' | 'updated' | 'assigned' | 'approved' | 'completed' | 'status_changed'
  actionUrl?: string // Deep link to the entity
  
  // Status tracking
  isRead: boolean
  readAt?: Date
  expiresAt?: Date // Optional: auto-cleanup
  
  // Additional metadata
  metadata?: Record<string, any> // Flexible data for future extensions
  priority: 1 | 2 | 3 | 4 // 1=low, 2=medium, 3=high, 4=urgent
  
  // Meta fields
  createdAt: Date
  updatedAt: Date
}

const SystemNotificationSchema = new Schema<ISystemNotification>({
  type: {
    type: String,
    enum: ['project_created', 'task_assigned', 'project_approved', 'task_completed', 'project_status_changed', 'department_assigned'],
    required: [true, 'Notification type is required']
  },
  category: {
    type: String,
    enum: ['project', 'task', 'system', 'department'],
    required: [true, 'Category is required']
  },
  recipientId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Recipient is required'],
    index: true
  },
  recipientRole: {
    type: String,
    trim: true
  },
  senderId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Sender is required']
  },
  senderName: {
    type: String,
    required: [true, 'Sender name is required'],
    trim: true
  },
  senderAvatar: {
    type: String,
    trim: true
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    maxlength: [255, 'Title cannot exceed 255 characters']
  },
  message: {
    type: String,
    required: [true, 'Message is required'],
    trim: true,
    maxlength: [1000, 'Message cannot exceed 1000 characters']
  },
  contentPreview: {
    type: String,
    trim: true,
    maxlength: [200, 'Content preview cannot exceed 200 characters']
  },
  entityType: {
    type: String,
    enum: ['project', 'task', 'department', 'user'],
    required: [true, 'Entity type is required']
  },
  entityId: {
    type: Schema.Types.ObjectId,
    required: [true, 'Entity ID is required'],
    index: true
  },
  entityName: {
    type: String,
    trim: true
  },
  actionType: {
    type: String,
    enum: ['created', 'updated', 'assigned', 'approved', 'completed', 'status_changed'],
    required: [true, 'Action type is required']
  },
  actionUrl: {
    type: String,
    trim: true
  },
  isRead: {
    type: Boolean,
    default: false,
    index: true
  },
  readAt: {
    type: Date
  },
  expiresAt: {
    type: Date,
    index: true
  },
  metadata: {
    type: Schema.Types.Mixed,
    default: {}
  },
  priority: {
    type: Number,
    enum: [1, 2, 3, 4],
    default: 1
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
})

// Performance indexes
SystemNotificationSchema.index({ recipientId: 1, isRead: 1, createdAt: -1 })
SystemNotificationSchema.index({ type: 1, createdAt: -1 })
SystemNotificationSchema.index({ entityType: 1, entityId: 1 })
SystemNotificationSchema.index({ category: 1, createdAt: -1 })
SystemNotificationSchema.index({ priority: 1, isRead: 1 })
SystemNotificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }) // TTL index

// Virtuals
SystemNotificationSchema.virtual('recipient', {
  ref: 'User',
  localField: 'recipientId',
  foreignField: '_id',
  justOne: true
})

SystemNotificationSchema.virtual('sender', {
  ref: 'User',
  localField: 'senderId',
  foreignField: '_id',
  justOne: true
})

export default mongoose.models.SystemNotification || mongoose.model<ISystemNotification>('SystemNotification', SystemNotificationSchema)

### 1.1.2 Validation Schemas (Following App Patterns)

**File: `lib/validations/system-notification.ts`**
```typescript
import { z } from 'zod'

// Notification type validation
export const notificationTypeSchema = z.enum([
  'project_created',
  'task_assigned', 
  'project_approved',
  'task_completed',
  'project_status_changed',
  'department_assigned'
])

export const notificationCategorySchema = z.enum(['project', 'task', 'system', 'department'])
export const entityTypeSchema = z.enum(['project', 'task', 'department', 'user'])
export const actionTypeSchema = z.enum(['created', 'updated', 'assigned', 'approved', 'completed', 'status_changed'])
export const prioritySchema = z.enum([1, 2, 3, 4])

// MongoDB ObjectId validation
export const objectIdSchema = z.string().regex(
  /^[0-9a-fA-F]{24}$/,
  'Invalid ObjectId format'
)

// Base notification schema
export const baseSystemNotificationSchema = z.object({
  type: notificationTypeSchema,
  category: notificationCategorySchema,
  recipientId: objectIdSchema,
  recipientRole: z.string().optional(),
  senderId: objectIdSchema,
  senderName: z.string().min(1, 'Sender name is required').max(100),
  senderAvatar: z.string().url().optional(),
  title: z.string().min(1, 'Title is required').max(255),
  message: z.string().min(1, 'Message is required').max(1000),
  contentPreview: z.string().max(200).optional(),
  entityType: entityTypeSchema,
  entityId: objectIdSchema,
  entityName: z.string().max(255).optional(),
  actionType: actionTypeSchema,
  actionUrl: z.string().max(500).optional(),
  priority: prioritySchema.default(1),
  metadata: z.record(z.any()).optional(),
  expiresAt: z.date().optional()
})

// Create notification validation
export const createSystemNotificationSchema = baseSystemNotificationSchema.strict()

// Update notification validation  
export const updateSystemNotificationSchema = z.object({
  isRead: z.boolean().optional(),
  readAt: z.date().optional()
}).strict()

// Notification query parameters
export const notificationQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(50),
  offset: z.coerce.number().min(0).default(0),
  unreadOnly: z.coerce.boolean().default(false),
  category: notificationCategorySchema.optional(),
  type: notificationTypeSchema.optional()
})

// Mark as read schema
export const markAsReadSchema = z.object({
  notificationIds: z.array(objectIdSchema).min(1).optional(),
  markAllAsRead: z.boolean().optional()
}).refine(
  (data) => data.notificationIds || data.markAllAsRead,
  'Either notificationIds or markAllAsRead must be provided'
)

// Notification response schema
export const systemNotificationResponseSchema = z.object({
  success: z.boolean(),
  data: z.any().optional(),
  error: z.string().optional(),
  pagination: z.object({
    limit: z.number(),
    offset: z.number(),
    hasMore: z.boolean()
  }).optional()
})
```
```

**File: `models/TaskOperation.ts`**
```typescript
import mongoose, { Document, Schema } from 'mongoose'

export interface ITaskOperation extends Document {
  // Task info
  taskId: mongoose.Types.ObjectId
  projectId: mongoose.Types.ObjectId
  departmentId?: mongoose.Types.ObjectId
  
  // Operation data
  operationType: 'create' | 'update' | 'delete' | 'assign' | 'status_change' | 'priority_change'
  oldData?: Record<string, any>
  newData: Record<string, any>
  
  // User info
  userId: mongoose.Types.ObjectId
  userName: string
  
  // Channel broadcast info
  broadcastChannels?: string[]
  broadcastStatus: 'pending' | 'sent' | 'failed'
  
  // Meta fields
  createdAt: Date
}

const TaskOperationSchema = new Schema<ITaskOperation>({
  taskId: {
    type: Schema.Types.ObjectId,
    ref: 'Task',
    required: [true, 'Task ID is required'],
    index: true
  },
  projectId: {
    type: Schema.Types.ObjectId,
    ref: 'Project',
    required: [true, 'Project ID is required'],
    index: true
  },
  departmentId: {
    type: Schema.Types.ObjectId,
    ref: 'Department',
    index: true
  },
  operationType: {
    type: String,
    enum: ['create', 'update', 'delete', 'assign', 'status_change', 'priority_change'],
    required: [true, 'Operation type is required']
  },
  oldData: {
    type: Schema.Types.Mixed
  },
  newData: {
    type: Schema.Types.Mixed,
    required: [true, 'New data is required']
  },
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User ID is required'],
    index: true
  },
  userName: {
    type: String,
    required: [true, 'User name is required'],
    trim: true
  },
  broadcastChannels: [{
    type: String,
    trim: true
  }],
  broadcastStatus: {
    type: String,
    enum: ['pending', 'sent', 'failed'],
    default: 'pending'
  }
}, {
  timestamps: { createdAt: true, updatedAt: false },
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
})

// Performance indexes
TaskOperationSchema.index({ taskId: 1, createdAt: -1 })
TaskOperationSchema.index({ projectId: 1, createdAt: -1 })
TaskOperationSchema.index({ userId: 1, createdAt: -1 })
TaskOperationSchema.index({ operationType: 1, createdAt: -1 })

// TTL index to auto-cleanup old operations (keep for 30 days)
TaskOperationSchema.index({ createdAt: 1 }, { expireAfterSeconds: 2592000 })

export default mongoose.models.TaskOperation || mongoose.model<ITaskOperation>('TaskOperation', TaskOperationSchema)

**File: `lib/validations/task-operation.ts`**
```typescript
import { z } from 'zod'
import { objectIdSchema } from './system-notification'

// Operation type validation
export const operationTypeSchema = z.enum([
  'create', 
  'update', 
  'delete', 
  'assign', 
  'status_change', 
  'priority_change',
  'revert_status_change'
])

export const broadcastStatusSchema = z.enum(['pending', 'sent', 'failed'])

// Base task operation schema
export const baseTaskOperationSchema = z.object({
  taskId: objectIdSchema,
  projectId: objectIdSchema,
  departmentId: objectIdSchema.optional(),
  operationType: operationTypeSchema,
  oldData: z.record(z.any()).optional(),
  newData: z.record(z.any()),
  userId: objectIdSchema,
  userName: z.string().min(1).max(100),
  broadcastChannels: z.array(z.string()).optional(),
  broadcastStatus: broadcastStatusSchema.default('pending')
})

// Create task operation validation
export const createTaskOperationSchema = baseTaskOperationSchema.strict()

// Drag and drop operation validation
export const dragAndDropOperationSchema = z.object({
  taskId: objectIdSchema,
  oldStatus: z.string().min(1),
  newStatus: z.string().min(1),
  oldOrder: z.number().min(0).optional(),
  newOrder: z.number().min(0).optional(),
  projectId: objectIdSchema,
  departmentId: objectIdSchema.optional(),
  userId: objectIdSchema,
  userName: z.string().min(1)
})

// Task assignment operation validation
export const taskAssignmentOperationSchema = z.object({
  taskId: objectIdSchema,
  oldAssigneeId: objectIdSchema.optional(),
  newAssigneeId: objectIdSchema.optional(),
  assignerId: objectIdSchema,
  assignerName: z.string().min(1),
  projectId: objectIdSchema,
  departmentId: objectIdSchema.optional(),
  taskTitle: z.string().min(1)
})

// Task operations query validation
export const taskOperationsQuerySchema = z.object({
  taskId: objectIdSchema.optional(),
  projectId: objectIdSchema.optional(),
  departmentId: objectIdSchema.optional(),
  operationType: operationTypeSchema.optional(),
  limit: z.coerce.number().min(1).max(200).default(50),
  offset: z.coerce.number().min(0).default(0)
})
```
```

### 1.2 Backend Services

**File: `lib/services/notification-service.ts`**
```typescript
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
            event: 'system_notification',
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
            })
            
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
          .populate('creator', 'name avatar')
          .populate('client', 'name')
          .lean()
      })
      
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
            senderName: project.creator?.name || 'Unknown User',
            senderAvatar: project.creator?.avatar,
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
          .populate('creator', 'name')
          .populate('approver', 'name avatar')
          .lean()
      })
      
      if (!project || !project.creator) return
      
      await this.createNotification({
        type: 'project_approved',
        category: 'project',
        recipientId: project.creator._id.toString(),
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
      })
      
      if (!task || assignerId === assigneeId) return
      
      const assigner = await executeGenericDbQuery(async () => {
        return await User.findById(assignerId).select('name avatar').lean()
      })
      
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
```

### 1.3 Frontend Components

**File: `components/notifications/system-notification.tsx`**
```typescript
"use client"
import { useState, useCallback, useMemo } from 'react'
import { Bell, BellRing, CheckCircle, Clock, AlertCircle } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarImage, AvatarFallback } from '@/components/ui/avatar'
import { useSystemNotifications } from '@/hooks/use-system-notifications'

interface SystemNotificationProps {
  className?: string
  showBadge?: boolean
}

export const SystemNotification = ({ className, showBadge = true }: SystemNotificationProps) => {
  // Component implementation
  // Similar structure to message-notification.tsx but for system notifications
}
```

**File: `hooks/use-system-notifications.ts`**
```typescript
import { useAppDispatch, useAppSelector } from '@/hooks/redux'
import { useSession } from 'next-auth/react'
import { useState, useEffect, useCallback, useRef } from 'react'
import { getRealtimeManager } from '@/lib/realtime-manager'
import { apiRequest, handleAPIError } from '@/lib/utils/api-client'
import { useToast } from '@/hooks/use-toast'
import { useGenericQuery, useGenericUpdate } from '@/hooks/use-generic-query'
import {
  setNotifications,
  addNotification,
  markAsRead as markAsReadAction,
  markAllAsRead as markAllAsReadAction,
  setLoading,
  setError,
  clearNotifications
} from '@/store/slices/systemNotificationSlice'

export function useSystemNotifications() {
  const dispatch = useAppDispatch()
  const { toast } = useToast()
  const { data: session } = useSession()
  const realtimeManager = getRealtimeManager()
  const subscriptionInitializedRef = useRef(false)
  
  const {
    notifications,
    unreadCount,
    loading,
    error,
    lastFetch
  } = useAppSelector((state) => state.systemNotifications)
  
  const currentUserId = (session?.user as any)?.id
  
  // Handle realtime system notification
  const handleSystemNotification = useCallback((payload: any) => {
    const notification = {
      id: payload.id,
      type: payload.type,
      category: payload.category,
      title: payload.title,
      message: payload.message,
      contentPreview: payload.contentPreview,
      entityType: payload.entityType,
      entityId: payload.entityId,
      entityName: payload.entityName,
      actionUrl: payload.actionUrl,
      senderName: payload.senderName,
      senderAvatar: payload.senderAvatar,
      isRead: false,
      priority: payload.priority,
      createdAt: payload.createdAt,
      metadata: payload.metadata
    }
    
    dispatch(addNotification(notification))
    
    // Show toast notification
    toast({
      title: payload.title,
      description: payload.message,
      variant: payload.priority >= 3 ? 'destructive' : 'default',
      duration: payload.priority >= 3 ? 8000 : 5000
    })
  }, [dispatch, toast])
  
  // Subscribe to system notifications
  const subscribeToNotifications = useCallback(async (categories?: string[]) => {
    if (!currentUserId || subscriptionInitializedRef.current) return
    
    try {
      await realtimeManager.subscribeToNotifications(currentUserId, {
        onSystemNotification: handleSystemNotification
      })
      
      subscriptionInitializedRef.current = true
      console.log('Subscribed to system notifications for user:', currentUserId)
    } catch (error) {
      console.error('Failed to subscribe to system notifications:', error)
    }
  }, [currentUserId, realtimeManager, handleSystemNotification])
  
  // Unsubscribe from notifications
  const unsubscribeFromNotifications = useCallback(() => {
    if (!currentUserId) return
    
    try {
      realtimeManager.unsubscribeFromNotifications(currentUserId)
      subscriptionInitializedRef.current = false
      console.log('Unsubscribed from system notifications')
    } catch (error) {
      console.error('Failed to unsubscribe from notifications:', error)
    }
  }, [currentUserId, realtimeManager])
  
  // Fetch notifications from API
  const fetchNotifications = useCallback(async (options: {
    limit?: number
    offset?: number
    unreadOnly?: boolean
  } = {}) => {
    if (!currentUserId) return
    
    dispatch(setLoading(true))
    dispatch(setError(null))
    
    try {
      const params = new URLSearchParams()
      if (options.limit) params.set('limit', options.limit.toString())
      if (options.offset) params.set('offset', options.offset.toString())
      if (options.unreadOnly) params.set('unreadOnly', 'true')
      
      const response = await apiRequest(`/api/system-notifications?${params.toString()}`)
      const notifications = response.notifications || []
      
      dispatch(setNotifications(notifications))
    } catch (error) {
      console.error('Failed to fetch system notifications:', error)
      dispatch(setError('Failed to load notifications'))
    } finally {
      dispatch(setLoading(false))
    }
  }, [currentUserId, dispatch])
  
  // Mark notifications as read
  const markAsRead = useCallback(async (notificationIds: string[]) => {
    if (!currentUserId || notificationIds.length === 0) return
    
    try {
      await apiRequest.patch('/api/system-notifications', {
        notificationIds
      })
      
      dispatch(markAsReadAction(notificationIds))
    } catch (error) {
      console.error('Failed to mark notifications as read:', error)
      toast({
        title: 'Error',
        description: 'Failed to mark notifications as read',
        variant: 'destructive'
      })
    }
  }, [currentUserId, dispatch, toast])
  
  // Mark all notifications as read
  const markAllAsRead = useCallback(async () => {
    if (!currentUserId) return
    
    try {
      await apiRequest.patch('/api/system-notifications', {
        markAllAsRead: true
      })
      
      dispatch(markAllAsReadAction())
      
      toast({
        title: 'Success',
        description: 'All notifications marked as read',
        variant: 'default'
      })
    } catch (error) {
      console.error('Failed to mark all notifications as read:', error)
      toast({
        title: 'Error',
        description: 'Failed to mark notifications as read',
        variant: 'destructive'
      })
    }
  }, [currentUserId, dispatch, toast])
  
  // Auto-subscribe on mount
  useEffect(() => {
    if (currentUserId && !subscriptionInitializedRef.current) {
      subscribeToNotifications()
    }
    
    return () => {
      unsubscribeFromNotifications()
    }
  }, [currentUserId, subscribeToNotifications, unsubscribeFromNotifications])
  
  // Auto-fetch on mount if no recent data
  useEffect(() => {
    const fiveMinutesAgo = Date.now() - (5 * 60 * 1000)
    
    if (currentUserId && (!lastFetch || lastFetch < fiveMinutesAgo)) {
      fetchNotifications({ limit: 50 })
    }
  }, [currentUserId, lastFetch, fetchNotifications])
  
  return {
    notifications,
    unreadCount,
    loading,
    error,
    markAsRead,
    markAllAsRead,
    fetchNotifications,
    subscribeToNotifications,
    unsubscribeFromNotifications
  }
}
```

### 1.4 Redux Store Extension

**File: `store/slices/systemNotificationSlice.ts`**
```typescript
import { createSlice, PayloadAction } from '@reduxjs/toolkit'

interface SystemNotification {
  id: string
  type: string
  category: string
  title: string
  message: string
  contentPreview?: string
  entityType: string
  entityId: string
  entityName?: string
  actionUrl?: string
  senderName: string
  senderAvatar?: string
  isRead: boolean
  priority: number
  createdAt: string
  readAt?: string
  metadata?: Record<string, any>
}

interface SystemNotificationState {
  notifications: SystemNotification[]
  unreadCount: number
  loading: boolean
  error: string | null
  lastFetch: number | null
}

const initialState: SystemNotificationState = {
  notifications: [],
  unreadCount: 0,
  loading: false,
  error: null,
  lastFetch: null
}

const systemNotificationSlice = createSlice({
  name: 'systemNotifications',
  initialState,
  reducers: {
    setNotifications: (state, action: PayloadAction<SystemNotification[]>) => {
      state.notifications = action.payload
      state.unreadCount = action.payload.filter(n => !n.isRead).length
      state.lastFetch = Date.now()
    },
    
    addNotification: (state, action: PayloadAction<SystemNotification>) => {
      state.notifications.unshift(action.payload)
      if (!action.payload.isRead) {
        state.unreadCount += 1
      }
    },
    
    markAsRead: (state, action: PayloadAction<string[]>) => {
      const notificationIds = new Set(action.payload)
      state.notifications.forEach(notification => {
        if (notificationIds.has(notification.id) && !notification.isRead) {
          notification.isRead = true
          notification.readAt = new Date().toISOString()
          state.unreadCount -= 1
        }
      })
    },
    
    markAllAsRead: (state) => {
      state.notifications.forEach(notification => {
        if (!notification.isRead) {
          notification.isRead = true
          notification.readAt = new Date().toISOString()
        }
      })
      state.unreadCount = 0
    },
    
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload
    },
    
    setError: (state, action: PayloadAction<string | null>) => {
      state.error = action.payload
    },
    
    clearNotifications: (state) => {
      state.notifications = []
      state.unreadCount = 0
    }
  }
})

export const {
  setNotifications,
  addNotification,
  markAsRead,
  markAllAsRead,
  setLoading,
  setError,
  clearNotifications
} = systemNotificationSlice.actions

export default systemNotificationSlice.reducer
```

## 🎯 Phase 2: Realtime Task Operations

### 2.1 Task Operations Service

**File: `lib/services/task-operations-service.ts`**
```typescript
import { executeGenericDbQuery } from '@/lib/mongodb'
import { broadcastToChannel, broadcastToMultipleChannels } from '@/lib/communication/broadcast'
import TaskOperation from '@/models/TaskOperation'

export interface TaskOperationData {
  taskId: string
  projectId: string
  departmentId?: string
  operationType: 'create' | 'update' | 'delete' | 'assign' | 'status_change' | 'priority_change'
  oldData?: any
  newData: any
  userId: string
  userName: string
  broadcastChannels?: string[]
}

export class TaskOperationsService {
  /**
   * Record task operation in MongoDB and broadcast via Supabase realtime
   */
  static async recordTaskOperation(data: TaskOperationData): Promise<void> {
    try {
      // Insert operation record in MongoDB
      const operation = await executeGenericDbQuery(async () => {
        return await TaskOperation.create({
          taskId: data.taskId,
          projectId: data.projectId,
          departmentId: data.departmentId,
          operationType: data.operationType,
          oldData: data.oldData,
          newData: data.newData,
          userId: data.userId,
          userName: data.userName,
          broadcastChannels: data.broadcastChannels || [],
          broadcastStatus: 'pending'
        })
      })

      // Broadcast to relevant channels via Supabase
      await this.broadcastTaskOperation(data)
      
      // Update broadcast status to 'sent' in MongoDB
      await executeGenericDbQuery(async () => {
        return await TaskOperation.findByIdAndUpdate(
          operation._id,
          { broadcastStatus: 'sent' },
          { new: true }
        )
      })
      
    } catch (error) {
      console.error('Failed to record task operation:', error)
      
      // Update broadcast status to 'failed' if operation was created
      try {
        const failedOperation = await executeGenericDbQuery(async () => {
          return await TaskOperation.findOne({
            taskId: data.taskId,
            operationType: data.operationType,
            userId: data.userId,
            broadcastStatus: 'pending'
          }).sort({ createdAt: -1 })
        })
        
        if (failedOperation) {
          await executeGenericDbQuery(async () => {
            return await TaskOperation.findByIdAndUpdate(
              failedOperation._id,
              { broadcastStatus: 'failed' }
            )
          })
        }
      } catch (updateError) {
        console.error('Failed to update broadcast status:', updateError)
      }
      
      throw error
    }
  }

  /**
   * Broadcast task operation to relevant Supabase realtime channels
   */
  private static async broadcastTaskOperation(data: TaskOperationData): Promise<void> {
    const broadcastPromises: Promise<boolean>[] = []
    
    // Determine broadcast channels
    const channels = data.broadcastChannels || await this.determineBroadcastChannels(data)
    
    // Broadcast to each channel
    channels.forEach(channelId => {
      broadcastPromises.push(
        broadcastToChannel({
          channelId,
          event: 'task_operation',
          payload: {
            operation_type: data.operationType,
            task_id: data.taskId,
            project_id: data.projectId,
            department_id: data.departmentId,
            old_data: data.oldData,
            new_data: data.newData,
            user_id: data.userId,
            user_name: data.userName,
            timestamp: new Date().toISOString()
          }
        })
      )
    })

    // Wait for all broadcasts to complete
    const results = await Promise.allSettled(broadcastPromises)
    
    // Log any failed broadcasts
    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        console.error(`Failed to broadcast to channel ${channels[index]}:`, result.reason)
      }
    })
  }

  /**
   * Determine which Supabase channels should receive the broadcast
   */
  private static async determineBroadcastChannels(data: TaskOperationData): Promise<string[]> {
    const channels: string[] = []
    
    // Project-based channel for task operations
    const projectChannelId = `project_${data.projectId}_tasks`
    channels.push(projectChannelId)
    
    // Department-based channel (if exists)
    if (data.departmentId) {
      const deptChannelId = `department_${data.departmentId}_tasks`
      channels.push(deptChannelId)
    }
    
    // Global task operations channel (for admin/managers)
    channels.push('global_task_operations')
    
    return channels
  }

  /**
   * Get task operations history from MongoDB
   */
  static async getTaskOperations(taskId: string, limit = 50): Promise<any[]> {
    return executeGenericDbQuery(async () => {
      return await TaskOperation
        .find({ taskId })
        .sort({ createdAt: -1 })
        .limit(limit)
        .populate('userId', 'name avatar')
        .lean()
    }, `task-operations-${taskId}-${limit}`, 60000) // Cache for 1 minute
  }

  /**
   * Get project task operations history
   */
  static async getProjectTaskOperations(projectId: string, limit = 100): Promise<any[]> {
    return executeGenericDbQuery(async () => {
      return await TaskOperation
        .find({ projectId })
        .sort({ createdAt: -1 })
        .limit(limit)
        .populate('userId', 'name avatar')
        .populate('taskId', 'title status')
        .lean()
    }, `project-task-operations-${projectId}-${limit}`, 120000) // Cache for 2 minutes
  }

  /**
   * Get department task operations history
   */
  static async getDepartmentTaskOperations(departmentId: string, limit = 100): Promise<any[]> {
    return executeGenericDbQuery(async () => {
      return await TaskOperation
        .find({ departmentId })
        .sort({ createdAt: -1 })
        .limit(limit)
        .populate('userId', 'name avatar')
        .populate('taskId', 'title status')
        .lean()
    }, `department-task-operations-${departmentId}-${limit}`, 120000) // Cache for 2 minutes
  }

  /**
   * Get failed broadcast operations for retry
   */
  static async getFailedOperations(limit = 50): Promise<any[]> {
    return executeGenericDbQuery(async () => {
      return await TaskOperation
        .find({ broadcastStatus: 'failed' })
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean()
    })
  }

  /**
   * Retry failed broadcast operations
   */
  static async retryFailedOperations(): Promise<void> {
    try {
      const failedOps = await this.getFailedOperations()
      
      for (const operation of failedOps) {
        try {
          await this.broadcastTaskOperation({
            taskId: operation.taskId,
            projectId: operation.projectId,
            departmentId: operation.departmentId,
            operationType: operation.operationType,
            oldData: operation.oldData,
            newData: operation.newData,
            userId: operation.userId,
            userName: operation.userName,
            broadcastChannels: operation.broadcastChannels
          })
          
          // Update status to sent
          await executeGenericDbQuery(async () => {
            return await TaskOperation.findByIdAndUpdate(
              operation._id,
              { broadcastStatus: 'sent' }
            )
          })
          
          console.log(`Retried failed operation: ${operation._id}`)
        } catch (error) {
          console.error(`Failed to retry operation ${operation._id}:`, error)
        }
      }
    } catch (error) {
      console.error('Failed to retry failed operations:', error)
    }
  }

  /**
   * Enhanced drag-and-drop with realtime updates (no jerking)
   */
  static async handleDragAndDrop(data: {
    taskId: string
    oldStatus: string
    newStatus: string
    oldOrder?: number
    newOrder?: number
    projectId: string
    departmentId?: string
    userId: string
    userName: string
  }): Promise<void> {
    try {
      // Immediately broadcast optimistic update for smooth UX
      await this.broadcastTaskOperation({
        taskId: data.taskId,
        projectId: data.projectId,
        departmentId: data.departmentId,
        operationType: 'status_change',
        oldData: { status: data.oldStatus, order: data.oldOrder },
        newData: { status: data.newStatus, order: data.newOrder },
        userId: data.userId,
        userName: data.userName,
        broadcastChannels: await this.determineBroadcastChannels({
          taskId: data.taskId,
          projectId: data.projectId,
          departmentId: data.departmentId,
          operationType: 'status_change',
          newData: { status: data.newStatus },
          userId: data.userId,
          userName: data.userName
        })
      })

      // Then record the operation in MongoDB
      await this.recordTaskOperation({
        taskId: data.taskId,
        projectId: data.projectId,
        departmentId: data.departmentId,
        operationType: 'status_change',
        oldData: { status: data.oldStatus, order: data.oldOrder },
        newData: { status: data.newStatus, order: data.newOrder },
        userId: data.userId,
        userName: data.userName
      })

    } catch (error) {
      console.error('Failed to handle drag and drop:', error)
      
      // Broadcast revert operation if failed
      await this.broadcastTaskOperation({
        taskId: data.taskId,
        projectId: data.projectId,
        departmentId: data.departmentId,
        operationType: 'revert_status_change',
        oldData: { status: data.newStatus },
        newData: { status: data.oldStatus, order: data.oldOrder },
        userId: data.userId,
        userName: data.userName
      })
      
      throw error
    }
  }

  /**
   * Handle task assignment with notifications
   */
  static async handleTaskAssignment(data: {
    taskId: string
    oldAssigneeId?: string
    newAssigneeId?: string
    assignerId: string
    assignerName: string
    projectId: string
    departmentId?: string
    taskTitle: string
  }): Promise<void> {
    try {
      // Record task operation
      await this.recordTaskOperation({
        taskId: data.taskId,
        projectId: data.projectId,
        departmentId: data.departmentId,
        operationType: 'assign',
        oldData: { assigneeId: data.oldAssigneeId },
        newData: { assigneeId: data.newAssigneeId },
        userId: data.assignerId,
        userName: data.assignerName
      })

      // Send notification to new assignee
      if (data.newAssigneeId && data.newAssigneeId !== data.assignerId) {
        const { NotificationService } = await import('./notification-service')
        await NotificationService.notifyTaskAssigned(
          data.taskId,
          data.assignerId,
          data.newAssigneeId
        )
      }

      // If reassignment, notify old assignee about removal
      if (data.oldAssigneeId && data.oldAssigneeId !== data.assignerId && data.oldAssigneeId !== data.newAssigneeId) {
        const { NotificationService } = await import('./notification-service')
        await NotificationService.createNotification({
          type: 'task_assigned', // Reuse type but with different message
          category: 'task',
          recipientId: data.oldAssigneeId,
          senderId: data.assignerId,
          senderName: data.assignerName,
          title: 'Task Reassigned',
          message: `Task "${data.taskTitle}" has been reassigned to someone else`,
          entityType: 'task',
          entityId: data.taskId,
          entityName: data.taskTitle,
          actionType: 'assigned',
          actionUrl: `/projects/${data.projectId}?task=${data.taskId}`,
          priority: 2
        })
      }

    } catch (error) {
      console.error('Failed to handle task assignment:', error)
      throw error
    }
  }


  static async cleanupOldOperations(daysOld = 30): Promise<void> {
    try {
      const cutoffDate = new Date(Date.now() - (daysOld * 24 * 60 * 60 * 1000))
      
      await executeGenericDbQuery(async () => {
        return await TaskOperation.deleteMany({
          createdAt: { $lt: cutoffDate }
        })
      })
      
      console.log(`Cleaned up task operations older than ${daysOld} days`)
    } catch (error) {
      console.error('Failed to cleanup old task operations:', error)
    }
  }
}
```

### 2.2 Enhanced Task Hook Integration

**File: `hooks/use-tasks-realtime.ts`** (extends existing `use-tasks.ts`)
```typescript
import { useAppDispatch } from '@/hooks/redux'
import { useTasks } from '@/hooks/use-tasks'
import { getRealtimeManager } from '@/lib/realtime-manager'
import { TaskOperationsService } from '@/lib/services/task-operations-service'
import { useCallback, useEffect, useRef } from 'react'
import { useToast } from '@/hooks/use-toast'

export function useTasksRealtime(projectId?: string, departmentId?: string) {
  const dispatch = useAppDispatch()
  const { toast } = useToast()
  const tasksHook = useTasks() // Original hook
  const realtimeManager = getRealtimeManager()
  const subscribedChannelsRef = useRef<Set<string>>(new Set())

  // Handle realtime task operations with optimistic updates
  const handleTaskOperation = useCallback((payload: any) => {
    const { operation_type, task_id, new_data, old_data, user_name, user_id } = payload
    const currentUserId = (session?.user as any)?.id
    
    switch (operation_type) {
      case 'create':
        // Add task to local state
        tasksHook.addTaskToLocal(new_data)
        if (user_id !== currentUserId) {
          toast({
            title: 'New Task Created',
            description: `${user_name} created: "${new_data.title}"`,
            variant: 'default'
          })
        }
        break
        
      case 'update':
      case 'status_change':
        // Update task in local state immediately (optimistic)
        tasksHook.updateTaskInLocal(task_id, new_data)
        break
        
      case 'revert_status_change':
        // Revert failed drag operation
        tasksHook.updateTaskInLocal(task_id, new_data)
        if (user_id === currentUserId) {
          toast({
            title: 'Update Failed',
            description: 'Task status update failed and was reverted',
            variant: 'destructive'
          })
        }
        break
        
      case 'priority_change':
        // Update task priority
        tasksHook.updateTaskInLocal(task_id, new_data)
        if (user_id !== currentUserId) {
          toast({
            title: 'Priority Updated',
            description: `${user_name} changed task priority`,
            variant: 'default'
          })
        }
        break
        
      case 'assign':
        // Handle assignment with notification
        tasksHook.updateTaskInLocal(task_id, new_data)
        if (user_id !== currentUserId) {
          const wasAssignedToMe = new_data.assigneeId === currentUserId
          const wasUnassignedFromMe = old_data.assigneeId === currentUserId && !new_data.assigneeId
          
          if (wasAssignedToMe) {
            toast({
              title: 'Task Assigned to You',
              description: `${user_name} assigned you a task`,
              variant: 'default'
            })
          } else if (wasUnassignedFromMe) {
            toast({
              title: 'Task Unassigned',
              description: `${user_name} unassigned you from a task`,
              variant: 'default'
            })
          }
        }
        break
        
      case 'delete':
        // Remove task from local state
        tasksHook.removeTaskFromLocal(task_id)
        if (user_id !== currentUserId) {
          toast({
            title: 'Task Deleted',
            description: `${user_name} deleted a task`,
            variant: 'default'
          })
        }
        break
    }
  }, [tasksHook, toast, session?.user])

  // Enhanced drag and drop handler with realtime updates
  const handleDragAndDropRealtime = useCallback(async (data: {
    taskId: string
    oldStatus: string
    newStatus: string
    oldOrder?: number
    newOrder?: number
  }) => {
    const currentUserId = (session?.user as any)?.id
    const currentUserName = (session?.user as any)?.name
    
    if (!currentUserId || !currentUserName) {
      throw new Error('User not authenticated')
    }

    try {
      // First, optimistically update local state for immediate feedback
      const task = tasksHook.tasks.find(t => t.id === data.taskId)
      if (task) {
        const optimisticTask = {
          ...task,
          status: data.newStatus,
          order: data.newOrder || task.order
        }
        tasksHook.updateTaskInLocal(data.taskId, optimisticTask)
      }

      // Then handle the realtime update and database persistence
      await TaskOperationsService.handleDragAndDrop({
        taskId: data.taskId,
        oldStatus: data.oldStatus,
        newStatus: data.newStatus,
        oldOrder: data.oldOrder,
        newOrder: data.newOrder,
        projectId: projectId!,
        departmentId: departmentId,
        userId: currentUserId,
        userName: currentUserName
      })
      
    } catch (error) {
      // Revert local state on error
      const task = tasksHook.tasks.find(t => t.id === data.taskId)
      if (task) {
        tasksHook.updateTaskInLocal(data.taskId, {
          ...task,
          status: data.oldStatus,
          order: data.oldOrder || task.order
        })
      }
      
      console.error('Failed to handle drag and drop:', error)
      toast({
        title: 'Update Failed',
        description: 'Failed to update task status',
        variant: 'destructive'
      })
      throw error
    }
  }, [tasksHook, projectId, departmentId, session?.user, toast])

  // Enhanced assignment handler with notifications
  const assignTaskRealtime = useCallback(async (taskId: string, assigneeId: string) => {
    const currentUserId = (session?.user as any)?.id
    const currentUserName = (session?.user as any)?.name
    
    if (!currentUserId || !currentUserName) {
      throw new Error('User not authenticated')
    }

    try {
      const task = tasksHook.tasks.find(t => t.id === taskId)
      if (!task) {
        throw new Error('Task not found')
      }

      const oldAssigneeId = task.assigneeId
      
      // Optimistically update local state
      tasksHook.updateTaskInLocal(taskId, {
        ...task,
        assigneeId: assigneeId || undefined
      })

      // Handle assignment with notifications
      await TaskOperationsService.handleTaskAssignment({
        taskId,
        oldAssigneeId,
        newAssigneeId: assigneeId || undefined,
        assignerId: currentUserId,
        assignerName: currentUserName,
        projectId: task.projectId,
        departmentId: task.departmentId,
        taskTitle: task.title
      })
      
      return task
    } catch (error) {
      console.error('Failed to assign task with realtime:', error)
      throw error
    }
  }, [tasksHook, session?.user])

  // Subscribe to realtime task operations
  const subscribeToTaskOperations = useCallback(async (channels: string[]) => {
    for (const channelId of channels) {
      if (!subscribedChannelsRef.current.has(channelId)) {
        await realtimeManager.subscribeToChannel(channelId, {
          onTaskOperation: handleTaskOperation
        })
        subscribedChannelsRef.current.add(channelId)
      }
    }
  }, [realtimeManager, handleTaskOperation])

  // Enhanced task operations with realtime broadcasting
  const createTaskRealtime = useCallback(async (taskData: any) => {
    try {
      // Create task via original hook (MongoDB)
      const newTask = await tasksHook.createTask(taskData)
      
      // Record and broadcast operation
      await TaskOperationsService.recordTaskOperation({
        taskId: newTask.id,
        projectId: newTask.projectId,
        departmentId: newTask.departmentId,
        operationType: 'create',
        newData: newTask,
        userId: newTask.createdBy,
        userName: newTask.createdByName
      })
      
      return newTask
    } catch (error) {
      console.error('Failed to create task with realtime:', error)
      throw error
    }
  }, [tasksHook])

  const updateTaskRealtime = useCallback(async (taskId: string, updates: any) => {
    try {
      const oldTask = tasksHook.tasks.find(t => t.id === taskId)
      const updatedTask = await tasksHook.updateTask(taskId, updates)
      
      // Determine operation type
      let operationType = 'update'
      if (updates.status && updates.status !== oldTask?.status) {
        operationType = 'status_change'
      } else if (updates.priority && updates.priority !== oldTask?.priority) {
        operationType = 'priority_change'
      } else if (updates.assigneeId && updates.assigneeId !== oldTask?.assigneeId) {
        operationType = 'assign'
      }
      
      // Record and broadcast operation
      await TaskOperationsService.recordTaskOperation({
        taskId,
        projectId: updatedTask.projectId,
        departmentId: updatedTask.departmentId,
        operationType: operationType as any,
        oldData: oldTask,
        newData: updatedTask,
        userId: updates.updatedBy,
        userName: updates.updatedByName
      })
      
      return updatedTask
    } catch (error) {
      console.error('Failed to update task with realtime:', error)
      throw error
    }
  }, [tasksHook])

  // Setup subscriptions based on context
  useEffect(() => {
    const channels: string[] = []
    
    if (projectId) {
      channels.push(`project_${projectId}_tasks`)
    }
    
    if (departmentId) {
      channels.push(`department_${departmentId}_tasks`)
    }
    
    if (channels.length > 0) {
      subscribeToTaskOperations(channels)
    }
    
    // Cleanup on unmount
    return () => {
      subscribedChannelsRef.current.forEach(channelId => {
        realtimeManager.unsubscribeFromChannel(channelId)
      })
      subscribedChannelsRef.current.clear()
    }
  }, [projectId, departmentId, subscribeToTaskOperations])

  return {
    ...tasksHook,
    createTaskRealtime,
    updateTaskRealtime,
    assignTaskRealtime,
    handleDragAndDropRealtime,
    subscribeToTaskOperations
  }
}
```

### 2.4 Task Assignment Integration

**File: `components/projects/TaskModal.tsx`** (existing, update assignment handler)
```typescript
// Add import for realtime assignment
import { useTasksRealtime } from '@/hooks/use-tasks-realtime'

export function TaskModal({ /* existing props */ }) {
  // ... existing code
  
  // Use realtime tasks hook instead of regular one
  const { assignTaskRealtime } = useTasksRealtime(projectId, departmentId)
  
  // Update the assignment handler in handleSubmit function
  const handleSubmit = async (data: CreateTaskFormData) => {
    // ... existing code for create and edit modes
    
    } else if (mode === 'assign' && task) {
      if (data.assigneeId && data.assigneeId !== 'unassigned' && data.assigneeId !== task.assigneeId) {
        // Use realtime assignment with notifications
        await assignTaskRealtime(task._id!, data.assigneeId)
        
        const assigneeName = departmentUsers.find(u => u._id === data.assigneeId)?.name || 'Unknown'
        toast({
          title: "Task Assigned",
          description: `Task "${task.title}" has been assigned to ${assigneeName}. They will receive a notification.`,
        })
      } else if (data.assigneeId === 'unassigned' && task.assigneeId) {
        // Use realtime unassignment
        await assignTaskRealtime(task._id!, "")
        toast({
          title: "Task Unassigned",
          description: `Task "${task.title}" has been unassigned.`,
        })
      }
    }
    
    // ... rest of existing code
  }
  
  // ... rest of component
}
```

**File: `components/projects/TaskDataViews.tsx`** (existing, update inline assignment)
```typescript
// In the DraggableTask component, update the assignment handler
const handleAssigneeChange = useCallback(async (newAssigneeId: string) => {
  if (onAssigneeChange) {
    try {
      await onAssigneeChange(task._id, newAssigneeId)
      // Success feedback is handled in the parent component
    } catch (error) {
      console.error('Assignment failed:', error)
      // Error feedback is handled in the parent component
    }
  }
}, [task._id, onAssigneeChange])

// Use the handler in the assignee select component
<SearchableSelect
  options={assigneeOptions}
  value={task.assigneeId || 'unassigned'}
  onValueChange={handleAssigneeChange}
  placeholder="Assign to..."
  disabled={usersLoading || isActionLoadingForTask?.(task._id)}
/>
```

**File: `components/projects/TaskBoardRealtime.tsx`** (extends `TaskDataViews.tsx`)
```typescript
"use client"
import { useCallback, useEffect, useState, useMemo } from 'react'
import { DndContext, DragEndEvent, DragStartEvent, DragOverlay } from '@dnd-kit/core'
import { TaskBoardView } from './TaskDataViews'
import { useTasksRealtime } from '@/hooks/use-tasks-realtime'
import { useToast } from '@/hooks/use-toast'
import { useSession } from 'next-auth/react'

interface TaskBoardRealtimeProps {
  departmentId: string
  departmentName: string
  projectId?: string
  // ... other props from TaskBoardView
}

export const TaskBoardRealtime = ({
  departmentId,
  departmentName,
  projectId,
  ...props
}: TaskBoardRealtimeProps) => {
  const { toast } = useToast()
  const { data: session } = useSession()
  const [isDragging, setIsDragging] = useState(false)
  const [draggedTask, setDraggedTask] = useState<any>(null)
  const [optimisticUpdates, setOptimisticUpdates] = useState<Record<string, any>>({})
  
  // Use realtime-enabled tasks hook
  const {
    tasks,
    updateTaskRealtime,
    createTaskRealtime,
    assignTaskRealtime,
    handleDragAndDropRealtime,
    loading,
    error
  } = useTasksRealtime(projectId, departmentId)

  // Merge tasks with optimistic updates for smooth UI
  const tasksWithOptimisticUpdates = useMemo(() => {
    return tasks.map(task => ({
      ...task,
      ...(optimisticUpdates[task.id] || {})
    }))
  }, [tasks, optimisticUpdates])

  // Clear optimistic update after a delay (in case realtime update doesn't come)
  const clearOptimisticUpdate = useCallback((taskId: string, delay = 3000) => {
    setTimeout(() => {
      setOptimisticUpdates(prev => {
        const { [taskId]: _, ...rest } = prev
        return rest
      })
    }, delay)
  }, [])

  // Handle drag start with immediate visual feedback
  const handleDragStart = useCallback((event: DragStartEvent) => {
    const { active } = event
    const task = tasks.find(t => t.id === active.id)
    
    if (task) {
      setDraggedTask(task)
      setIsDragging(true)
      
      // Optional: Show dragging indicator to other users
      // This could broadcast that user is dragging a task
    }
  }, [tasks])

  // Handle drag end with optimistic updates and realtime sync
  const handleDragEnd = useCallback(async (event: DragEndEvent) => {
    const { active, over } = event
    
    setIsDragging(false)
    setDraggedTask(null)
    
    if (!over || active.id === over.id) {
      return
    }

    const taskId = active.id as string
    const newStatus = over.id as string
    
    const task = tasks.find(t => t.id === taskId)
    if (!task || task.status === newStatus) {
      return
    }

    const oldStatus = task.status
    const oldOrder = task.order
    
    // Calculate new order based on drop position
    const tasksInNewStatus = tasks.filter(t => t.status === newStatus)
    const newOrder = tasksInNewStatus.length + 1

    try {
      // Apply optimistic update immediately for smooth UX
      setOptimisticUpdates(prev => ({
        ...prev,
        [taskId]: {
          status: newStatus,
          order: newOrder,
          updatedAt: new Date().toISOString()
        }
      }))
      
      // Clear optimistic update after delay
      clearOptimisticUpdate(taskId)
      
      // Perform realtime update (this will broadcast to other users)
      await handleDragAndDropRealtime({
        taskId,
        oldStatus,
        newStatus,
        oldOrder,
        newOrder
      })
      
      // Success feedback (optional, as the change should be visible)
      // toast({
      //   title: 'Task Updated',
      //   description: `Task moved to ${newStatus}`,
      //   variant: 'default',
      //   duration: 2000
      // })
      
    } catch (error) {
      console.error('Failed to update task status:', error)
      
      // Remove optimistic update immediately on error
      setOptimisticUpdates(prev => {
        const { [taskId]: _, ...rest } = prev
        return rest
      })
      
      toast({
        title: 'Update Failed',
        description: 'Failed to update task status. Please try again.',
        variant: 'destructive'
      })
    }
  }, [tasks, handleDragAndDropRealtime, toast, clearOptimisticUpdate])

  // Handle task assignment with realtime notifications
  const handleTaskAssignment = useCallback(async (taskId: string, assigneeId: string) => {
    try {
      await assignTaskRealtime(taskId, assigneeId)
      
      const assigneeName = assigneeId ? 
        'User' : // You can get actual user name from users list
        'Unassigned'
      
      toast({
        title: 'Task Assigned',
        description: `Task ${assigneeId ? 'assigned to ' + assigneeName : 'unassigned'}`,
        variant: 'default'
      })
      
    } catch (error) {
      console.error('Failed to assign task:', error)
      toast({
        title: 'Assignment Failed',
        description: 'Failed to assign task. Please try again.',
        variant: 'destructive'
      })
    }
  }, [assignTaskRealtime, toast])

  return (
    <TaskBoardView
      {...props}
      departmentId={departmentId}
      departmentName={departmentName}
      departmentTasks={tasksWithOptimisticUpdates}
      draggingTask={draggedTask}
      isLoading={loading}
      onHandleDragStart={handleDragStart}
      onHandleDragEnd={handleDragEnd}
      onAssigneeChange={handleTaskAssignment}
      // Pass through other handlers
      onStatusChange={async (taskId, newStatus) => {
        // This handles programmatic status changes (not drag-and-drop)
        try {
          await updateTaskRealtime(taskId, {
            status: newStatus,
            updatedBy: (session?.user as any)?.id,
            updatedByName: (session?.user as any)?.name
          })
        } catch (error) {
          console.error('Failed to update task status:', error)
          toast({
            title: 'Update Failed',
            description: 'Failed to update task status',
            variant: 'destructive'
          })
        }
      }}
      onPriorityChange={async (taskId, newPriority) => {
        try {
          await updateTaskRealtime(taskId, {
            priority: newPriority,
            updatedBy: (session?.user as any)?.id,
            updatedByName: (session?.user as any)?.name
          })
        } catch (error) {
          console.error('Failed to update task priority:', error)
          toast({
            title: 'Update Failed',
            description: 'Failed to update task priority',
            variant: 'destructive'
          })
        }
      }}
    />
  )
}
```

## 🎯 Phase 3: API Route Updates

### 3.1 Enhanced Project Routes

**File: `app/api/projects/route.ts`** (existing, update to include notifications)
```typescript
import { NextRequest, NextResponse } from 'next/server'
import { NotificationService } from '@/lib/services/notification-service'
// ... existing imports

export async function POST(request: NextRequest) {
  try {
    // ... existing project creation logic
    const newProject = await Project.create(projectData)
    
    // Send notifications to department heads
    await NotificationService.notifyProjectCreated(
      newProject._id.toString(),
      session.user.id
    )
    
    return NextResponse.json(newProject)
  } catch (error) {
    // ... error handling
  }
}

export async function PATCH(request: NextRequest) {
  try {
    // ... existing project update logic
    
    // If project was approved, send notification
    if (updates.status === 'approved' && oldProject.status !== 'approved') {
      await NotificationService.notifyProjectApproved(
        projectId,
        session.user.id
      )
    }
    
    return NextResponse.json(updatedProject)
  } catch (error) {
    // ... error handling
  }
}
```

### 3.2 Enhanced Task Routes

**File: `app/api/tasks/route.ts`** (existing, update to include realtime)
```typescript
import { NextRequest, NextResponse } from 'next/server'
import { TaskOperationsService } from '@/lib/services/task-operations-service'
import { NotificationService } from '@/lib/services/notification-service'
// ... existing imports

export async function POST(request: NextRequest) {
  try {
    // ... existing task creation logic
    const newTask = await Task.create(taskData)
    
    // Record realtime operation
    await TaskOperationsService.recordTaskOperation({
      taskId: newTask._id.toString(),
      projectId: newTask.projectId,
      departmentId: newTask.departmentId,
      operationType: 'create',
      newData: newTask,
      userId: session.user.id,
      userName: session.user.name
    })
    
    // Send assignment notification if task is assigned
    if (newTask.assigneeId && newTask.assigneeId !== session.user.id) {
      await NotificationService.notifyTaskAssigned(
        newTask._id.toString(),
        session.user.id,
        newTask.assigneeId
      )
    }
    
    return NextResponse.json(newTask)
  } catch (error) {
    // ... error handling
  }
}

export async function PATCH(request: NextRequest) {
  try {
    // ... existing task update logic
    
    // Record realtime operation
    await TaskOperationsService.recordTaskOperation({
      taskId: taskId,
      projectId: updatedTask.projectId,
      departmentId: updatedTask.departmentId,
      operationType: this.determineOperationType(oldTask, updates),
      oldData: oldTask,
      newData: updatedTask,
      userId: session.user.id,
      userName: session.user.name
    })
    
    // Handle assignment notifications
    if (updates.assigneeId && updates.assigneeId !== oldTask.assigneeId) {
      await NotificationService.notifyTaskAssigned(
        taskId,
        session.user.id,
        updates.assigneeId
      )
    }
    
    return NextResponse.json(updatedTask)
  } catch (error) {
    // ... error handling
  }
}
```

### 3.3 New System Notification Routes

**File: `app/api/system-notifications/route.ts`**
```typescript
import { NextRequest, NextResponse } from 'next/server'
import { executeGenericDbQuery, clearCache } from '@/lib/mongodb'
import SystemNotification from '@/models/SystemNotification'
import { auth } from '@/lib/auth-config'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { notificationQuerySchema, markAsReadSchema } from '@/lib/validations/system-notification'
import { createErrorResponse, createSuccessResponse } from '@/lib/utils/response-helpers'

export async function GET(request: NextRequest) {
  try {
    const session = await auth()
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const limit = parseInt(searchParams.get('limit') || '50')
    const offset = parseInt(searchParams.get('offset') || '0')
    const unreadOnly = searchParams.get('unreadOnly') === 'true'

    const notifications = await executeGenericDbQuery(async () => {
      const query: any = { recipientId: session.user.id }
      
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
    }, `system-notifications-${session.user.id}-${limit}-${offset}-${unreadOnly}`, 30000)

    const unreadCount = await executeGenericDbQuery(async () => {
      return await SystemNotification.countDocuments({
        recipientId: session.user.id,
        isRead: false
      })
    }, `unread-system-notifications-${session.user.id}`, 10000)

    return NextResponse.json({
      success: true,
      notifications,
      unreadCount,
      pagination: {
        limit,
        offset,
        hasMore: notifications.length === limit
      }
    })
  } catch (error) {
    console.error('Failed to fetch system notifications:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to fetch notifications' },
      { status: 500 }
    )
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const session = await auth()
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const { notificationIds, markAllAsRead } = body

    if (markAllAsRead) {
      // Mark all notifications as read for the user
      await executeGenericDbQuery(async () => {
        return await SystemNotification.updateMany(
          {
            recipientId: session.user.id,
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
    } else if (notificationIds && Array.isArray(notificationIds)) {
      // Mark specific notifications as read
      await executeGenericDbQuery(async () => {
        return await SystemNotification.updateMany(
          {
            _id: { $in: notificationIds },
            recipientId: session.user.id
          },
          {
            $set: {
              isRead: true,
              readAt: new Date()
            }
          }
        )
      })
    } else {
      return NextResponse.json(
        { success: false, error: 'Invalid request body' },
        { status: 400 }
      )
    }

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to update system notifications:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to update notifications' },
      { status: 500 }
    )
  }
}

// DELETE endpoint to remove old notifications
export async function DELETE(request: NextRequest) {
  try {
    const session = await auth()
    if (!session?.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const olderThanDays = parseInt(searchParams.get('olderThanDays') || '30')
    
    const cutoffDate = new Date(Date.now() - (olderThanDays * 24 * 60 * 60 * 1000))
    
    const result = await executeGenericDbQuery(async () => {
      return await SystemNotification.deleteMany({
        recipientId: session.user.id,
        isRead: true,
        createdAt: { $lt: cutoffDate }
      })
    })

    return NextResponse.json({
      success: true,
      deletedCount: result.deletedCount
    })
  } catch (error) {
    console.error('Failed to delete old notifications:', error)
    return NextResponse.json(
      { success: false, error: 'Failed to delete notifications' },
      { status: 500 }
    )
  }
}
```

## 🎯 Phase 4: Integration & UI Updates

### 4.1 Header Component Update

**File: `components/layout/header.tsx`** (existing, add system notifications)
```typescript
// Add import
import { SystemNotification } from '@/components/notifications/system-notification'

export const Header = memo(function Header() {
  // ... existing code
  
  return (
    <>
      <header className="flex h-16 items-center justify-between lg:justify-end border-b bg-sidebar/95 backdrop-blur-sm px-4 lg:px-6 shrink-0 sticky top-0 z-30">
        <div className="w-10 lg:hidden" />

        <div className="flex items-center justify-end space-x-2 lg:space-x-4">
          <ThemeToggle />
          
          {/* System Notifications */}
          <SystemNotification className="h-8 w-8 lg:h-9 lg:w-9" />
          
          {/* Message Notifications */}
          <MessageNotification className="h-8 w-8 lg:h-9 lg:w-9" />

          {/* ... rest of existing code */}
        </div>
      </header>
      {/* ... existing modals */}
    </>
  )
})
```

### 4.2 Project Page Integration

**File: `app/projects/page.tsx`** (existing, add realtime notifications)
```typescript
// Add import
import { useSystemNotifications } from '@/hooks/use-system-notifications'

export default function ProjectsPage() {
  // ... existing code
  
  // Add system notifications hook
  const { subscribeToNotifications } = useSystemNotifications()
  
  // Subscribe to project-related notifications
  useEffect(() => {
    subscribeToNotifications(['project'])
  }, [subscribeToNotifications])
  
  // ... rest of existing code
}
```

### 4.3 Task Board Integration

**File: `components/projects/ProjectCategorization.tsx`** (existing, use realtime version)
```typescript
// Replace TaskBoardView with TaskBoardRealtime
import { TaskBoardRealtime } from './TaskBoardRealtime'

// In the component, replace the board view usage:
{taskView === "board" && (
  <TaskBoardRealtime
    departmentId={departmentId}
    departmentName={departmentName}
    projectId={projectId}
    // ... other props
  />
)}
```

## 📋 Implementation Phases & Timeline

### Phase 1: Foundation (Week 1)
- [ ] Create Supabase tables (`system_notifications`, `task_operations`)
- [ ] Implement `NotificationService` class
- [ ] Create Redux slice for system notifications
- [ ] Develop `useSystemNotifications` hook
- [ ] Build basic `SystemNotification` component

### Phase 2: Task Operations (Week 2)  
- [ ] Implement `TaskOperationsService` class
- [ ] Create `useTasksRealtime` hook
- [ ] Extend realtime-manager for task operations
- [ ] Update existing task routes with realtime broadcasting
- [ ] Build `TaskBoardRealtime` component

### Phase 3: Integration (Week 3)
- [ ] Update project routes with notifications
- [ ] Create notification API routes
- [ ] Integrate system notifications in header
- [ ] Add realtime subscriptions to project pages
- [ ] Update task board components

### Phase 4: Testing & Polish (Week 4)
- [ ] End-to-end testing of notification flow
- [ ] Real-time task operation testing
- [ ] Performance optimization
- [ ] UI/UX refinements
- [ ] Documentation updates

## 🔧 Technical Considerations

### Performance Optimizations
1. **Debounced Realtime Updates**: Prevent excessive broadcasts for rapid operations
2. **Selective Broadcasting**: Only broadcast to relevant channels/users
3. **Smart Caching Strategy**: 
   - Notifications cached for 30 seconds (frequently changing)
   - Unread counts cached for 10 seconds (real-time requirement)
   - Task operations cached for 1-2 minutes (audit data)
4. **Optimistic UI Updates**: Immediate visual feedback with error rollback
5. **Background Processing**: Non-critical operations (logging, cleanup) run asynchronously
6. **Connection Pooling**: Reuse database connections via executeGenericDbQuery
7. **Batch Operations**: Group multiple notifications/operations when possible
8. **TTL Indexes**: Automatic cleanup of old records (30 days for operations, configurable for notifications)
9. **Efficient Queries**: 
   - Compound indexes on frequently queried fields
   - Lean queries for data serialization
   - Pagination for large result sets
10. **Memory Management**: Clear optimistic updates after 3 seconds to prevent memory leaks
3. **Efficient State Updates**: Use immer for immutable updates in Redux
4. **Cleanup Strategies**: Auto-remove old notifications and operations
5. **Connection Recovery**: Handle network disconnections gracefully

### Security Measures
1. **Permission Checks**: Verify user permissions before sending notifications
2. **Rate Limiting**: Prevent spam notifications
3. **Data Sanitization**: Clean notification content
4. **Channel Authorization**: Ensure users can only access relevant channels

### Monitoring & Logging
1. **Notification Delivery**: Track successful/failed notifications
2. **Real-time Performance**: Monitor broadcast latency
3. **Error Tracking**: Comprehensive error logging
4. **Usage Analytics**: Track notification engagement

## 🚀 Benefits

### For Users
- **Instant Updates**: Real-time feedback on task operations and project changes with **zero lag**
- **Smooth Drag & Drop**: Seamless task status updates without jerking or visual glitches
- **Smart Notifications**: Contextual notifications for task assignments with deep links
- **Optimistic Updates**: Immediate visual feedback while changes sync in the background
- **Better Awareness**: Know exactly when others are working on tasks with live updates
- **Improved Collaboration**: Real-time task assignments with instant notifications
- **Reduced Polling**: No need to refresh pages - everything updates automatically
- **Professional UX**: Enterprise-grade user experience with smooth animations and transitions

### For System Architecture
- **MongoDB-First**: All business data stored in MongoDB with proper relationships and validation
- **Optimistic UI**: Immediate visual feedback with automatic error handling and rollback
- **Scalable Realtime**: Leverages existing Supabase infrastructure for efficient broadcasting
- **Error Resilient**: Automatic retry mechanisms and graceful error handling
- **Maintainable Code**: Generic services that work across all modules
- **Performance**: Efficient real-time updates without overloading MongoDB
- **Data Consistency**: Single source of truth in MongoDB with optimized caching
- **Future-Ready**: Foundation for additional real-time features
- **Professional Logging**: Centralized error handling and user feedback

### Technical Advantages
- **Hybrid Architecture**: Best of both worlds - MongoDB for data integrity, Supabase for real-time
- **Zero-Lag Experience**: Optimistic updates with automatic fallback on errors
- **Generic Implementation**: Services can be extended for other modules (leads, clients, departments)
- **Efficient Caching**: Smart caching with `executeGenericDbQuery` reduces database load
- **Type Safety**: Full TypeScript support throughout the stack
- **Error Handling**: Comprehensive error management with user-friendly messages
- **Audit Trail**: Complete tracking of task operations and notifications
- **Smooth Animations**: Professional drag-and-drop with visual feedback
- **Smart Broadcasting**: Efficient realtime updates only to relevant users

## � Implementation Guidelines for Smooth Realtime Experience

### 1. Drag & Drop Best Practices
```typescript
// Always use optimistic updates for immediate feedback
const handleDragEnd = async (event: DragEndEvent) => {
  // 1. Apply optimistic update immediately
  setOptimisticUpdates(prev => ({ ...prev, [taskId]: newState }))
  
  // 2. Broadcast to other users via Supabase
  await broadcastTaskOperation({ /* realtime data */ })
  
  // 3. Persist to MongoDB in background
  await recordTaskOperation({ /* database data */ })
  
  // 4. Auto-cleanup optimistic update after delay
  setTimeout(() => clearOptimisticUpdate(taskId), 3000)
}
```

### 2. Error Handling Pattern
```typescript
try {
  // Optimistic update
  updateUIImmediately()
  
  // Realtime broadcast
  await broadcastChange()
  
  // Database persistence
  await saveToMongoDB()
} catch (error) {
  // Revert optimistic update
  revertUIChange()
  
  // Show user-friendly error
  toast({ title: 'Update failed', variant: 'destructive' })
  
  // Log for debugging
  console.error('Operation failed:', error)
}
```

### 3. Notification Timing
- **Immediate**: UI updates (drag & drop, status changes)
- **Fast (< 500ms)**: Task assignments, priority changes
- **Normal (1-2s)**: Project approvals, complex operations
- **Background**: Audit logging, cleanup operations

### 4. Performance Optimizations
- Use `useMemo` for expensive calculations
- Implement optimistic updates for all user actions
- Batch multiple operations when possible
- Clean up subscriptions on component unmount
- Use proper TypeScript types for better performance

### 5. User Experience Guidelines
- Show loading states only for operations > 1 second
- Use subtle animations for state transitions
- Provide clear feedback for all user actions
- Handle network failures gracefully
- Implement proper accessibility features



## 🛠️ Missing Components & Integrations

### Additional Files Needed

**File: `lib/utils/response-helpers.ts`** (if not exists)
```typescript
import { NextResponse } from 'next/server'

export function createSuccessResponse(data: any, message?: string) {
  return NextResponse.json({
    success: true,
    data,
    message
  })
}

export function createErrorResponse(message: string, status = 500, details?: any) {
  return NextResponse.json(
    {
      success: false,
      error: message,
      details
    },
    { status }
  )
}
```

**File: `scripts/cleanup-notifications.ts`** (Cron job)
```typescript
import { NotificationService } from '@/lib/services/notification-service'
import { TaskOperationsService } from '@/lib/services/task-operations-service'

// Run daily cleanup
export async function runNotificationCleanup() {
  try {
    console.log('🧹 Starting notification cleanup...')
    
    // Cleanup expired notifications
    await NotificationService.cleanupExpiredNotifications()
    
    // Cleanup old task operations (older than 30 days)
    await TaskOperationsService.cleanupOldOperations(30)
    
    // Retry failed broadcast operations
    await TaskOperationsService.retryFailedOperations()
    
    console.log('✅ Notification cleanup completed')
  } catch (error) {
    console.error('❌ Notification cleanup failed:', error)
  }
}
```

**File: `components/notifications/NotificationToast.tsx`**
```typescript
"use client"
import { useEffect } from 'react'
import { useToast } from '@/hooks/use-toast'
import { useSystemNotifications } from '@/hooks/use-system-notifications'

export function NotificationToast() {
  const { toast } = useToast()
  const { notifications } = useSystemNotifications()

  // Show toast for new notifications
  useEffect(() => {
    const latestNotification = notifications[0]
    if (latestNotification && !latestNotification.isRead) {
      toast({
        title: latestNotification.title,
        description: latestNotification.message,
        variant: latestNotification.priority >= 3 ? 'destructive' : 'default',
        duration: latestNotification.priority >= 3 ? 8000 : 5000
      })
    }
  }, [notifications, toast])

  return null
}
```

### Database Strategy
```
📊 MONGODB (Primary Database)
├── SystemNotification model - All notification data
├── TaskOperation model - Task operation history
├── User, Project, Task models - Business entities
├── Relationships & validation - Data integrity
└── executeGenericDbQuery - Caching & performance

🔄 SUPABASE (Realtime Only)
├── User notification channels - Real-time delivery
├── Task operation channels - Live updates
├── Broadcasting service - Message distribution
└── Connection management - Presence & typing

⚡ REALTIME FLOW
1. Action occurs (task created, project approved)
2. Data validated with Zod schemas
3. Data saved to MongoDB (business logic + executeGenericDbQuery)
4. Cache invalidated (pattern-based clearing)
5. Broadcast sent via Supabase (real-time)
6. Frontend receives update (instant UI)
7. State updated in Redux (consistent state)
8. Optimistic updates handled (immediate feedback)
```

### Key Design Principles
1. **MongoDB First**: All business logic and data storage in MongoDB
2. **Supabase for Broadcasting**: Only use Supabase for real-time message delivery
3. **Generic Services**: Reusable across all modules (projects, tasks, departments)
4. **Type Safety**: Full TypeScript implementation
5. **Error Handling**: Comprehensive error management with user feedback
6. **Caching Strategy**: Smart caching to reduce database load
7. **Audit Trail**: Complete tracking of all operations

### Integration with Current App
- ✅ Uses existing `executeGenericDbQuery` pattern
- ✅ Follows current CRUD implementation guidelines
- ✅ Integrates with existing authentication and permissions
- ✅ Uses current error handling and toast patterns
- ✅ Leverages existing Supabase realtime infrastructure
- ✅ Maintains MongoDB as single source of truth
- ✅ Compatible with existing Redux store patterns

## 🧪 Testing Strategy

### Unit Tests
```typescript
// tests/services/notification-service.test.ts
import { NotificationService } from '@/lib/services/notification-service'
import { createSystemNotificationSchema } from '@/lib/validations/system-notification'

describe('NotificationService', () => {
  test('creates valid notification', async () => {
    const payload = {
      type: 'task_assigned',
      category: 'task',
      recipientId: '507f1f77bcf86cd799439011',
      senderId: '507f1f77bcf86cd799439012',
      senderName: 'John Doe',
      title: 'Task Assigned',
      message: 'You have a new task',
      entityType: 'task',
      entityId: '507f1f77bcf86cd799439013',
      actionType: 'assigned'
    }
    
    await expect(NotificationService.createNotification(payload)).resolves.toBeUndefined()
  })
  
  test('validates notification payload', () => {
    const invalidPayload = { title: 'Invalid' }
    
    expect(() => createSystemNotificationSchema.parse(invalidPayload)).toThrow()
  })
})
```

### Integration Tests
- Test realtime broadcasting end-to-end
- Verify database operations with executeGenericDbQuery
- Test cache invalidation patterns
- Validate drag-and-drop optimistic updates

### Performance Tests
- Load test with 100+ concurrent notifications
- Measure broadcast latency
- Test cache effectiveness
- Monitor memory usage with optimistic updates

## 🚀 Deployment Checklist

### Environment Variables
```bash
# Add to .env.local
SUPABASE_REALTIME_URL=your_supabase_url
SUPABASE_SERVICE_KEY=your_service_key
MONGODB_NOTIFICATION_CLEANUP_ENABLED=true
NOTIFICATION_BROADCAST_TIMEOUT=5000
```

### Database Indexes
```javascript
// Run in MongoDB console
db.systemnotifications.createIndex({ "recipientId": 1, "isRead": 1, "createdAt": -1 })
db.systemnotifications.createIndex({ "expiresAt": 1 }, { "expireAfterSeconds": 0 })
db.taskoperations.createIndex({ "taskId": 1, "createdAt": -1 })
db.taskoperations.createIndex({ "createdAt": 1 }, { "expireAfterSeconds": 2592000 })
```

### Monitoring Setup
- Monitor notification delivery rates
- Track failed broadcasts for retry
- Alert on high notification volumes
- Monitor cache hit/miss ratios

### Redis Store Integration (Optional Enhancement)
```typescript
// lib/cache/notification-cache.ts
import Redis from 'ioredis'

class NotificationCache {
  private redis = new Redis(process.env.REDIS_URL)
  
  async cacheUnreadCount(userId: string, count: number) {
    await this.redis.setex(`unread:${userId}`, 10, count.toString())
  }
  
  async getUnreadCount(userId: string): Promise<number | null> {
    const count = await this.redis.get(`unread:${userId}`)
    return count ? parseInt(count) : null
  }
}
```

## 🔮 Future Extensions

After implementation, this system can be extended for:
1. **Client Support Integration**: Real-time support ticket notifications
2. **Department Activity**: Broadcasts for department-wide events  
3. **System Monitoring**: Alerts for system health and performance
4. **Mobile Push Notifications**: Integration with mobile app notifications
5. **Email Digests**: Batch notification summaries via email
6. **Analytics Dashboard**: Notification engagement metrics
7. **A/B Testing**: Different notification formats and timing
8. **Webhook Integration**: External system notifications
9. **Smart Filtering**: AI-powered notification relevance scoring
10. **Multi-tenant Support**: Organization-specific notification rules

## 📊 Success Metrics

### Technical Metrics
- Notification delivery latency < 500ms
- Realtime broadcast success rate > 99%
- Cache hit ratio > 80%
- Zero data loss during failures

### User Experience Metrics  
- Task status update perceived as instant
- Zero drag-and-drop jerking effects
- Notification engagement rate
- User satisfaction with realtime features

### System Performance
- Database query response time < 100ms
- Memory usage stable under load
- CPU usage optimized for concurrent operations
- Horizontal scaling capability verified

---

**End of Implementation Plan**

This comprehensive plan provides a production-ready roadmap for implementing generic real-time notifications and task operations while maintaining the existing MongoDB-first architecture, following current app patterns, and leveraging the existing Supabase real-time infrastructure with full optimization and enterprise-grade features.