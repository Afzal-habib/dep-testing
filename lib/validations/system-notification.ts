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
export const prioritySchema = z.enum(['1', '2', '3', '4']).transform(val => parseInt(val, 10) as 1 | 2 | 3 | 4)

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
  senderAvatar: z.string().url().optional().or(z.literal('')),
  title: z.string().min(1, 'Title is required').max(255),
  message: z.string().min(1, 'Message is required').max(1000),
  contentPreview: z.string().max(200).optional(),
  entityType: entityTypeSchema,
  entityId: objectIdSchema,
  entityName: z.string().max(255).optional(),
  actionType: actionTypeSchema,
  actionUrl: z.string().max(500).optional(),
  priority: prioritySchema.default("1"),
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

// Backward compatibility alias
export const getSystemNotificationsSchema = notificationQuerySchema

// Mark as read schema
export const markAsReadSchema = z.object({
  notificationIds: z.array(objectIdSchema).min(1, 'At least one notification ID is required')
}).strict()

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