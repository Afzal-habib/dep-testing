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

// Task status change operation validation
export const taskStatusOperationSchema = z.object({
  type: z.literal('status_change'),
  category: z.literal('status'),
  taskId: objectIdSchema,
  projectId: objectIdSchema,
  departmentId: objectIdSchema.optional(),
  userId: objectIdSchema,
  userName: z.string().min(1).max(100),
  userAvatar: z.string().url().optional(),
  previousState: z.object({
    status: z.string().min(1)
  }).optional(),
  newState: z.object({
    status: z.string().min(1)
  }),
  metadata: z.record(z.any()).optional()
})

// Update drag and drop schema to match service expectations
export const dragAndDropOperationSchema = z.object({
  type: z.literal('drag_drop'),
  category: z.literal('task_board'),
  taskId: objectIdSchema,
  projectId: objectIdSchema,
  departmentId: objectIdSchema.optional(),
  userId: objectIdSchema,
  userName: z.string().min(1).max(100),
  userAvatar: z.string().url().optional(),
  previousState: z.object({
    phaseId: objectIdSchema,
    phaseName: z.string().min(1),
    order: z.number().min(0)
  }),
  newState: z.object({
    phaseId: objectIdSchema,
    phaseName: z.string().min(1),
    order: z.number().min(0)
  }),
  metadata: z.record(z.any()).optional()
})

// Update task assignment schema to match service expectations
export const taskAssignmentOperationSchema = z.object({
  type: z.literal('assignment'),
  category: z.literal('assignment'),
  taskId: objectIdSchema,
  projectId: objectIdSchema,
  departmentId: objectIdSchema.optional(),
  userId: objectIdSchema,
  userName: z.string().min(1).max(100),
  userAvatar: z.string().url().optional(),
  previousState: z.object({
    assigneeId: objectIdSchema.optional(),
    assigneeName: z.string().optional()
  }).optional(),
  newState: z.object({
    assigneeId: objectIdSchema,
    assigneeName: z.string().min(1)
  }),
  metadata: z.record(z.any()).optional()
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