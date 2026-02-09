import { broadcastToUser } from '@/lib/communication/broadcast'
import { executeGenericDbQuery, clearCache } from '@/lib/mongodb'
import TaskOperation from '@/models/TaskOperation'
import Task from '@/models/Task'
import Project from '@/models/Project'
import User from '@/models/User'
import Department from '@/models/Department'
import { 
  dragAndDropOperationSchema, 
  taskAssignmentOperationSchema, 
  taskStatusOperationSchema 
} from '@/lib/validations/task-operation'
import { z } from 'zod'
import { NotificationService } from './notification-service'

export interface TaskOperationPayload {
  type: 'drag_drop' | 'assignment' | 'status_change' | 'creation' | 'deletion'
  category: 'task_board' | 'assignment' | 'status'
  userId: string
  userName: string
  userAvatar?: string
  taskId: string
  projectId: string
  departmentId?: string
  previousState?: Record<string, any>
  newState: Record<string, any>
  metadata?: Record<string, any>
}

export interface DragDropPayload extends TaskOperationPayload {
  type: 'drag_drop'
  category: 'task_board'
  previousState: {
    phaseId: string
    phaseName: string
    order: number
  }
  newState: {
    phaseId: string
    phaseName: string
    order: number
  }
}

export interface AssignmentPayload extends TaskOperationPayload {
  type: 'assignment'
  category: 'assignment'
  previousState?: {
    assigneeId?: string
    assigneeName?: string
  }
  newState: {
    assigneeId: string
    assigneeName: string
  }
}

export interface StatusChangePayload extends TaskOperationPayload {
  type: 'status_change'
  category: 'status'
  previousState?: {
    status: string
  }
  newState: {
    status: string
  }
}

export class TaskOperationsService {
  /**
   * Handle task drag and drop operations with realtime broadcast
   */
  static async handleTaskDragDrop(payload: DragDropPayload): Promise<void> {
    try {
      // Validate payload
      const validatedPayload = dragAndDropOperationSchema.parse(payload)
      
      // Record operation in MongoDB
      const operation = await executeGenericDbQuery(async () => {
        const taskOperation = new TaskOperation({
          ...validatedPayload,
          broadcastStatus: 'pending'
        })
        return await taskOperation.save()
      })

      // Get project and task details for broadcasting
      const [task, project] = await Promise.all([
        executeGenericDbQuery(async () => 
          Task.findById(payload.taskId).lean()
        ),
        executeGenericDbQuery(async () => 
          Project.findById(payload.projectId).lean()
        )
      ])

      if (!task || !project) {
        throw new Error('Task or project not found')
      }

      // Broadcast to project room (all users viewing this project)
      const broadcastPayload = {
        operationId: operation._id.toString(),
        type: 'drag_drop',
        userId: payload.userId,
        userName: payload.userName,
        userAvatar: payload.userAvatar,
        taskId: payload.taskId,
        taskTitle: task.title,
        projectId: payload.projectId,
        previousPhase: payload.previousState,
        newPhase: payload.newState,
        timestamp: new Date().toISOString(),
        metadata: payload.metadata
      }

      // Broadcast to project stakeholders (simplified to use broadcastToUser)
      // Note: In a real implementation, you'd get all project stakeholders and broadcast to each
      console.log('Broadcasting task drag-drop operation:', broadcastPayload)
      // TODO: Implement project stakeholder broadcasting when project members API is available

      // Mark operation as broadcast successfully
      await executeGenericDbQuery(async () => {
        return await TaskOperation.findByIdAndUpdate(
          operation._id,
          { broadcastStatus: 'success' }
        )
      })

      // Clear related cache
      clearCache(`project-tasks-${payload.projectId}`)
      clearCache(`task-operations-${payload.taskId}`)
      
      console.log(`✅ Task drag-drop operation broadcast for task ${payload.taskId}`)
      
    } catch (error) {
      console.error('❌ Failed to handle task drag-drop:', error)
      
      // Mark operation as failed
      if (payload.taskId) {
        try {
          await executeGenericDbQuery(async () => {
            return await TaskOperation.updateMany(
              { 
                taskId: payload.taskId,
                type: 'drag_drop',
                broadcastStatus: 'pending'
              },
              { broadcastStatus: 'failed' }
            )
          })
        } catch (updateError) {
          console.error('Failed to update operation status:', updateError)
        }
      }
      
      throw error
    }
  }

  /**
   * Handle task assignment changes with realtime broadcast and notifications
   */
  static async handleTaskAssignment(payload: AssignmentPayload): Promise<void> {
    try {
      // Validate payload
      const validatedPayload = taskAssignmentOperationSchema.parse(payload)
      
      // Record operation in MongoDB
      const operation = await executeGenericDbQuery(async () => {
        const taskOperation = new TaskOperation({
          ...validatedPayload,
          broadcastStatus: 'pending'
        })
        return await taskOperation.save()
      })

      // Get task and project details
      const [task, project] = await Promise.all([
        executeGenericDbQuery(async () => 
          Task.findById(payload.taskId)
            .populate('assignee', 'name email avatar')
            .lean()
        ),
        executeGenericDbQuery(async () => 
          Project.findById(payload.projectId).lean()
        )
      ])

      if (!task || !project) {
        throw new Error('Task or project not found')
      }

      // Broadcast assignment change to project room
      const broadcastPayload = {
        operationId: operation._id.toString(),
        type: 'assignment',
        userId: payload.userId,
        userName: payload.userName,
        userAvatar: payload.userAvatar,
        taskId: payload.taskId,
        taskTitle: task.title,
        projectId: payload.projectId,
        previousAssignee: payload.previousState,
        newAssignee: payload.newState,
        timestamp: new Date().toISOString(),
        metadata: payload.metadata
      }

      // Broadcast assignment change to project stakeholders
      console.log('Broadcasting task assignment operation:', broadcastPayload)
      // TODO: Implement project stakeholder broadcasting when project members API is available

      // Send notification to newly assigned user
      if (payload.newState.assigneeId && payload.newState.assigneeId !== payload.userId) {
        await NotificationService.notifyTaskAssigned(
          payload.taskId,
          payload.userId,
          payload.newState.assigneeId
        )
      }

      // Mark operation as broadcast successfully
      await executeGenericDbQuery(async () => {
        return await TaskOperation.findByIdAndUpdate(
          operation._id,
          { broadcastStatus: 'success' }
        )
      })

      // Clear related cache
      clearCache(`project-tasks-${payload.projectId}`)
      clearCache(`user-tasks-${payload.newState.assigneeId}`)
      if (payload.previousState?.assigneeId) {
        clearCache(`user-tasks-${payload.previousState.assigneeId}`)
      }
      
      console.log(`✅ Task assignment operation broadcast for task ${payload.taskId}`)
      
    } catch (error) {
      console.error('❌ Failed to handle task assignment:', error)
      throw error
    }
  }

  /**
   * Handle task status changes with realtime broadcast
   */
  static async handleTaskStatusChange(payload: StatusChangePayload): Promise<void> {
    try {
      // Validate payload
      const validatedPayload = taskStatusOperationSchema.parse(payload)
      
      // Record operation in MongoDB
      const operation = await executeGenericDbQuery(async () => {
        const taskOperation = new TaskOperation({
          ...validatedPayload,
          broadcastStatus: 'pending'
        })
        return await taskOperation.save()
      })

      // Get task details
      const task = await executeGenericDbQuery(async () => 
        Task.findById(payload.taskId)
          .populate('assignee', 'name')
          .lean()
      )

      if (!task) {
        throw new Error('Task not found')
      }

      // Broadcast status change to project room
      const broadcastPayload = {
        operationId: operation._id.toString(),
        type: 'status_change',
        userId: payload.userId,
        userName: payload.userName,
        userAvatar: payload.userAvatar,
        taskId: payload.taskId,
        taskTitle: task.title,
        projectId: payload.projectId,
        previousStatus: payload.previousState?.status,
        newStatus: payload.newState.status,
        timestamp: new Date().toISOString(),
        metadata: payload.metadata
      }

      // Broadcast status change to project stakeholders
      console.log('Broadcasting task status change operation:', broadcastPayload)
      // TODO: Implement project stakeholder broadcasting when project members API is available

      // If task is completed, send notification
      if (payload.newState.status === 'completed' && task.assigneeId) {
        // Send notification to project creator or stakeholders
        // This would be implemented based on notification rules
      }

      // Mark operation as broadcast successfully
      await executeGenericDbQuery(async () => {
        return await TaskOperation.findByIdAndUpdate(
          operation._id,
          { broadcastStatus: 'success' }
        )
      })

      // Clear related cache
      clearCache(`project-tasks-${payload.projectId}`)
      clearCache(`task-${payload.taskId}`)
      
      console.log(`✅ Task status change operation broadcast for task ${payload.taskId}`)
      
    } catch (error) {
      console.error('❌ Failed to handle task status change:', error)
      throw error
    }
  }

  /**
   * Get task operations history for audit trail
   */
  static async getTaskOperations(taskId: string, options: {
    limit?: number
    offset?: number
    type?: string
  } = {}): Promise<any[]> {
    const { limit = 20, offset = 0, type } = options
    
    return executeGenericDbQuery(async () => {
      const query: any = { taskId }
      
      if (type) {
        query.type = type
      }
      
      return await TaskOperation
        .find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(offset)
        .populate('user', 'name email avatar')
        .lean()
    }, `task-operations-${taskId}-${limit}-${offset}-${type}`, 30000)
  }

  /**
   * Get project operations history
   */
  static async getProjectOperations(projectId: string, options: {
    limit?: number
    offset?: number
    type?: string
  } = {}): Promise<any[]> {
    const { limit = 50, offset = 0, type } = options
    
    return executeGenericDbQuery(async () => {
      const query: any = { projectId }
      
      if (type) {
        query.type = type
      }
      
      return await TaskOperation
        .find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(offset)
        .populate('user', 'name email avatar')
        .populate('task', 'title')
        .lean()
    }, `project-operations-${projectId}-${limit}-${offset}-${type}`, 30000)
  }

  /**
   * Cleanup old task operations (run via cron job)
   */
  static async cleanupOldOperations(): Promise<void> {
    try {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
      
      await executeGenericDbQuery(async () => {
        return await TaskOperation.deleteMany({
          createdAt: { $lt: thirtyDaysAgo }
        })
      })
      
      console.log('✅ Cleaned up old task operations')
    } catch (error) {
      console.error('❌ Failed to cleanup old task operations:', error)
    }
  }

  /**
   * Retry failed broadcasts
   */
  static async retryFailedBroadcasts(): Promise<void> {
    try {
      const failedOperations = await executeGenericDbQuery(async () => {
        return await TaskOperation.find({
          broadcastStatus: 'failed',
          createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // Last hour only
        }).limit(10).lean()
      })

      for (const operation of failedOperations) {
        try {
          // Retry broadcast based on operation type
          // Note: For now, just log the operation since proper type casting requires more context
          console.log(`Retrying failed operation ${operation._id} of type ${operation.type}`)
          
          // TODO: Implement proper retry logic when operation schema is more defined
          // switch (operation.type) {
          //   case 'drag_drop':
          //     await this.handleTaskDragDrop(operation as unknown as DragDropPayload)
          //     break
          //   case 'assignment':
          //     await this.handleTaskAssignment(operation as unknown as AssignmentPayload)
          //     break
          //   case 'status_change':
          //     await this.handleTaskStatusChange(operation as unknown as StatusChangePayload)
          //     break
          // }
        } catch (retryError) {
          console.error(`Failed to retry operation ${operation._id}:`, retryError)
        }
      }
    } catch (error) {
      console.error('Failed to retry failed broadcasts:', error)
    }
  }

  /**
   * Get realtime statistics for dashboard
   */
  static async getRealtimeStats(projectId?: string): Promise<{
    totalOperations: number
    operationsToday: number
    failedBroadcasts: number
    topOperationTypes: Array<{ type: string, count: number }>
  }> {
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    
    return executeGenericDbQuery(async () => {
      const query = projectId ? { projectId } : {}
      
      const [total, today_count, failed, topTypes] = await Promise.all([
        TaskOperation.countDocuments(query),
        TaskOperation.countDocuments({ ...query, createdAt: { $gte: today } }),
        TaskOperation.countDocuments({ ...query, broadcastStatus: 'failed' }),
        TaskOperation.aggregate([
          { $match: query },
          { $group: { _id: '$type', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 5 },
          { $project: { type: '$_id', count: 1, _id: 0 } }
        ])
      ])
      
      return {
        totalOperations: total,
        operationsToday: today_count,
        failedBroadcasts: failed,
        topOperationTypes: topTypes
      }
    }, `realtime-stats-${projectId || 'global'}`, 60000) // Cache for 1 minute
  }
}