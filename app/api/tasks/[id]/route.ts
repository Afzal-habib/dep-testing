import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Task from "@/models/Task"
import User from "@/models/User"
import { updateTaskSchema, taskIdSchema, assignTaskSchema, updateTaskStatusSchema } from "@/lib/validations/task"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { performSoftDelete, addSoftDeleteFilter } from "@/lib/utils/soft-delete"
import mongoose from 'mongoose'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/tasks/[id] - Get task by ID
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'tasks', 'read')
    
    const resolvedParams = await params
    const validatedParams = taskIdSchema.parse({ id: resolvedParams.id })

    // Fetch task with automatic connection management and caching
    const task = await executeGenericDbQuery(async () => {
      // Build filter based on user permissions
      const filter: any = { 
        _id: validatedParams.id,
        status: { $ne: 'cancelled' }
      }

      // Department-based filtering for non-support users (super admin bypasses this)
      const userDepartment = user.department?.name?.toLowerCase()
      const isSupport = ['support', 'admin'].includes(userDepartment)
      if (!isSuperAdmin && user.departmentId && !isSupport) {
        filter.departmentId = user.departmentId
      }

      // Team members can only see their assigned or created tasks
      if (!isSuperAdmin && user.role?.name === 'team_member') {
        filter.$or = [
          { assigneeId: user.id },
          { createdBy: user.id }
        ]
      }

      // Apply soft delete filtering
      addSoftDeleteFilter(filter, isSuperAdmin)

      return await Task.findOne(filter)
        .populate('project', 'name clientId status')
        .populate('department', 'name status')
        .populate('assignee', 'name email role')
        .populate('creator', 'name email')
        .populate('assigner', 'name email')
        .populate('parentTask', 'title status')
        .populate({
          path: 'subTasks',
          populate: {
            path: 'assignee',
            select: 'name email'
          }
        })
        .lean()
    }, `task-${validatedParams.id}`, 300000) // 5-minute cache

    if (!task) {
      return NextResponse.json({
        success: false,
        error: 'Task not found or access denied'
      }, { status: 404 })
    }

    return NextResponse.json({
      success: true,
      data: task,
      message: 'Task retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching task:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid task ID',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch task'
    }, { status: 500 })
  }
}

// PUT /api/tasks/[id] - Update task
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'tasks', 'update')
    
    const resolvedParams = await params
    const validatedParams = taskIdSchema.parse({ id: resolvedParams.id })
    const body = await request.json()
    
    // Handle special operations
    if (body.operation === 'assign') {
      return handleAssignTask(validatedParams.id, body, user, isSuperAdmin || false)
    }
    
    if (body.operation === 'updateStatus') {
      return handleUpdateStatus(validatedParams.id, body, user, isSuperAdmin || false)
    }
    
    // Regular update operation
    // Convert string dates and numbers
    const processedData = {
      ...body,
      startDate: body.startDate ? new Date(body.startDate) : undefined,
      dueDate: body.dueDate ? new Date(body.dueDate) : undefined,
      estimatedHours: body.estimatedHours ? parseFloat(body.estimatedHours) : undefined,
      actualHours: body.actualHours ? parseFloat(body.actualHours) : undefined,
    }

    const validatedData = updateTaskSchema.parse(processedData)

    // Update task with automatic connection management
    const updatedTask = await executeGenericDbQuery(async () => {
      // Find existing task with proper filtering
      const filter: any = { 
        _id: validatedParams.id,
        status: { $ne: 'cancelled' }
      }

      // Department-based filtering for non-support users (super admin bypasses this)
      const userDepartment = user.department?.name?.toLowerCase()
      const isSupport = ['support', 'admin'].includes(userDepartment)
      if (!isSuperAdmin && user.department && !isSupport) {
        filter.departmentId = user.department
      }

      // Apply soft delete filtering
      addSoftDeleteFilter(filter, isSuperAdmin)

      const existingTask = await Task.findOne(filter)
      
      if (!existingTask) {
        throw new Error('Task not found or access denied')
      }

      // Permission checks for updates (super admin bypasses all)
      if (!isSuperAdmin) {
        const isLeadOrManager = ['department_lead', 'manager'].includes(user.role?.name)
        const isAssignee = existingTask.assigneeId?.toString() === user.id
        const isCreator = existingTask.createdBy?.toString() === user.id

        // Who can update what
        const canUpdateBasicFields = isSupport || isLeadOrManager || isCreator
        const canUpdateStatus = isSupport || isLeadOrManager || isAssignee
        const canAssign = isSupport || isLeadOrManager

        // Check specific field permissions
        if (validatedData.status && !canUpdateStatus) {
          throw new Error('You do not have permission to update task status')
        }

        if (validatedData.assigneeId !== undefined && !canAssign) {
          throw new Error('You do not have permission to assign tasks')
        }

        if ((validatedData.title || validatedData.description || validatedData.priority) && !canUpdateBasicFields) {
          throw new Error('You do not have permission to update task details')
        }
      }

      // Validate assignee if being changed
      if (validatedData.assigneeId) {
        const assignee = await User.findOne({
          _id: validatedData.assigneeId,
          department: existingTask.departmentId,
          status: 'active'
        })

        if (!assignee) {
          throw new Error('Assignee not found or not in the task department')
        }

        // Set assigner if assignment is being made
        validatedData.assignedBy = user.id as any
      }

      // Status-specific logic
      if (validatedData.status && validatedData.status !== existingTask.status) {
        // Set completion time for completed status
        if (validatedData.status === 'completed') {
          validatedData.completedAt = new Date() as any
        } else {
          validatedData.completedAt = undefined as any
        }
      }

      // Update the task
      const updated = await Task.findByIdAndUpdate(
        validatedParams.id,
        { 
          $set: validatedData,
          updatedAt: new Date()
        },
        { 
          new: true,
          runValidators: false // Disable validation to avoid issues with existing corrupted data
        }
      )
      .populate('project', 'name clientId status')
      .populate('department', 'name status')
      .populate('assignee', 'name email role')
      .populate('creator', 'name email')
      .populate('assigner', 'name email')
      .populate('parentTask', 'title status')

      // Sync assignee to project channel if assignee was changed
      if (validatedData.assigneeId && updated?.projectId) {
        try {
          const { channelSyncManager } = await import('@/lib/communication/channel-sync-manager')
          await channelSyncManager.syncAssigneeToProjectChannel(
            validatedData.assigneeId.toString(),
            updated.projectId.toString(),
            user.id
          )
        } catch (syncError) {
          console.warn('Failed to sync assignee to project channel:', syncError)
          // Don't block task update if sync fails
        }
      }

      return updated
    })

    if (!updatedTask) {
      return NextResponse.json({
        success: false,
        error: 'Task not found'
      }, { status: 404 })
    }

    // Clear relevant cache patterns after update
    clearCache('tasks')
    clearCache(`task-${validatedParams.id}`)
    clearCache(`project-${updatedTask.projectId}`)

    return NextResponse.json({
      success: true,
      data: updatedTask,
      message: 'Task updated successfully'
    })

  } catch (error: any) {
    console.error('Error updating task:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Validation failed',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to update task'
    }, { status: 500 })
  }
}

// DELETE /api/tasks/[id] - Soft delete task
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'tasks', 'delete')

    // Resolve params and validate
    const resolvedParams = await params
    const validatedParams = taskIdSchema.parse({ id: resolvedParams.id })

    // Check if task exists and user has access (same filtering as GET)
    const existingTask = await executeGenericDbQuery(async () => {
      // Build filter based on user permissions
      const filter: any = {
        _id: validatedParams.id,
        status: { $ne: 'cancelled' }
      }

      // Department-based filtering for non-support users (super admin bypasses this)
      const userDepartment = user.department?.name?.toLowerCase()
      const isSupport = ['support', 'admin'].includes(userDepartment)
      if (!isSuperAdmin && user.departmentId && !isSupport) {
        filter.departmentId = user.departmentId
      }

      // Team members can only see their assigned or created tasks
      if (!isSuperAdmin && user.role?.name === 'team_member') {
        filter.$or = [
          { assigneeId: user.id },
          { createdBy: user.id }
        ]
      }

      // Apply soft delete filtering (exclude deleted tasks like departments)
      addSoftDeleteFilter(filter, false)

      return await Task.findOne(filter)
    })

    if (!existingTask) {
      return NextResponse.json({
        success: false,
        error: 'Task not found or access denied'
      }, { status: 404 })
    }

    // Perform soft delete using the generic utility
    const deleteResult = await performSoftDelete('task', validatedParams.id, userEmail)

    if (!deleteResult.success) {
      return NextResponse.json({
        success: false,
        error: deleteResult.message
      }, { status: 400 })
    }

    return NextResponse.json({
      success: true,
      message: deleteResult.message,
      data: deleteResult.data
    })

  } catch (error: any) {
    console.error('Error deleting task:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid task ID',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to delete task'
    }, { status: 500 })
  }
}

// Helper function to handle task assignment
async function handleAssignTask(taskId: string, body: any, user: any, isSuperAdmin: boolean = false) {
  try {
    const validatedData = assignTaskSchema.parse({
      assigneeId: body.assigneeId,
      assignedBy: user.id
    })

    const updatedTask = await executeGenericDbQuery(async () => {
      // First, get the existing task with minimal fields to check permissions
      const existingTask = await Task.findById(taskId).select('departmentId projectId').lean()
      
      if (!existingTask) {
        throw new Error('Task not found')
      }

      // Permission checks (super admin bypasses all)
      if (!isSuperAdmin) {
        const userDepartment = user.department?.name?.toLowerCase()
        const isSupport = ['support', 'admin'].includes(userDepartment)
        const isLeadOrManager = ['department_lead', 'manager'].includes(user.role?.name)

        if (!isSupport && !isLeadOrManager) {
          throw new Error('Only department leads and support team can assign tasks')
        }

        if (!isSupport && existingTask.departmentId?.toString() !== user.department?.toString()) {
          throw new Error('You can only assign tasks in your department')
        }
      }

      // Validate assignee exists and belongs to department
      let assignee = null
      
      // Check if task has a valid departmentId
      if (existingTask.departmentId && mongoose.Types.ObjectId.isValid(existingTask.departmentId)) {
        assignee = await User.findOne({
          _id: validatedData.assigneeId,
          department: existingTask.departmentId,
          status: 'active'
        }).select('_id name email').lean()
      } else {
        // If task has corrupted departmentId, just check if user exists and is active
        console.warn(`Task ${taskId} has corrupted departmentId: ${existingTask.departmentId}`)
        assignee = await User.findOne({
          _id: validatedData.assigneeId,
          status: 'active'
        }).select('_id name email department').lean()
      }

      if (!assignee) {
        throw new Error('Assignee not found or not active')
      }

      // Use MongoDB's direct update operation to avoid Mongoose validation issues
      const updateResult = await Task.updateOne(
        { _id: taskId },
        { 
          $set: {
            assigneeId: validatedData.assigneeId,
            assignedBy: validatedData.assignedBy,
            updatedAt: new Date()
          }
        }
      )

      if (updateResult.matchedCount === 0) {
        throw new Error('Task not found')
      }

      // Return the updated task with populated fields
      return await Task.findById(taskId)
        .populate('assignee', 'name email role')
        .populate('assigner', 'name email')
        .lean()
    })

    // Clear cache
    clearCache('tasks')
    clearCache(`task-${taskId}`)
    if (updatedTask?.projectId) {
      clearCache(`project-${updatedTask.projectId}`)
    }

    return NextResponse.json({
      success: true,
      data: updatedTask,
      message: 'Task assigned successfully'
    })

  } catch (error: any) {
    console.error('Error assigning task:', error)

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to assign task'
    }, { status: 500 })
  }
}

// Helper function to handle status updates
async function handleUpdateStatus(taskId: string, body: any, user: any, isSuperAdmin: boolean = false) {
  try {
    const validatedData = updateTaskStatusSchema.parse({
      status: body.status,
      actualHours: body.actualHours
    })

    const updatedTask = await executeGenericDbQuery(async () => {
      const existingTask = await Task.findById(taskId)
      
      if (!existingTask) {
        throw new Error('Task not found')
      }

      // Permission checks (super admin bypasses all)
      if (!isSuperAdmin) {
        const userDepartment = user.department?.name?.toLowerCase()
        const isSupport = ['support', 'admin'].includes(userDepartment)
        const isLeadOrManager = ['department_lead', 'manager'].includes(user.role?.name)
        const isAssignee = existingTask.assigneeId?.toString() === user.id

        if (!isSupport && !isLeadOrManager && !isAssignee) {
          throw new Error('You do not have permission to update task status')
        }
      }

      const updateData: any = {
        status: validatedData.status,
        updatedAt: new Date()
      }

      // Handle completion
      if (validatedData.status === 'completed') {
        updateData.completedAt = new Date()
        if (validatedData.actualHours) {
          updateData.actualHours = validatedData.actualHours
        }
      } else {
        updateData.completedAt = undefined
      }

      // Update status
      return await Task.findByIdAndUpdate(
        taskId,
        { $set: updateData },
        { 
          new: true,
          runValidators: true
        }
      )
      .populate('project', 'name')
      .populate('assignee', 'name email')
    })

    // Clear cache
    clearCache('tasks')
    clearCache(`task-${taskId}`)
    if (updatedTask?.projectId) {
      clearCache(`project-${updatedTask.projectId}`)
    }

    return NextResponse.json({
      success: true,
      data: updatedTask,
      message: 'Task status updated successfully'
    })

  } catch (error: any) {
    console.error('Error updating task status:', error)

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to update task status'
    }, { status: 500 })
  }
}