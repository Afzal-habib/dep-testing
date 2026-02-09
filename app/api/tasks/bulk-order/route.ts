import { NextRequest, NextResponse } from 'next/server'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { executeGenericDbQuery } from '@/lib/mongodb'
import { clearCache } from '@/lib/mongodb'
import Task from '@/models/Task'
import { z } from 'zod'

// Validation schema for bulk order updates
const bulkOrderUpdateSchema = z.object({
  updates: z.array(z.object({
    id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid task ID format'),
    order: z.number().min(0, 'Order must be non-negative')
  })).min(1, 'At least one update required').max(100, 'Too many updates at once')
})

// PATCH /api/tasks/bulk-order - Update task order positions
export async function PATCH(request: NextRequest) {
  try {
    // Security & Authentication
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'tasks', 'update')

    const body = await request.json()
    const validatedData = bulkOrderUpdateSchema.parse(body)

    // Update task orders in bulk
    const updatedTasks = await executeGenericDbQuery(async () => {
      const bulkOps = validatedData.updates.map(update => ({
        updateOne: {
          filter: { 
            _id: update.id,
            // Security: only allow updating tasks user has access to
            $or: [
              { createdBy: user.id },
              { assigneeId: user.id },
              ...(user.department && !['support', 'admin'].includes(user.department?.name?.toLowerCase())
                ? [{ departmentId: user.departmentId }]
                : [{}] // Super admin can update any task
              )
            ]
          },
          update: { 
            $set: { 
              order: update.order,
              updatedAt: new Date()
            }
          }
        }
      }))

      const result = await Task.bulkWrite(bulkOps)
      
      // Return updated tasks for verification
      const taskIds = validatedData.updates.map(u => u.id)
      return await Task.find({ 
        _id: { $in: taskIds } 
      }).select('_id title status departmentId projectId order')

    }, `bulk-order-${validatedData.updates.map(u => u.id).join('-')}`, 5000) // Short cache for bulk operations

    // Clear relevant cache patterns
    clearCache('tasks')
    
    // Clear project-specific caches if we can determine projects
    const projectIds = [...new Set(updatedTasks.map(t => t.projectId?.toString()).filter(Boolean))]
    projectIds.forEach(projectId => {
      clearCache(`project-${projectId}`)
    })

    return NextResponse.json({
      success: true,
      data: updatedTasks,
      message: `${validatedData.updates.length} task(s) reordered successfully`
    })

  } catch (error: any) {
    console.error('Error updating task order:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid request data',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to update task order'
    }, { status: 500 })
  }
}