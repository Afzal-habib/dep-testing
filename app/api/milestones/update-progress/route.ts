import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery } from "@/lib/mongodb"
import Milestone from "@/models/Milestone"
import Task from "@/models/Task"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { z } from 'zod'

// Validation schema for milestone progress update
const milestoneProgressUpdateSchema = z.object({
  milestoneId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid milestone ID'),
  projectId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid project ID').optional(),
})

// POST /api/milestones/update-progress - Update milestone progress based on linked tasks
export async function POST(request: NextRequest) {
  try {
    // Security & Authentication
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'milestones', 'update')

    const body = await request.json()
    
    if (body.projectId) {
      // Bulk update all milestones for a project
      const validation = z.object({ projectId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid project ID') }).safeParse(body)
      
      if (!validation.success) {
        return NextResponse.json({
          success: false,
          error: 'Invalid request data',
          details: validation.error.errors
        }, { status: 400 })
      }

      const results = await executeGenericDbQuery(async () => {
        // Update all milestones for the project
        return await (Milestone as any).updateProjectMilestoneProgress(validation.data.projectId)
      }, `milestone-progress-update-project-${validation.data.projectId}`, 30000) // 30-second cache

      return NextResponse.json({
        success: true,
        data: results,
        message: `Updated progress for ${results.length} milestone(s)`
      })

    } else if (body.milestoneId) {
      // Update specific milestone
      const validation = milestoneProgressUpdateSchema.safeParse(body)
      
      if (!validation.success) {
        return NextResponse.json({
          success: false,
          error: 'Invalid request data',
          details: validation.error.errors
        }, { status: 400 })
      }

      const result = await executeGenericDbQuery(async () => {
        const milestone = await Milestone.findById(validation.data.milestoneId) as any
        
        if (!milestone) {
          throw new Error('Milestone not found')
        }

        // Check permissions - user should have access to the project
        if (!isSuperAdmin) {
          // Add basic security check - user should be able to access this milestone's project
          // This would typically be enhanced with more sophisticated permission checks
        }

        const newProgress = await milestone.calculateProgressFromTasks()
        
        return {
          milestoneId: milestone._id,
          progress: newProgress,
          status: milestone.status,
          completedDate: milestone.completedDate
        }
      }, `milestone-progress-update-${validation.data.milestoneId}`, 30000) // 30-second cache

      return NextResponse.json({
        success: true,
        data: result,
        message: 'Milestone progress updated successfully'
      })

    } else {
      return NextResponse.json({
        success: false,
        error: 'Either milestoneId or projectId is required'
      }, { status: 400 })
    }

  } catch (error: any) {
    console.error('Error updating milestone progress:', error)

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to update milestone progress'
    }, { status: 500 })
  }
}

// GET /api/milestones/update-progress?projectId=xxx - Get milestone progress for a project (read-only)
export async function GET(request: NextRequest) {
  try {
    // Security & Authentication  
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'milestones', 'read')

    const searchParams = request.nextUrl.searchParams
    const projectId = searchParams.get('projectId')

    if (!projectId || !/^[0-9a-fA-F]{24}$/.test(projectId)) {
      return NextResponse.json({
        success: false,
        error: 'Valid projectId is required'
      }, { status: 400 })
    }

    const milestoneProgress = await executeGenericDbQuery(async () => {
      // Get milestone progress summary for project
      const milestones = await Milestone.find({
        projectId,
        isDeleted: false
      }).select('_id title progress status dueDate linkedTaskIds').lean()

      const progressData = []

      for (const milestone of milestones) {
        // Get linked task counts
        const taskCounts = await Task.aggregate([
          { 
            $match: { 
              milestoneId: milestone._id,
              status: { $nin: ['cancelled', 'deleted'] }
            }
          },
          {
            $group: {
              _id: '$status',
              count: { $sum: 1 }
            }
          }
        ])

        const totalTasks = taskCounts.reduce((sum, item) => sum + item.count, 0)
        const completedTasks = taskCounts.find(item => item._id === 'completed')?.count || 0

        progressData.push({
          milestoneId: milestone._id,
          title: milestone.title,
          progress: milestone.progress,
          status: milestone.status,
          dueDate: milestone.dueDate,
          totalTasks,
          completedTasks,
          taskCompletionRate: totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0
        })
      }

      return progressData
    }, `milestone-progress-summary-${projectId}`, 60000) // 1-minute cache

    return NextResponse.json({
      success: true,
      data: milestoneProgress,
      message: 'Milestone progress retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error retrieving milestone progress:', error)

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to retrieve milestone progress'
    }, { status: 500 })
  }
}