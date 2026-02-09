import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery } from "@/lib/mongodb"
import Phase from "@/models/Phase"
import mongoose from "mongoose"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { z } from 'zod'

// Validation schema for analytics request
const phaseAnalyticsSchema = z.object({
  projectId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid project ID').optional(),
  departmentId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid department ID').optional(),
  type: z.enum(['overview', 'timeline', 'tasks']).optional().default('overview'),
  phaseId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid phase ID').optional(),
})

// GET /api/phases/analytics - Get phase analytics data
export async function GET(request: NextRequest) {
  try {
    // Security & Authentication
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'phases', 'read')

    const searchParams = request.nextUrl.searchParams
    const queryParams = {
      projectId: searchParams.get('projectId') || undefined,
      departmentId: searchParams.get('departmentId') || undefined,
      type: searchParams.get('type') || 'overview',
      phaseId: searchParams.get('phaseId') || undefined,
    }

    const validation = phaseAnalyticsSchema.safeParse(queryParams)
    
    if (!validation.success) {
      return NextResponse.json({
        success: false,
        error: 'Invalid request parameters',
        details: validation.error.errors
      }, { status: 400 })
    }

    const { projectId, departmentId, type, phaseId } = validation.data

    let analyticsData: any = {}

    const cacheKey = `phase-analytics-${type}-${projectId || 'all'}-${departmentId || 'all'}-${phaseId || 'none'}`

    if (type === 'overview') {
      // Get comprehensive phase analytics
      analyticsData = await executeGenericDbQuery(async () => {
        return await Phase.getPhaseAnalytics(projectId, departmentId)
      }, cacheKey, 300000) // 5-minute cache

    } else if (type === 'timeline' && projectId) {
      // Get phase timeline for a specific project
      analyticsData = await executeGenericDbQuery(async () => {
        return await Phase.getPhaseTimeline(projectId)
      }, cacheKey, 300000) // 5-minute cache

    } else if (type === 'tasks' && phaseId) {
      // Get task analytics for a specific phase
      analyticsData = await executeGenericDbQuery(async () => {
        return await Phase.getPhaseTaskAnalytics(phaseId)
      }, cacheKey, 300000) // 5-minute cache

    } else {
      return NextResponse.json({
        success: false,
        error: 'Invalid analytics type or missing required parameters',
        details: {
          timeline: 'requires projectId',
          tasks: 'requires phaseId'
        }
      }, { status: 400 })
    }

    return NextResponse.json({
      success: true,
      data: analyticsData,
      type,
      message: 'Phase analytics retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error retrieving phase analytics:', error)

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to retrieve phase analytics'
    }, { status: 500 })
  }
}

// POST /api/phases/analytics - Get custom analytics with filters
export async function POST(request: NextRequest) {
  try {
    // Security & Authentication
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'phases', 'read')

    const body = await request.json()
    
    // Extended validation for POST requests
    const customAnalyticsSchema = z.object({
      projectId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid project ID').optional(),
      departmentId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid department ID').optional(),
      dateRange: z.object({
        startDate: z.string().datetime().optional(),
        endDate: z.string().datetime().optional(),
      }).optional(),
      status: z.array(z.enum(['pending', 'planning', 'in-progress', 'on-hold', 'completed', 'cancelled'])).optional(),
      includeMetrics: z.array(z.enum(['budget', 'timeline', 'tasks', 'risks', 'dependencies'])).optional().default(['budget', 'timeline', 'tasks']),
    })

    const validation = customAnalyticsSchema.safeParse(body)
    
    if (!validation.success) {
      return NextResponse.json({
        success: false,
        error: 'Invalid request data',
        details: validation.error.errors
      }, { status: 400 })
    }

    const { projectId, departmentId, dateRange, status, includeMetrics } = validation.data

    const analyticsData = await executeGenericDbQuery(async () => {
      // Build match query for custom filtering
      const matchQuery: any = { isDeleted: false }
      
      if (projectId) {
        matchQuery.projectId = new mongoose.Types.ObjectId(projectId)
      }
      
      if (departmentId && !projectId) {
        const Project = mongoose.models.Project;
        const departmentProjects = await Project.find({ 
          departmentId: new mongoose.Types.ObjectId(departmentId),
          isDeleted: false 
        }).select('_id');
        
        const projectIds = departmentProjects.map((p: any) => p._id);
        matchQuery.projectId = { $in: projectIds };
      }

      if (status && status.length > 0) {
        matchQuery.status = { $in: status }
      }

      if (dateRange) {
        if (dateRange.startDate) {
          matchQuery.startDate = { $gte: new Date(dateRange.startDate) }
        }
        if (dateRange.endDate) {
          matchQuery.endDate = { $lte: new Date(dateRange.endDate) }
        }
      }

      // Get filtered phases
      const phases = await Phase.find(matchQuery)
        .populate('projectId', 'name departmentId')
        .sort({ startDate: 1 })

      const metrics: any = {
        totalPhases: phases.length,
        phases: phases.map(phase => ({
          _id: phase._id,
          title: phase.title,
          status: phase.status,
          progress: phase.progress,
          startDate: phase.startDate,
          endDate: phase.endDate,
          projectName: (phase.projectId as any)?.name || 'Unknown',
        }))
      }

      // Include specific metrics based on request
      if (includeMetrics.includes('budget')) {
        const budgetMetrics = phases.reduce((acc, phase) => {
          acc.totalAllocated += phase.budgetAllocation || 0
          acc.totalActual += phase.actualCost || 0
          return acc
        }, { totalAllocated: 0, totalActual: 0 })

        metrics.budget = {
          ...budgetMetrics,
          variance: budgetMetrics.totalAllocated > 0 
            ? Math.round(((budgetMetrics.totalActual - budgetMetrics.totalAllocated) / budgetMetrics.totalAllocated) * 100)
            : 0
        }
      }

      if (includeMetrics.includes('timeline')) {
        const now = new Date()
        const timelineMetrics = phases.reduce((acc, phase) => {
          if (phase.status === 'completed') acc.completed++
          else if (new Date(phase.endDate) < now) acc.overdue++
          else acc.onTrack++
          return acc
        }, { completed: 0, overdue: 0, onTrack: 0 })

        metrics.timeline = timelineMetrics
      }

      if (includeMetrics.includes('tasks')) {
        // This would require aggregating task data for each phase
        // For now, just include basic phase completion rates
        const avgProgress = phases.length > 0 
          ? Math.round(phases.reduce((sum, phase) => sum + phase.progress, 0) / phases.length)
          : 0

        metrics.tasks = {
          averageProgress: avgProgress,
          completionRate: phases.length > 0
            ? Math.round((phases.filter(p => p.status === 'completed').length / phases.length) * 100)
            : 0
        }
      }

      return metrics

    }, `custom-phase-analytics-${JSON.stringify(body)}`, 180000) // 3-minute cache

    return NextResponse.json({
      success: true,
      data: analyticsData,
      message: 'Custom phase analytics retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error retrieving custom phase analytics:', error)

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to retrieve custom phase analytics'
    }, { status: 500 })
  }
}