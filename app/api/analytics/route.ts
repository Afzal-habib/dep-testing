import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery } from "@/lib/mongodb"
import Project from "@/models/Project"
import Task from "@/models/Task"
import mongoose from "mongoose"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { createAPIErrorResponse, createAPISuccessResponse } from "@/lib/utils/api-responses"
import { analyticsQuerySchema } from "@/lib/validations/analytics"

// Cache TTL for analytics queries - DISABLED for real-time updates
const CACHE_TTL = 0 // Was 10 minutes, now disabled to ensure fresh data after CRUD operations

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/analytics - Get comprehensive project and task analytics
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions) with filtering
    const { session, user, userEmail, isSuperAdmin, applyFilters } = await genericApiRoutesMiddleware(request, 'analytics', 'read')
    console.log("🔍 Analytics API: Authenticated user details:", {
      permissions: JSON.stringify(user.permissions, null, 2),
      isSuperAdmin,
      rolePermissions: user.role?.permissions?.map((p: any) => ({ resource: p.resource, conditions: p.conditions })),
      userRole: user.role?.name,
      userId: user._id || user.id,
      userEmail: user.email,
      userDepartment: user.department,
      hasUserPermissions: !!user.permissions,
      hasRolePermissions: !!user.role?.permissions,
      permissionsCount: user.permissions?.length || user.role?.permissions?.length || 0
    })

    console.log("🔍 Analytics API: Applied filters:", applyFilters)

    // Parse and validate query parameters
    const { searchParams } = new URL(request.url)
    const queryParams = Object.fromEntries(searchParams.entries())

    const validation = analyticsQuerySchema.safeParse(queryParams)
    if (!validation.success) {
      return createErrorResponse("Invalid query parameters", 400, {
        errors: validation.error.errors
      })
    }

    const { projectId, dateRange, includeCompleted, departmentId, userId } = validation.data

    // Generate user-specific cache key to prevent cross-user cache pollution
    const userCacheIdentifier = isSuperAdmin ? 'superadmin' : `user_${user._id || user.id}_${user.role?.name || 'no_role'}_${user.department || 'no_dept'}`
    const cacheKey = `analytics:${userCacheIdentifier}:${projectId}:${dateRange}:${includeCompleted}:${departmentId}:${userId}`

    // Execute database query with optimized connection and caching
    const result = await executeGenericDbQuery(async () => {
      // Ensure models are registered
      if (!mongoose.models.Project) {
        require('@/models/Project')
      }
      if (!mongoose.models.Task) {
        require('@/models/Task')
      }
      if (!mongoose.models.Department) {
        require('@/models/Department')
      }

      // Calculate date range
      const endDate = new Date()
      const startDate = new Date()
      
      switch (dateRange) {
        case '7d':
          startDate.setDate(endDate.getDate() - 7)
          break
        case '30d':
          startDate.setDate(endDate.getDate() - 30)
          break
        case '90d':
          startDate.setDate(endDate.getDate() - 90)
          break
        case '1y':
          startDate.setFullYear(endDate.getFullYear() - 1)
          break
      }

      // Build base filter
      const baseFilter: any = {}

      // For project-specific analytics, don't filter by date - we want all project data
      // For general analytics, filter by date range
      if (!projectId) {
        baseFilter.createdAt = { $gte: startDate, $lte: endDate }
      }

      if (projectId) {
        if (mongoose.Types.ObjectId.isValid(projectId)) {
          baseFilter.projectId = new mongoose.Types.ObjectId(projectId)
        } else {
          baseFilter.projectId = new mongoose.Types.ObjectId()
        }
      }

      console.log('🔥 Analytics API: About to apply filters:', {
        originalQuery: baseFilter,
        isSuperAdmin,
        userEmail: userEmail,
        userId: user._id || user.id,
        userDepartment: user.department,
        userRole: user.role?.name,
        applyFiltersType: typeof applyFilters,
        userPermissions: user.permissions?.length || user.role?.permissions?.length || 0
      })

      // 🔥 Apply permission-based filters for each model
      const projectFilter = await applyFilters({ 
        ...baseFilter, 
        ...(departmentId ? { departmentIds: { $in: [new mongoose.Types.ObjectId(departmentId)] } } : {})
      })
      const taskFilter = await applyFilters({ 
        ...baseFilter, 
        ...(departmentId ? { departmentId: new mongoose.Types.ObjectId(departmentId) } : {}),
        ...(userId ? { assigneeId: new mongoose.Types.ObjectId(userId) } : {})
      })

      console.log('🔥 Analytics API: Query filtering applied:', {
        isSuperAdmin,
        projectId,
        originalQuery: baseFilter,
        projectFilter,
        taskFilter,
        userPermissions: user.role?.permissions?.map((p: any) => ({
          resource: p.resource,
          conditions: p.conditions
        })) || user.permissions?.map((p: any) => ({
          resource: p.resource,
          conditions: p.conditions
        }))
      })

      // For debugging: Let's also count how many documents match each filter
      const [projectCount, taskCount] = await Promise.all([
        Project.countDocuments(projectFilter),
        Task.countDocuments(taskFilter)
      ])

      console.log('🔥 Analytics API: Document counts:', {
        projectId,
        projectCount,
        taskCount,
        baseFilterProjectId: baseFilter.projectId?.toString()
      })

      // Execute comprehensive analytics queries in parallel with error handling
      const [
        projectOverview,
        teamMetrics,
        resourceMetrics,
        taskMetrics,
        riskAssessment
      ] = await Promise.allSettled([
        // Project Overview - if projectId is specified, get single project data
        projectId ? 
          Project.findById(projectId).lean() :
          Project.aggregate([
            { $match: projectFilter },
            {
              $group: {
                _id: null,
                totalProjects: { $sum: 1 },
                activeProjects: { $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } },
                completedProjects: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
                onHoldProjects: { $sum: { $cond: [{ $eq: ['$status', 'on-hold'] }, 1, 0] } },
                totalBudget: { $sum: '$budget' }
              }
            }
          ]),
        
        // Team Performance Analytics
        calculateTeamMetrics(projectId, departmentId, userId),
        
        // Resource Optimization Analytics
        calculateResourceMetrics(projectId, departmentId, userId),
        
        // Basic Task Metrics (for backward compatibility)
        Task.aggregate([
          { $match: taskFilter },
          {
            $group: {
              _id: null,
              totalTasks: { $sum: 1 },
              completedTasks: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
              inProgressTasks: { $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] } },
              pendingTasks: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
              overdueTasks: { 
                $sum: { 
                  $cond: [
                    { 
                      $and: [
                        { $ne: ['$status', 'completed'] },
                        { $ne: ['$status', 'cancelled'] },
                        { $ne: ['$status', 'closed'] },
                        { $ne: ['$status', 'deleted'] },
                        { $ne: ['$dueDate', null] },
                        { $lt: ['$dueDate', new Date()] }
                      ]
                    }, 
                    1, 
                    0
                  ] 
                }
              }
            }
          }
        ]),
        
        // Enhanced Risk Assessment
        getRiskAssessment(projectId)
      ])

      // Extract results from Promise.allSettled, providing fallbacks for failed promises
      const getSettledValue = (result: any, fallback: any) => {
        return result.status === 'fulfilled' ? result.value : fallback
      }

      const projectOverviewData = getSettledValue(projectOverview, null)
      const teamMetricsData = getSettledValue(teamMetrics, { departments: [], individuals: [], summary: { totalDepartments: 0, totalTeamMembers: 0, avgDepartmentProductivity: 0, avgIndividualProductivity: 0 } })
      const resourceMetricsData = getSettledValue(resourceMetrics, { budget: { utilization: 0 }, hours: { efficiency: 100 }, summary: { overallEfficiency: 100, budgetHealth: 'good', resourceHealth: 'good' } })
      const taskMetricsData = getSettledValue(taskMetrics, [{}])
      const riskAssessmentData = getSettledValue(riskAssessment, [])

      // Log any failed analytics for debugging
      const failures = [projectOverview, teamMetrics, resourceMetrics, taskMetrics, riskAssessment]
        .filter(result => result.status === 'rejected')
        .map(result => result.reason)
      
      if (failures.length > 0) {
        console.warn('Some analytics calculations failed:', failures)
      }

      // Transform data based on whether we're looking at a specific project or general overview
      const overviewData = projectId && projectOverviewData && !Array.isArray(projectOverviewData) ? {
        // Single project data
        totalProjects: 1,
        activeProjects: projectOverviewData.status === 'active' ? 1 : 0,
        completedProjects: projectOverviewData.status === 'completed' ? 1 : 0,
        onHoldProjects: projectOverviewData.status === 'on-hold' ? 1 : 0,
        averageProgress: 0, // Will be calculated from tasks
        totalBudget: projectOverviewData.budget || 0,
        totalSpent: 0 // Not available
      } : (Array.isArray(projectOverviewData) ? projectOverviewData[0] : null) || {
        totalProjects: 0,
        activeProjects: 0,
        completedProjects: 0,
        onHoldProjects: 0,
        averageProgress: 0,
        totalBudget: 0,
        totalSpent: 0
      }

      // Calculate key performance indicators
      const taskData = taskMetricsData[0] || {
        totalTasks: 0,
        completedTasks: 0,
        inProgressTasks: 0,
        pendingTasks: 0,
        overdueTasks: 0
      }

      const kpiMetrics = {
        taskCompletion: taskData.totalTasks > 0 ? Math.round((taskData.completedTasks / taskData.totalTasks) * 100) : 0,
        budgetUtilization: resourceMetricsData.budget?.utilization || 0,
        budgetEfficiency: resourceMetricsData.budget?.efficiency || 100,
        teamProductivity: teamMetricsData.summary?.avgIndividualProductivity || 0,
        overallHealth: Math.round([
          taskData.totalTasks > 0 ? (taskData.completedTasks / taskData.totalTasks) * 100 : 100,
          Math.max(0, 100 - Math.abs((resourceMetricsData.budget?.utilization || 0) - 85)),
          resourceMetricsData.budget?.efficiency || 100,
          teamMetricsData.summary?.avgIndividualProductivity || 85
        ].reduce((sum, val) => sum + val, 0) / 4)
      }

      const responseData = {
        overview: overviewData,
        kpi: kpiMetrics,
        
        // Team Performance Analytics
        team: teamMetricsData,
        
        // Resource Optimization
        resources: resourceMetricsData,
        
        // Enhanced Risk Assessment
        risks: riskAssessmentData,
        
        // Collaboration Metrics
        collaboration: {
          departmentCollaboration: teamMetricsData.departments?.length || 0,
          crossDepartmentTasks: taskData.totalTasks,
          communicationScore: Math.min(100, Math.max(0, 85 - (riskAssessmentData?.length || 0) * 10))
        },
        
        // AI-Powered Insights
        insights: generateInsights(teamMetricsData, resourceMetricsData, riskAssessmentData, taskData),
        
        // Backward compatibility - basic metrics
        tasks: taskData,
        
        meta: {
          dateRange,
          startDate: startDate.toISOString(),
          endDate: endDate.toISOString(),
          projectId,
          generatedAt: new Date().toISOString(),
          userRole: user.role?.name,
          userId: user._id || user.id,
          analyticsVersion: '2.0'
        }
      }

      console.log("resourceMetricsData 325",resourceMetricsData);

      // Return result for caching
      return responseData
    }, cacheKey, CACHE_TTL)

    return NextResponse.json({
      success: true,
      data: result,
      message: 'Analytics data retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error in GET /api/analytics:', error)

    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }

    return createAPIErrorResponse("Internal server error", 500)
  }

  } 

// Helper function: Calculate comprehensive team metrics from project data
async function calculateTeamMetrics(projectId?: string, departmentId?: string, userId?: string) {
  const Project = mongoose.model('Project')
  const Task = mongoose.model('Task')
  const Department = mongoose.model('Department')
  
  // Get basic project data (no invalid populate)
  const project: any = projectId ? 
    await Project.findById(projectId)
      .populate('departmentIds', 'name')
      .lean() : null
      
  if (projectId && !project) {
    throw new Error('Project not found')
  }

  const filter: any = {}
  if (projectId) {
    filter.projectId = new mongoose.Types.ObjectId(projectId)
  }
  if (departmentId) {
    filter.departmentId = new mongoose.Types.ObjectId(departmentId)
  }
  if (userId) {
    filter.assigneeId = new mongoose.Types.ObjectId(userId)
  }

  // Get all tasks for analysis with proper population
  const allTasks = await Task.find(filter)
    .populate('assigneeId', 'name email avatar role department')
    .populate('departmentId', 'name')
    .lean()

  // Department performance analysis
  const departmentMetrics = new Map()
  const individualMetrics = new Map()
  
  // Create department metrics from task data
  try {
    allTasks.forEach((task: any) => {
      const deptId = task.departmentId?._id?.toString() || task.departmentId?.toString() || 'unassigned'
      const deptName = task.departmentId?.name || 'Unassigned'
      
      // Department metrics
      const existing = departmentMetrics.get(deptId) || {
        id: deptId,
        name: deptName,
        totalTasks: 0,
        completedTasks: 0,
        overdueTasks: 0,
        completionRate: 0,
        productivity: 85,
        avgCompletionTime: 0,
        teamMembers: new Set(),
        efficiency: 100
      }
      
      // Ensure teamMembers is always a Set
      if (!(existing.teamMembers instanceof Set)) {
        existing.teamMembers = new Set()
      }
      
      existing.totalTasks += 1
      if (task.status === 'completed') existing.completedTasks += 1
      if (task.dueDate && new Date(task.dueDate) < new Date() && task.status !== 'completed') {
        existing.overdueTasks += 1
      }
      if (task.assigneeId) {
        const memberId = task.assigneeId._id?.toString() || task.assigneeId.toString()
        existing.teamMembers.add(memberId)
      }
      
      // Calculate average completion time for completed tasks
      if (task.status === 'completed' && task.completedAt && task.createdAt) {
        const completionDays = (new Date(task.completedAt).getTime() - new Date(task.createdAt).getTime()) / (1000 * 60 * 60 * 24)
        existing.avgCompletionTime = existing.avgCompletionTime > 0 ? 
          (existing.avgCompletionTime + completionDays) / 2 : completionDays
      }
      
      existing.completionRate = existing.totalTasks > 0 ? Math.round((existing.completedTasks / existing.totalTasks) * 100) : 0
      existing.efficiency = existing.totalTasks > 0 ? Math.max(0, Math.round((1 - existing.overdueTasks / existing.totalTasks) * 100)) : 100
      existing.productivity = Math.min(100, Math.max(0, (existing.completionRate + existing.efficiency) / 2))
      
      departmentMetrics.set(deptId, {
        ...existing,
        teamMembers: existing.teamMembers.size,
        avgCompletionTime: Math.round((existing.avgCompletionTime || 0) * 10) / 10
      })
      
      // Individual team member metrics
      if (task.assigneeId) {
        const assignee = task.assigneeId
        const memberId = assignee._id?.toString() || assignee.toString()
        
        if (memberId && assignee.name) {
          const individualExisting = individualMetrics.get(memberId) || {
            id: memberId,
            name: assignee.name || 'Unknown',
            email: assignee.email || '',
            avatar: assignee.avatar || '',
            role: assignee.role?.name || 'Team Member',
            department: assignee.department?.name || deptName,
            totalTasks: 0,
            completedTasks: 0,
            overdueTasks: 0,
            completionRate: 0,
            productivity: 85,
            efficiency: 100
          }
          
          individualExisting.totalTasks += 1
          if (task.status === 'completed') individualExisting.completedTasks += 1
          if (task.dueDate && new Date(task.dueDate) < new Date() && task.status !== 'completed') {
            individualExisting.overdueTasks += 1
          }
          
          individualExisting.completionRate = individualExisting.totalTasks > 0 ? 
            Math.round((individualExisting.completedTasks / individualExisting.totalTasks) * 100) : 0
          individualExisting.efficiency = individualExisting.totalTasks > 0 ? 
            Math.max(0, Math.round((1 - individualExisting.overdueTasks / individualExisting.totalTasks) * 100)) : 100
          individualExisting.productivity = Math.min(100, Math.max(0, (individualExisting.completionRate + individualExisting.efficiency) / 2))
          
          individualMetrics.set(memberId, individualExisting)
        }
      }
    })
  } catch (error) {
    console.error('Error calculating team metrics:', error)
    // Continue with empty metrics instead of failing
  }
  


  return {
    departments: Array.from(departmentMetrics.values()),
    individuals: Array.from(individualMetrics.values()),
    summary: {
      totalDepartments: departmentMetrics.size,
      totalTeamMembers: individualMetrics.size,
      avgDepartmentProductivity: departmentMetrics.size > 0 ? 
        Math.round(Array.from(departmentMetrics.values()).reduce((sum, d) => sum + d.productivity, 0) / departmentMetrics.size) : 0,
      avgIndividualProductivity: individualMetrics.size > 0 ? 
        Math.round(Array.from(individualMetrics.values()).reduce((sum, i) => sum + i.productivity, 0) / individualMetrics.size) : 0
    }
  }
}

// Helper function: Calculate resource optimization metrics
async function calculateResourceMetrics(projectId?: string, departmentId?: string, userId?: string) {
  const Project = mongoose.model('Project')
  const Task = mongoose.model('Task')
  
  const filter: any = {}
  if (projectId) {
    filter.projectId = new mongoose.Types.ObjectId(projectId)
  }
  if (departmentId) {
    filter.departmentId = new mongoose.Types.ObjectId(departmentId)
  }
  if (userId) {
    filter.assigneeId = new mongoose.Types.ObjectId(userId)
  }

  const [project, tasks] = await Promise.all([
    projectId ? Project.findById(projectId).lean() as Promise<any> : Promise.resolve(null),
    Task.find(filter).lean()
  ])

  // Budget analysis
  const projectBudget = project?.budget || 0
  const budgetBreakdown = project?.budgetBreakdown || {}
  const totalAllocated = Object.values(budgetBreakdown).reduce((sum: number, val: any) => sum + (val || 0), 0)
  
  // Hour efficiency tracking
  const totalEstimatedHours = tasks.reduce((sum, t) => sum + (t.estimatedHours || 0), 0)
  const totalActualHours = tasks.reduce((sum, t) => sum + (t.actualHours || 0), 0)
  const completedTasks = tasks.filter(t => t.status === 'completed')
  const completedEstimatedHours = completedTasks.reduce((sum, t) => sum + (t.estimatedHours || 0), 0)
  const completedActualHours = completedTasks.reduce((sum, t) => sum + (t.actualHours || 0), 0)
  
  // Resource utilization
  const assignedTasks = tasks.filter(t => t.assigneeId)
  const unassignedTasks = tasks.filter(t => !t.assigneeId)
  const utilizationRate = tasks.length > 0 ? Math.round((assignedTasks.length / tasks.length) * 100) : 100
  
  // Efficiency calculations
  const hourEfficiency = completedEstimatedHours > 0 
    ? Math.min(200, Math.max(0, Math.round((completedActualHours / completedEstimatedHours) * 100)))
    : 100
  
  // Budget utilization: how much of the allocated budget is actually used
  // Since we don't have actual costs, we'll use estimated hours vs allocated budget as proxy
  const budgetUtilization = projectBudget > 0 ? Math.round((totalAllocated / projectBudget) * 100) : 0
  
  // Budget efficiency: for completed tasks, how well we estimated vs actual
  const budgetEfficiency = completedEstimatedHours > 0 
    ? Math.min(200, Math.max(0, Math.round((completedActualHours / completedEstimatedHours) * 100)))
    : 100

  return {
    budget: {
      total: projectBudget,
      allocated: totalAllocated,
      utilization: budgetUtilization,
      efficiency: budgetEfficiency,
      variance: projectBudget > 0 ? Math.round(((totalAllocated - projectBudget) / projectBudget) * 100) : 0,
      breakdown: budgetBreakdown
    },
    hours: {
      totalEstimated: totalEstimatedHours,
      totalActual: totalActualHours,
      completedEstimated: completedEstimatedHours,
      completedActual: completedActualHours,
      efficiency: hourEfficiency,
      variance: totalEstimatedHours > 0 ? Math.round(((totalActualHours - totalEstimatedHours) / totalEstimatedHours) * 100) : 0
    },
    utilization: {
      assignedTasks: assignedTasks.length,
      unassignedTasks: unassignedTasks.length,
      utilizationRate,
      totalTasks: tasks.length
    },
    summary: {
      overallEfficiency: Math.round((hourEfficiency + Math.max(0, 100 - Math.abs(budgetUtilization - 100))) / 2),
      budgetHealth: budgetUtilization <= 100 ? 'good' : budgetUtilization <= 110 ? 'warning' : 'critical',
      resourceHealth: utilizationRate >= 90 ? 'good' : utilizationRate >= 70 ? 'warning' : 'critical'
    }
  }
}

// Helper function: Get project overview
async function getProjectOverview(projectId?: string, user?: any) {
  const filter: any = {}
  
  if (projectId) {
    filter._id = projectId
  } else if (user.departmentId && !['support', 'admin'].includes(user.department?.name?.toLowerCase())) {
    filter.departmentIds = user.departmentId
  }

  const projects = await Project.find(filter).lean()
  
  if (projectId && projects.length === 0) {
    throw new Error('Project not found')
  }

  const totalProjects = projects.length
  const activeProjects = projects.filter(p => p.status === 'active').length
  const completedProjects = projects.filter(p => p.status === 'completed').length
  const pendingProjects = projects.filter(p => p.status === 'pending').length

  const totalBudget = projects.reduce((sum, p) => {
    const breakdown = p.budgetBreakdown || {}
    return sum + (breakdown.development || 0) + (breakdown.design || 0) + 
           (breakdown.testing || 0) + (breakdown.deployment || 0) + 
           (breakdown.maintenance || 0) + (breakdown.contingency || 0)
  }, 0)

  return {
    totalProjects,
    activeProjects,
    completedProjects,
    pendingProjects,
    totalBudget,
    completionRate: totalProjects > 0 ? Math.round((completedProjects / totalProjects) * 100) : 0
  }
}

// Helper function: Get task metrics
async function getTaskMetrics(baseFilter: any) {
  const taskFilter = { ...baseFilter }
  delete taskFilter.createdAt // Remove date filter for current status

  const [tasks, recentTasks] = await Promise.all([
    Task.find(taskFilter).lean(),
    Task.find(baseFilter).lean()
  ])

  const totalTasks = tasks.length
  const completedTasks = tasks.filter(t => t.status === 'completed').length
  const inProgressTasks = tasks.filter(t => t.status === 'in-progress').length
  const pendingTasks = tasks.filter(t => t.status === 'pending').length
  const onHoldTasks = tasks.filter(t => t.status === 'on-hold').length
  
  const overdueTasks = tasks.filter(t => 
    t.dueDate && t.dueDate < new Date() && t.status !== 'completed'
  ).length

  const totalEstimatedHours = tasks.reduce((sum, t) => sum + (t.estimatedHours || 0), 0)
  const totalActualHours = tasks.reduce((sum, t) => sum + (t.actualHours || 0), 0)

  return {
    totalTasks,
    completedTasks,
    inProgressTasks,
    pendingTasks,
    onHoldTasks,
    overdueTasks,
    totalEstimatedHours,
    totalActualHours,
    completionRate: totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0,
    efficiencyRate: totalEstimatedHours > 0 ? Math.round((totalEstimatedHours / totalActualHours) * 100) : 100,
    recentTasksCreated: recentTasks.length
  }
}

// Helper function: Get performance data
async function getPerformanceData(baseFilter: any, startDate: Date, endDate: Date) {
  // Task completion velocity (tasks completed per day)
  const completedTasks = await Task.find({
    ...baseFilter,
    status: 'completed',
    completedAt: { $gte: startDate, $lte: endDate }
  }).lean()

  const daysDiff = Math.ceil((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24))
  const velocity = completedTasks.length / daysDiff

  // Average task duration
  const tasksWithDuration = completedTasks.filter(t => t.completedAt && t.createdAt)
  const averageTaskDuration = tasksWithDuration.length > 0 ? 
    tasksWithDuration.reduce((sum, t) => {
      const duration = (new Date(t.completedAt!).getTime() - new Date(t.createdAt).getTime()) / (1000 * 60 * 60 * 24)
      return sum + duration
    }, 0) / tasksWithDuration.length : 0

  // Team productivity (tasks per team member)
  const teamMembers = [...new Set(completedTasks.map(t => t.assigneeId?.toString()).filter(Boolean))]
  const productivity = teamMembers.length > 0 ? completedTasks.length / teamMembers.length : 0

  return {
    velocity: Math.round(velocity * 100) / 100,
    averageTaskDuration: Math.round(averageTaskDuration * 100) / 100,
    productivity: Math.round(productivity * 100) / 100,
    activeTeamMembers: teamMembers.length
  }
}

// Helper function: Get trends data
async function getTrendsData(baseFilter: any, startDate: Date, endDate: Date, dateRange: string) {
  // Determine grouping interval based on date range
  const groupInterval = dateRange === '7d' ? 'day' : dateRange === '30d' ? 'day' : 'week'
  
  // Task completion trends
  const taskTrends = await Task.aggregate([
    {
      $match: {
        ...baseFilter,
        completedAt: { $gte: startDate, $lte: endDate }
      }
    },
    {
      $group: {
        _id: {
          $dateToString: {
            format: groupInterval === 'day' ? '%Y-%m-%d' : '%Y-%U',
            date: '$completedAt'
          }
        },
        completed: { $sum: 1 },
        totalHours: { $sum: { $ifNull: ['$actualHours', 0] } }
      }
    },
    { $sort: { _id: 1 } }
  ])


  return {
    tasks: taskTrends,
  }
}

// Helper function: Generate AI-powered insights
function generateInsights(teamMetrics: any, resourceMetrics: any, risks: any[], taskData: any) {
  const insights = []

  // Team Performance Insights
  if (teamMetrics.summary.avgIndividualProductivity > 85) {
    insights.push({
      type: 'success',
      category: 'team',
      title: 'High Team Productivity',
      description: `Your team is performing exceptionally well with ${teamMetrics.summary.avgIndividualProductivity}% average productivity.`,
      recommendation: 'Consider recognizing top performers and sharing best practices across departments.'
    })
  } else if (teamMetrics.summary.avgIndividualProductivity < 60) {
    insights.push({
      type: 'warning',
      category: 'team',
      title: 'Team Productivity Needs Attention',
      description: `Team productivity is at ${teamMetrics.summary.avgIndividualProductivity}%, which is below optimal levels.`,
      recommendation: 'Review workload distribution and provide additional support or training to struggling team members.'
    })
  }

  // Budget Insights
  const budgetUtilization = resourceMetrics.budget.utilization
  if (budgetUtilization > 0 && budgetUtilization <= 85) {
    insights.push({
      type: 'success',
      category: 'budget',
      title: 'Optimal Budget Utilization',
      description: `Budget utilization is at ${budgetUtilization}%, indicating efficient resource management.`,
      recommendation: 'Continue current budget management practices and consider reallocating unused budget to high-impact areas.'
    })
  } else if (budgetUtilization > 100) {
    insights.push({
      type: 'critical',
      category: 'budget',
      title: 'Budget Overrun Alert',
      description: `Budget utilization has exceeded 100% at ${budgetUtilization}%.`,
      recommendation: 'Immediately review expenses and consider cost reduction measures or budget reallocation.'
    })
  }

  // Resource Efficiency Insights
  if (resourceMetrics.hours.efficiency > 90) {
    insights.push({
      type: 'success',
      category: 'efficiency',
      title: 'High Hour Efficiency',
      description: `Team is completing tasks ${resourceMetrics.hours.efficiency}% efficiently compared to estimates.`,
      recommendation: 'Your estimation and execution are well-aligned. Use these metrics to improve future project planning.'
    })
  } else if (resourceMetrics.hours.efficiency < 70) {
    insights.push({
      type: 'warning',
      category: 'efficiency',
      title: 'Hour Efficiency Concern',
      description: `Hour efficiency is at ${resourceMetrics.hours.efficiency}%, indicating tasks are taking longer than estimated.`,
      recommendation: 'Review task complexity, provide additional training, or adjust estimation methods.'
    })
  }

  // Risk-Based Insights
  const criticalRisks = risks.filter(r => r.level === 'critical' || r.level === 'high')
  if (criticalRisks.length > 0) {
    insights.push({
      type: 'critical',
      category: 'risk',
      title: 'Critical Risks Identified',
      description: `${criticalRisks.length} high-priority risks require immediate attention.`,
      recommendation: 'Address critical risks immediately to prevent project delays or failures.'
    })
  }

  // Task Distribution Insights
  const taskCompletionRate = taskData.totalTasks > 0 ? (taskData.completedTasks / taskData.totalTasks) * 100 : 0
  if (taskCompletionRate > 80) {
    insights.push({
      type: 'success',
      category: 'tasks',
      title: 'Strong Task Completion',
      description: `${Math.round(taskCompletionRate)}% of tasks have been completed successfully.`,
      recommendation: 'Maintain current momentum and ensure quality standards are met in remaining tasks.'
    })
  }

  return insights
}

// Helper function: Enhanced risk assessment
async function getRiskAssessment(projectId?: string) {
  const Task = mongoose.model('Task')
  
  const filter: any = {}
  if (projectId) {
    filter.projectId = new mongoose.Types.ObjectId(projectId)
  }

  const tasks = await Task.find(filter).lean()

  const risks = []
  const now = new Date()

  // Timeline risk analysis (only tasks)
  const overdueItems = tasks.filter(t => t.dueDate && t.dueDate < now && t.status !== 'completed')

  if (overdueItems.length > 0) {
    const totalItems = tasks.length
    const overduePercentage = (overdueItems.length / totalItems) * 100
    const severity = overduePercentage > 25 ? 'critical' : overduePercentage > 15 ? 'high' : 
                    overduePercentage > 5 ? 'medium' : 'low'
    
    risks.push({
      id: 'timeline-delay',
      type: 'timeline',
      level: severity,
      description: `${overdueItems.length} tasks (${Math.round(overduePercentage)}%) are overdue`,
      impact: 'Project timeline may be delayed, affecting client satisfaction and delivery commitments',
      mitigation: 'Prioritize overdue tasks, reallocate resources, and adjust project timeline if necessary',
      probability: 'high',
      affectedAreas: ['Timeline', 'Client Relations', 'Team Morale']
    })
  }

  // Quality risk assessment
  const totalTasks = tasks.length
  const completedTasks = tasks.filter(t => t.status === 'completed').length
  const completionRate = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 100
  const inProgressTasks = tasks.filter(t => t.status === 'in-progress').length

  if (completionRate < 70 || (inProgressTasks / totalTasks) > 0.4) {
    const severity = completionRate < 50 ? 'high' : 'medium'
    risks.push({
      id: 'quality-concern',
      type: 'quality',
      level: severity,
      description: `Task completion rate is ${Math.round(completionRate)}% with ${inProgressTasks} tasks in progress`,
      impact: 'Project quality may be compromised due to scattered focus and low completion rate',
      mitigation: 'Focus on completing existing tasks before adding new ones, implement quality checkpoints',
      probability: completionRate < 60 ? 'high' : 'medium',
      affectedAreas: ['Quality', 'Client Satisfaction', 'Team Focus']
    })
  }

  // Resource allocation risk
  const unassignedTasks = tasks.filter(t => !t.assigneeId && t.status !== 'completed').length
  const unassignedPercentage = totalTasks > 0 ? (unassignedTasks / totalTasks) * 100 : 0
  const teamMembers = [...new Set(tasks.map(t => t.assigneeId?.toString()).filter(Boolean))]

  if (unassignedPercentage > 15) {
    const severity = unassignedPercentage > 30 ? 'high' : 'medium'
    risks.push({
      id: 'resource-allocation',
      type: 'resource',
      level: severity,
      description: `${unassignedTasks} tasks (${Math.round(unassignedPercentage)}%) are unassigned`,
      impact: 'Tasks may not be completed due to lack of clear ownership and accountability',
      mitigation: 'Assign tasks to appropriate team members and ensure balanced workload distribution',
      probability: 'high',
      affectedAreas: ['Task Completion', 'Accountability', 'Workload Balance']
    })
  }

  // Team capacity risk
  if (teamMembers.length > 0) {
    const avgTasksPerMember = totalTasks / teamMembers.length
    if (avgTasksPerMember > 15) {
      risks.push({
        id: 'team-overload',
        type: 'resource',
        level: avgTasksPerMember > 25 ? 'high' : 'medium',
        description: `Average ${Math.round(avgTasksPerMember)} tasks per team member may indicate overload`,
        impact: 'Team burnout and decreased quality due to excessive workload',
        mitigation: 'Consider additional resources or task redistribution to balance workload',
        probability: 'medium',
        affectedAreas: ['Team Morale', 'Quality', 'Productivity']
      })
    }
  }

  return risks
}