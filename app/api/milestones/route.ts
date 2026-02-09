import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery } from "@/lib/mongodb"
import Milestone from "@/models/Milestone"
import Project from "@/models/Project"
import Phase from "@/models/Phase"
import mongoose from "mongoose"
import { SecurityUtils } from "@/lib/security/validation"
import {
  createMilestoneSchema,
  milestoneQuerySchema,
} from "@/lib/validations/milestone"
import { getClientInfo } from "@/lib/security/error-handler"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { createAPIErrorResponse, createAPISuccessResponse } from "@/lib/utils/api-responses"

// Cache TTL for milestone queries
const CACHE_TTL = 5 * 60 * 1000 // 5 minutes

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/milestones - List milestones with pagination, search, and filters
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions) with filtering
    const { session, user, userEmail, isSuperAdmin, applyFilters } = await genericApiRoutesMiddleware(request, 'milestones', 'read')
    console.log("🔍 Milestones API: Authenticated user details:", {
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

    console.log("🔍 Milestones API: Applied filters:", applyFilters)

    // Parse and validate query parameters
    const { searchParams } = new URL(request.url)
    const queryParams = Object.fromEntries(searchParams.entries())

    const validation = milestoneQuerySchema.safeParse(queryParams)
    if (!validation.success) {
      return createErrorResponse("Invalid query parameters", 400, {
        errors: validation.error.errors
      })
    }

    const { page, limit, projectId, phaseId, status, priority, assigneeId, dueDateFrom, dueDateTo, sortBy, sortOrder } = validation.data

    // Generate user-specific cache key to prevent cross-user cache pollution
    const userCacheIdentifier = isSuperAdmin ? 'superadmin' : `user_${user._id || user.id}_${user.role?.name || 'no_role'}_${user.department || 'no_dept'}`
    const cacheKey = `milestones:${userCacheIdentifier}:${page}:${limit}:${projectId}:${phaseId}:${status}:${priority}:${sortBy}:${sortOrder}`

    // Execute database query with optimized connection and caching
    const result = await executeGenericDbQuery(async () => {
      // Ensure models are registered
      if (!mongoose.models.Project) {
        require('@/models/Project')
      }
      if (!mongoose.models.Phase) {
        require('@/models/Phase')
      }
      if (!mongoose.models.User) {
        require('@/models/User')
      }

      // Build secure and optimized query
      const filter: any = { isDeleted: false }

      // Apply filters securely
      if (projectId && projectId !== 'all') {
        if (mongoose.Types.ObjectId.isValid(projectId)) {
          filter.projectId = projectId
        } else {
          filter.projectId = new mongoose.Types.ObjectId()
        }
      }

      if (phaseId && phaseId !== 'all') {
        if (mongoose.Types.ObjectId.isValid(phaseId)) {
          filter.phaseId = phaseId
        } else {
          filter.phaseId = new mongoose.Types.ObjectId()
        }
      }

      if (status) filter.status = status
      if (priority) filter.priority = priority

      if (assigneeId && assigneeId !== 'all') {
        if (mongoose.Types.ObjectId.isValid(assigneeId)) {
          filter.assigneeId = assigneeId
        } else {
          filter.assigneeId = new mongoose.Types.ObjectId()
        }
      }

      // Date range filters
      if (dueDateFrom || dueDateTo) {
        filter.dueDate = {}
        if (dueDateFrom) {
          filter.dueDate.$gte = new Date(dueDateFrom)
        }
        if (dueDateTo) {
          filter.dueDate.$lte = new Date(dueDateTo)
        }
      }

      // Optimized sort with compound index support
      const sort: any = {}
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1

      console.log('🔥 Milestones API: About to apply filters:', {
        originalQuery: filter,
        isSuperAdmin,
        userEmail: userEmail,
        userId: user._id || user.id,
        userDepartment: user.department,
        userRole: user.role?.name,
        applyFiltersType: typeof applyFilters,
        userPermissions: user.permissions?.length || user.role?.permissions?.length || 0
      })

      // 🔥 Apply permission-based filters - THIS IS THE KEY CHANGE
      const filteredQuery = await applyFilters(filter)

      console.log('🔥 Milestones API: Query filtering applied:', {
        isSuperAdmin,
        originalQuery: filter,
        filteredQuery,
        wasFiltered: JSON.stringify(filteredQuery) !== JSON.stringify(filter),
        userPermissions: user.role?.permissions?.map((p: any) => ({
          resource: p.resource,
          conditions: p.conditions
        })) || user.permissions?.map((p: any) => ({
          resource: p.resource,
          conditions: p.conditions
        }))
      })

      // Parallel execution with optimized projections and population
      const [milestones, total, stats] = await Promise.all([
        Milestone.find(filteredQuery) // 🔥 Using filtered query
          .select('title description projectId phaseId dueDate status priority assigneeId progress tags createdBy createdAt updatedAt')
          .populate({
            path: 'projectId',
            select: 'name status'
          })
          .populate({
            path: 'phaseId',
            select: 'title order'
          })
          .populate({
            path: 'assigneeId',
            select: 'name email avatar'
          })
          .populate({
            path: 'createdBy',
            select: 'name email'
          })
          .sort(sort)
          .skip((page - 1) * limit)
          .limit(limit)
          .lean()
          .exec(),
        Milestone.countDocuments(filteredQuery).exec(), // 🔥 Using filtered query
        Milestone.aggregate([
          { $match: filteredQuery }, // 🔥 Using filtered query for stats too
          {
            $group: {
              _id: null,
              totalMilestones: { $sum: 1 },
              pendingMilestones: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
              inProgressMilestones: { $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] } },
              completedMilestones: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
              blockedMilestones: { $sum: { $cond: [{ $eq: ['$status', 'blocked'] }, 1, 0] } },
              overdueMilestones: { 
                $sum: { 
                  $cond: [
                    { 
                      $and: [
                        { $ne: ['$status', 'completed'] },
                        { $lt: ['$dueDate', new Date()] }
                      ]
                    }, 
                    1, 
                    0
                  ] 
                }
              },
              averageProgress: { $avg: '$progress' }
            }
          }
        ])
      ])

      const responseData = {
        milestones,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        },
        stats: stats[0] || {
          totalMilestones: 0,
          pendingMilestones: 0,
          inProgressMilestones: 0,
          completedMilestones: 0,
          blockedMilestones: 0,
          overdueMilestones: 0,
          averageProgress: 0
        }
      }

      // Return result for caching by cachedQuery
      return responseData
    }, cacheKey, CACHE_TTL)

    return NextResponse.json({
      success: true,
      data: result,
      message: 'Milestones retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error in GET /api/milestones:', error)

    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }

    return createAPIErrorResponse("Internal server error", 500)
  }
}

// POST /api/milestones - Create new milestone
export async function POST(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: currentUser, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'create')

    // Parse and validate request body
    const body = await request.json()
    console.log('Milestone creation request body:', body)

    const validation = createMilestoneSchema.safeParse(body)
    console.log('Milestone creation validation result:', validation)
    if (!validation.success) {
      return createErrorResponse("Validation failed", 400, {
        errors: validation.error.errors
      })
    }

    const validatedData = validation.data

    // Additional security checks
    const dataString = JSON.stringify(validatedData)
    if (SecurityUtils.containsSQLInjection && SecurityUtils.containsXSS) {
      if (SecurityUtils.containsSQLInjection(dataString) ||
        SecurityUtils.containsXSS(dataString)) {
        console.log('Malicious milestone creation attempt:', {
          userId: session.user.email,
          ip: getClientInfo(request).ipAddress,
          attemptedData: 'REDACTED_FOR_SECURITY'
        })
        return createErrorResponse("Invalid data detected", 400)
      }
    }

    // Execute milestone creation with database connection
    const result = await executeGenericDbQuery(async () => {
      // Check if project exists and user has access
      const project = await Project.findById(validatedData.projectId).lean()
      
      if (!project) {
        return createErrorResponse("Project not found", 404)
      }

      // Check if phase exists (if provided)
      if (validatedData.phaseId) {
        const phase = await Phase.findById(validatedData.phaseId).lean()
        if (!phase || phase.projectId.toString() !== validatedData.projectId) {
          return createErrorResponse("Phase not found or not part of the project", 404)
        }
      }

      // Create milestone with audit trail
      const { ipAddress: ip, userAgent } = getClientInfo(request)

      const milestoneData = {
        ...validatedData,
        createdBy: currentUser?._id || currentUser?.id || session.user?.id,
        updatedBy: currentUser?._id || currentUser?.id || session.user?.id,
        isDeleted: false,
        metadata: {
          createdBy: session.user.email || 'unknown',
          updatedBy: session.user.email || 'unknown',
        }
      }

      console.log('Creating milestone with data:', { 
        title: milestoneData.title, 
        projectId: milestoneData.projectId,
        phaseId: milestoneData.phaseId,
        createdBy: milestoneData.createdBy,
        userId: currentUser?._id || currentUser?.id || session.user?.id,
        userEmail: currentUser?.email || session.user?.email
      })

      const milestone = new Milestone(milestoneData)
      await milestone.save()

      // Clear relevant caches
      const { clearCache } = await import('@/lib/mongodb')
      clearCache('milestones') // Clear milestone-related cache

      // Prepare response with population
      const populatedMilestone = await Milestone.findById(milestone._id)
        .select('title description projectId phaseId dueDate status priority assigneeId progress tags createdBy createdAt updatedAt')
        .populate({
          path: 'projectId',
          select: 'name status'
        })
        .populate({
          path: 'phaseId',
          select: 'title order'
        })
        .populate({
          path: 'assigneeId',
          select: 'name email avatar'
        })
        .populate({
          path: 'createdBy',
          select: 'name email'
        })
        .lean()

      // Log successful milestone creation
      console.log('Milestone created successfully:', {
        createdBy: session.user.email,
        milestoneTitle: milestone.title,
        projectId: milestone.projectId,
        milestoneId: milestone._id,
        ip: getClientInfo(request).ipAddress
      })

      return populatedMilestone
    })

    return NextResponse.json({
      success: true,
      data: result,
      message: 'Milestone created successfully'
    }, { status: 201 })

  } catch (error: any) {
    console.error('Error in POST /api/milestones:', error)

    // Handle specific MongoDB errors
    if (error.code === 11000) {
      return createErrorResponse("Milestone with this title already exists in project", 409)
    }

    // Handle Mongoose validation errors
    if (error.name === 'ValidationError') {
      const validationErrors: any = {}
      for (const field in error.errors) {
        validationErrors[field] = error.errors[field].message
      }

      console.log('Validation error details:', validationErrors)

      return createErrorResponse("Validation failed", 400, {
        validationErrors
      })
    }

    return createErrorResponse("Failed to create milestone", 500)
  }
}