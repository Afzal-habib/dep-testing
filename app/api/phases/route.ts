import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery } from "@/lib/mongodb"
import Phase from "@/models/Phase"
import Project from "@/models/Project"
import mongoose from "mongoose"
import { SecurityUtils } from "@/lib/security/validation"
import {
  createPhaseSchema,
  phaseQuerySchema,
  reorderPhasesSchema,
} from "@/lib/validations/phase"
import { getClientInfo } from "@/lib/security/error-handler"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { createAPIErrorResponse, createAPISuccessResponse } from "@/lib/utils/api-responses"

// Cache TTL for phase queries
const CACHE_TTL = 5 * 60 * 1000 // 5 minutes

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/phases - List phases with pagination, search, and filters
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions) with filtering
    const { session, user, userEmail, isSuperAdmin, applyFilters } = await genericApiRoutesMiddleware(request, 'phases', 'read')
    console.log("🔍 Phases API: Authenticated user details:", {
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

    console.log("🔍 Phases API: Applied filters:", applyFilters)

    // Parse and validate query parameters
    const { searchParams } = new URL(request.url)
    const queryParams = Object.fromEntries(searchParams.entries())

    const validation = phaseQuerySchema.safeParse(queryParams)
    if (!validation.success) {
      return createErrorResponse("Invalid query parameters", 400, {
        errors: validation.error.errors
      })
    }

    const { page, limit, projectId, status, startDateFrom, startDateTo, endDateFrom, endDateTo, sortBy, sortOrder } = validation.data

    // Generate user-specific cache key to prevent cross-user cache pollution
    const userCacheIdentifier = isSuperAdmin ? 'superadmin' : `user_${user._id || user.id}_${user.role?.name || 'no_role'}_${user.department || 'no_dept'}`
    const cacheKey = `phases:${userCacheIdentifier}:${page}:${limit}:${projectId}:${status}:${sortBy}:${sortOrder}`

    // Execute database query with optimized connection and caching
    const result = await executeGenericDbQuery(async () => {
      // Ensure models are registered
      if (!mongoose.models.Project) {
        require('@/models/Project')
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

      if (status) filter.status = status

      // Date range filters
      if (startDateFrom || startDateTo) {
        filter.startDate = {}
        if (startDateFrom) {
          filter.startDate.$gte = new Date(startDateFrom)
        }
        if (startDateTo) {
          filter.startDate.$lte = new Date(startDateTo)
        }
      }

      if (endDateFrom || endDateTo) {
        filter.endDate = {}
        if (endDateFrom) {
          filter.endDate.$gte = new Date(endDateFrom)
        }
        if (endDateTo) {
          filter.endDate.$lte = new Date(endDateTo)
        }
      }

      // Optimized sort with compound index support
      const sort: any = {}
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1

      console.log('🔥 Phases API: About to apply filters:', {
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

      console.log('🔥 Phases API: Query filtering applied:', {
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
      const [phases, total, stats] = await Promise.all([
        Phase.find(filteredQuery) // 🔥 Using filtered query
          .select('title description projectId status priority startDate endDate progress order createdBy createdAt updatedAt approvedBy approvedAt actualStartDate actualEndDate')
          .populate({
            path: 'projectId',
            select: 'name status'
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
        Phase.countDocuments(filteredQuery).exec(), // 🔥 Using filtered query
        Phase.aggregate([
          { $match: filteredQuery }, // 🔥 Using filtered query for stats too
          {
            $group: {
              _id: null,
              totalPhases: { $sum: 1 },
              plannedPhases: { $sum: { $cond: [{ $eq: ['$status', 'planning'] }, 1, 0] } },
              activePhases: { $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] } },
              completedPhases: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
              onHoldPhases: { $sum: { $cond: [{ $eq: ['$status', 'on-hold'] }, 1, 0] } },
              averageProgress: { $avg: '$progress' }
            }
          }
        ])
      ])

      const responseData = {
        phases,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        },
        stats: stats[0] || {
          totalPhases: 0,
          plannedPhases: 0,
          activePhases: 0,
          completedPhases: 0,
          onHoldPhases: 0,
          averageProgress: 0
        }
      }

      // Return result for caching by cachedQuery
      return responseData
    }, cacheKey, CACHE_TTL)

    return NextResponse.json({
      success: true,
      data: result,
      message: 'Phases retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error in GET /api/phases:', error)

    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }

    return createAPIErrorResponse("Internal server error", 500)
  }
}

// POST /api/phases - Create new phase
export async function POST(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: currentUser, userEmail } = await genericApiRoutesMiddleware(request, 'phases', 'create')

    // Parse and validate request body
    const body = await request.json()
    console.log('Phase creation request body:', body)

    const validation = createPhaseSchema.safeParse(body)
    console.log('Phase creation validation result:', validation)
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
        console.log('Malicious phase creation attempt:', {
          userId: session.user.email,
          ip: getClientInfo(request).ipAddress,
          attemptedData: 'REDACTED_FOR_SECURITY'
        })
        return createErrorResponse("Invalid data detected", 400)
      }
    }

    // Execute phase creation with database connection
    const result = await executeGenericDbQuery(async () => {
      // Check if project exists and user has access
      const project = await Project.findById(validatedData.projectId).lean()
      
      if (!project) {
        return createErrorResponse("Project not found", 404)
      }

      // Get next order number for this project
      const lastPhase = await Phase.findOne({ 
        projectId: validatedData.projectId,
        isDeleted: false 
      }).sort({ order: -1 })
      
      const nextOrder = (lastPhase?.order || 0) + 1

      // Create phase with audit trail
      const { ipAddress: ip, userAgent } = getClientInfo(request)

      const phaseData = {
        ...validatedData,
        order: nextOrder,
        createdBy: currentUser?._id || currentUser?.id || session.user?.id,
        updatedBy: currentUser?._id || currentUser?.id || session.user?.id,
        isDeleted: false,
        metadata: {
          createdBy: session.user.email || 'unknown',
          updatedBy: session.user.email || 'unknown',
        }
      }

      console.log('Creating phase with data:', { 
        title: phaseData.title, 
        projectId: phaseData.projectId,
        createdBy: phaseData.createdBy,
        userId: currentUser._id,
        userEmail: currentUser.email 
      })

      const phase = new Phase(phaseData)
      await phase.save()

      // Clear relevant caches
      const { clearCache } = await import('@/lib/mongodb')
      clearCache('phases') // Clear phase-related cache

      // Prepare response with population
      const populatedPhase = await Phase.findById(phase._id)
        .select('title description projectId status priority startDate endDate progress order createdBy createdAt updatedAt')
        .populate({
          path: 'projectId',
          select: 'name status'
        })
        .populate({
          path: 'createdBy',
          select: 'name email'
        })
        .lean()

      // Log successful phase creation
      console.log('Phase created successfully:', {
        createdBy: session.user.email,
        phaseTitle: phase.title,
        projectId: phase.projectId,
        phaseId: phase._id,
        ip: getClientInfo(request).ipAddress
      })

      return populatedPhase
    })

    return NextResponse.json({
      success: true,
      data: result,
      message: 'Phase created successfully'
    }, { status: 201 })

  } catch (error: any) {
    console.error('Error in POST /api/phases:', error)

    // Handle specific MongoDB errors
    if (error.code === 11000) {
      return createErrorResponse("Phase with this title already exists in project", 409)
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

    return createErrorResponse("Failed to create phase", 500)
  }
}