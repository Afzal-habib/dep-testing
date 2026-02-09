import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Role, { type IRole } from "@/models/Role"
import Department, { type IDepartment } from "@/models/Department"
import { SecurityUtils } from "@/lib/security/validation"
import {
  roleQuerySchema,
  createRoleSchema,
} from "@/lib/validations/role"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import mongoose, { type Document } from "mongoose"
import { getClientInfo } from "@/lib/security/error-handler"
import { createAPIErrorResponse, createAPISuccessResponse } from "@/lib/utils/api-responses"
import { addSoftDeleteFilter } from "@/lib/utils/soft-delete"
import { createErrorResponse } from "@/lib/security/error-handler"




// Cache TTL for role queries
const CACHE_TTL = 5 * 60 * 1000 // 5 minutes


// Helper to create consistent error responses
// function createErrorResponse(message: string, status: number, details?: any) {
//   return NextResponse.json({
//     success: false,
//     error: message,
//     ...(details && { details })
//   }, { status })
// }

// GET /api/roles - List roles with pagination, search, and filters
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'roles', 'read')

    // Parse and validate query parameters
    const { searchParams } = new URL(request.url)
    const queryParams = Object.fromEntries(searchParams.entries())

    const validation = roleQuerySchema.safeParse(queryParams)
    if (!validation.success) {
      return createErrorResponse("Invalid query parameters", 400, {
        errors: validation.error.errors
      })
    }

    const validatedData = validation.data

    const { page, limit, search, department, hierarchyLevel, isSystemRole, status, sortBy, sortOrder } = validatedData

    // isSuperAdmin already available from middleware

    // Generate user-specific cache key to prevent cross-user contamination
    const userCacheIdentifier = isSuperAdmin ? 'superadmin' : `user_${user._id || user.id}_${user.role?.name || 'no_role'}`
    const cacheKey = `roles:${userCacheIdentifier}:${page}:${limit}:${search}:${department}:${hierarchyLevel}:${isSystemRole}:${status}:${sortBy}:${sortOrder}`

    // Execute database query with optimized connection and caching
    const result = await executeGenericDbQuery(async () => {
      // Ensure models are registered (fix for populate issues)
      if (!mongoose.models.Department) {
        require('@/models/Department')
      }

      // Build query with soft delete filter
      let query: any = {}

      // Apply soft delete filter - exclude deleted records unless super admin
      query = addSoftDeleteFilter(query, isSuperAdmin)

      // Only filter by status if it's explicitly provided, combining with soft delete filter
      if (status) {
        if (isSuperAdmin) {
          query.status = status
        } else {
          // For non-super admins, combine status filter with soft delete exclusion
          query.status = { $and: [{ $ne: 'deleted' }, { $eq: status }] }
        }
      }

      // Search implementation
      if (search) {
        const sanitizedSearch = SecurityUtils.sanitizeString(search)

        if (sanitizedSearch.length >= 2) {
          query.$text = { $search: sanitizedSearch }
        } else {
          query.$or = [
            { name: { $regex: sanitizedSearch, $options: 'i' } },
            { displayName: { $regex: sanitizedSearch, $options: 'i' } }
          ]
        }
      }

      // Apply filters
      if (department) {
        if (mongoose.Types.ObjectId.isValid(department)) {
          query.department = new mongoose.Types.ObjectId(department)
        }
      }
      if (hierarchyLevel !== undefined) {
        query.hierarchyLevel = hierarchyLevel
      }
      if (isSystemRole !== undefined) {
        query.isSystemRole = isSystemRole
      }

      // Sort configuration
      const sort: any = {}
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1

      // Execute parallel queries
      const [roles, total, departmentStats] = await Promise.all([
        Role.find(query)
          .populate('departmentDetails', 'name description')
          .populate('userCount')
          .select('name displayName description department permissions hierarchyLevel isSystemRole maxUsers validityPeriod status createdAt updatedAt')
          .sort(sort)
          .skip((page - 1) * limit)
          .limit(limit)
          .lean()
          .exec(),

        Role.countDocuments(query).exec(),

        Role.aggregate([
          { $match: addSoftDeleteFilter(status ? { status: status } : {}, isSuperAdmin) },
          {
            $group: {
              _id: '$department',
              roleCount: { $sum: 1 },
              avgHierarchyLevel: { $avg: '$hierarchyLevel' },
              activeRoles: {
                $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
              },
              inactiveRoles: {
                $sum: { $cond: [{ $eq: ['$status', 'inactive'] }, 1, 0] }
              }
            }
          },
          {
            $lookup: {
              from: 'departments',
              localField: '_id',
              foreignField: '_id',
              as: 'departmentInfo'
            }
          },
          { $unwind: '$departmentInfo' },
          {
            $project: {
              departmentId: '$_id',
              departmentName: '$departmentInfo.name',
              roleCount: 1,
              avgHierarchyLevel: { $round: ['$avgHierarchyLevel', 2] },
              activeRoles: 1,
              inactiveRoles: 1
            }
          }
        ])
      ])

      return {
        roles,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        },
        stats: {
          totalRoles: total,
          systemRoles: roles.filter((r: any) => r.isSystemRole).length,
          departmentRoles: roles.filter((r: any) => !r.isSystemRole).length,
          activeRoles: roles.filter((r: any) => r.status === 'active').length,
          inactiveRoles: roles.filter((r: any) => r.status === 'inactive').length,
          departmentStats
        }
      }
    }, cacheKey)

    // Log successful access
    console.log('Roles list accessed:', {
      userId: userEmail,
      page,
      limit,
      search: search || 'none',
      resultCount: result.roles.length,
      filters: { department, hierarchyLevel, isSystemRole },
      ip: getClientInfo(request).ipAddress
    })

    return createAPISuccessResponse(result, 'Roles retrieved successfully')

  } catch (error: any) {
    console.error('Error in GET /api/roles:', {
      message: error.message,
      stack: error.stack,
      name: error.name,
      timestamp: new Date().toISOString()
    })

    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }

    return createAPIErrorResponse("Internal server error", 500, "INTERNAL_ERROR", {
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    })
  }
}

// POST /api/roles - Create new role
export async function POST(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'roles', 'create')

    // User info already extracted by middleware
    // Parse and validate request body
    const body = await request.json()

    console.log('Role creation API: Received body:', JSON.stringify(body, null, 2));
    console.log('Role creation API: Permissions received:', JSON.stringify(body.permissions, null, 2));

    const validation = createRoleSchema.safeParse(body)
    if (!validation.success) {
      console.error('Role creation API: Validation failed:', validation.error.errors);
      return createErrorResponse("Validation failed", 400, {
        errors: validation.error.errors
      })
    }

    const validatedData = validation.data

    // Additional security checks - skip for structured data like permissions
    // Only check string fields that could contain user input

    const fieldsToCheck = [
      validatedData.name,
      validatedData.displayName,
      validatedData.description
    ].filter(Boolean).join(' ')

    console.log('Security check - Fields to check:', fieldsToCheck)

    if (SecurityUtils.containsSQLInjection && SecurityUtils.containsXSS) {
      const hasSQLInjection = SecurityUtils.containsSQLInjection(fieldsToCheck)
      const hasXSS = SecurityUtils.containsXSS(fieldsToCheck)

      console.log('Security check results:', { hasSQLInjection, hasXSS })

      if (hasSQLInjection || hasXSS) {
        console.log('Security threat detected in role creation:', {
          userId: userEmail,
          checkedFields: fieldsToCheck,
          hasSQLInjection,
          hasXSS,
          ip: getClientInfo(request).ipAddress
        })
        return createErrorResponse("Invalid data detected", 400)
      }
    }

    // Verify department exists
    const department = await executeGenericDbQuery(async () => {
      return await Department.findById(validatedData.department).lean()
    }) as (IDepartment & Document) | null
    if (!department) {
      return createErrorResponse("Department not found", 404)
    }

    // Prevent creating roles with deleted status
    if (validatedData.status === 'deleted') {
      return createErrorResponse("Cannot create roles with deleted status", 400)
    }

    // Check if role name already exists in the same department (exclude deleted roles)
    const existingRole = await executeGenericDbQuery(async () => {
      return await Role.findOne({
        name: validatedData.name,
        department: validatedData.department,
        status: { $ne: 'deleted' }
      }).lean()
    }) as (IRole & Document) | null

    if (existingRole) {
      console.log('Duplicate role creation attempt:', {
        userId: userEmail,
        roleName: validatedData.name,
        department: validatedData.department,
        ip: getClientInfo(request).ipAddress
      })
      return createErrorResponse("Role with this name already exists in the department", 409)
    }

    // Create role with audit trail
    const { ipAddress: ip, userAgent } = getClientInfo(request)
    const roleData = {
      ...validatedData,
      department: new mongoose.Types.ObjectId(validatedData.department),
      status: 'active',
      metadata: {
        createdBy: userEmail || 'unknown',
        createdAt: new Date(),
        userAgent,
        ip,
      }
    }

    const createdRole = await executeGenericDbQuery(async () => {
      const role = new Role(roleData)
      await role.save()
      return await role.populate('departmentDetails', 'name description')
    }, `role-create-${validatedData.name}-${validatedData.department}`)

    // Log successful role creation
    console.log('Role created successfully:', {
      createdBy: userEmail,
      roleId: createdRole._id,
      roleName: createdRole.name,
      department: department.name,
      hierarchyLevel: createdRole.hierarchyLevel,
      ip: getClientInfo(request).ipAddress
    })

    return NextResponse.json({
      success: true,
      data: { role: createdRole },
      message: 'Role created successfully'
    }, { status: 201 })

  } catch (error: any) {
    console.error('Error in POST /api/roles:', error)

    // Handle specific MongoDB errors
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0]
      return createErrorResponse(`Role with this ${field} already exists`, 409)
    }

    return createErrorResponse("Failed to create role", 500)
  }
}