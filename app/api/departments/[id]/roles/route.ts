import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery } from "@/lib/mongodb"
import Role, { type IRole } from "@/models/Role"
import Department, { type IDepartment } from "@/models/Department"
import User from "@/models/User"
import mongoose, { type Document } from "mongoose"
import { getClientInfo } from "@/lib/security/error-handler"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'



// Simple cache
const cache = new Map()
const CACHE_TTL = 3 * 60 * 1000 // 3 minutes


function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/departments/[id]/roles - Get all roles for a specific department
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'roles', 'read')

    const { id: departmentId } = await params

    // Validate Department ID
    if (!mongoose.Types.ObjectId.isValid(departmentId)) {
      return createErrorResponse('Invalid department ID', 400)
    }

    // Parse query parameters
    const { searchParams } = new URL(request.url)
    const includeInactive = searchParams.get('includeInactive') === 'true'
    const includeUserCount = searchParams.get('includeUserCount') === 'true'
    const sortBy = searchParams.get('sortBy') || 'hierarchyLevel'
    const sortOrder = searchParams.get('sortOrder') || 'desc'

    // Generate user-specific cache key to prevent cross-user contamination
    const userCacheIdentifier = `user_${user._id || user.id}_${user.role?.name || 'no_role'}`
    const cacheKey = `department_roles:${userCacheIdentifier}:${departmentId}:${includeInactive}:${includeUserCount}:${sortBy}:${sortOrder}`

    // Check cache
    const cached = cache.get(cacheKey)
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return NextResponse.json({
        success: true,
        ...cached.data,
        message: 'Department roles retrieved successfully (cached)'
      })
    }

    // Get department data with automatic connection management
    const responseData = await executeGenericDbQuery(async () => {
      // Verify department exists
      const department = await Department.findById(departmentId).lean() as (IDepartment & Document) | null
      if (!department) {
        throw new Error('Department not found')
      }

      // User info already extracted by middleware  
      const isSuperAdmin = user.role === 'super_admin';

      // For non-superadmin users, check if department is active
      if (!isSuperAdmin && department?.status !== 'active') {
        throw new Error('Department not accessible')
      }

      // Build query for roles
      const roleQuery: any = { department: departmentId }
      if (!includeInactive && !isSuperAdmin) {
        roleQuery.status = 'active'
      }

      // Build sort configuration
      const sort: any = {}
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1

      // Get roles with optional user count
      let rolesQuery = Role.find(roleQuery)
        .select('name displayName description hierarchyLevel maxUsers isSystemRole status validityPeriod createdAt updatedAt')
        .sort(sort)

      const roles = await rolesQuery.lean().exec()

      // Get user counts if requested
      let rolesWithUserCounts = roles
      if (includeUserCount) {
        const roleIds = roles.map(role => role._id)
        const userCounts = await User.aggregate([
          { $match: { role: { $in: roleIds } } },
          {
            $group: {
              _id: '$role',
              totalUsers: { $sum: 1 },
              activeUsers: { $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } },
              inactiveUsers: { $sum: { $cond: [{ $ne: ['$status', 'active'] }, 1, 0] } }
            }
          }
        ])

        const userCountMap = new Map(userCounts.map(count => [count._id.toString(), count]))

        rolesWithUserCounts = roles.map((role: any) => {
          const userCount = userCountMap.get(role?._id?.toString()) || { totalUsers: 0, activeUsers: 0, inactiveUsers: 0 }
          return {
            ...role,
            userCount: {
              total: userCount.totalUsers,
              active: userCount.activeUsers,
              inactive: userCount.inactiveUsers,
              utilizationRate: role.maxUsers ? Math.round((userCount.totalUsers / role.maxUsers) * 100) : null
            }
          }
        })
      }

      // Get department statistics
      const departmentStats = await Role.aggregate([
        { $match: { department: new mongoose.Types.ObjectId(departmentId), ...(isSuperAdmin ? {} : { status: 'active' }) } },
        {
          $group: {
            _id: null,
            totalRoles: { $sum: 1 },
            systemRoles: { $sum: { $cond: ['$isSystemRole', 1, 0] } },
            avgHierarchyLevel: { $avg: '$hierarchyLevel' },
            maxHierarchyLevel: { $max: '$hierarchyLevel' },
            minHierarchyLevel: { $min: '$hierarchyLevel' }
          }
        }
      ])

      return {
        department: {
          _id: department?._id,
          name: department?.name,
          description: department?.description,
          status: department?.status
        },
        // roles: rolesWithUserCounts,
        data: rolesWithUserCounts,
        statistics: departmentStats[0] || {
          totalRoles: 0,
          systemRoles: 0,
          avgHierarchyLevel: 0,
          maxHierarchyLevel: 0,
          minHierarchyLevel: 0
        }
      }
    }, cacheKey, CACHE_TTL)

    console.log('Roles query executed for department:', responseData);
    // Cache result
    cache.set(cacheKey, {
      data: responseData,
      timestamp: Date.now()
    })

    // Log access
    console.log('Department roles accessed:', {
      userId: userEmail,
      departmentId,
      departmentName: responseData.department?.name,
      roleCount: responseData.data?.length || 0,
      isSuperAdmin,
      ip: getClientInfo(request).ipAddress
    })

    return NextResponse.json({
      success: true,
      data: responseData.data, // Return roles directly for the frontend
      department: responseData.department,
      statistics: responseData.statistics,
      message: 'Department roles retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error in GET /api/departments/[id]/roles:', error)
    return createErrorResponse("Internal server error", 500)
  }
}

// POST /api/departments/[id]/roles - Create a new role for this department
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'roles', 'create')

    // User info already extracted by middleware
    const isSuperAdmin = user.role === 'super_admin';

    const { id: departmentId } = await params

    // Validate Department ID
    if (!mongoose.Types.ObjectId.isValid(departmentId)) {
      return createErrorResponse('Invalid department ID', 400)
    }

    // Verify department exists
    const department = await Department.findById(departmentId).lean() as (IDepartment & Document) | null
    if (!department) {
      return createErrorResponse('Department not found', 404)
    }

    // For non-superadmin users, check if department is active
    if (!isSuperAdmin && department?.status !== 'active') {
      return createErrorResponse('Department not found', 404)
    }

    // Get the request body and add the department ID
    const body = await request.json()
    const roleData = {
      ...body,
      department: departmentId
    }

    // Forward to the main roles API
    const rolesApiUrl = new URL('/api/roles', request.url)
    const roleResponse = await fetch(rolesApiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': request.headers.get('Authorization') || '',
        'Cookie': request.headers.get('Cookie') || '',
      },
      body: JSON.stringify(roleData)
    })

    const result = await roleResponse.json()

    // Clear cache for this department
    for (const key of cache.keys()) {
      if (key.startsWith(`department_roles:${departmentId}`)) {
        cache.delete(key)
      }
    }

    // Log role creation
    console.log('Role created for department:', {
      userId: userEmail,
      departmentId,
      departmentName: department?.name,
      roleName: roleData.name,
      isSuperAdmin,
      ip: getClientInfo(request).ipAddress
    })

    return NextResponse.json(result, { status: roleResponse.status })

  } catch (error: any) {
    console.error('Error in POST /api/departments/[id]/roles:', error)
    return createErrorResponse("Failed to create role", 500)
  }
}