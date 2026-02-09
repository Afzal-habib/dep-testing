import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery } from "@/lib/mongodb"
import SystemPermission from "@/models/SystemPermission"
import { z } from "zod"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'




// Cache for permissions - updated
const cache = new Map()
const CACHE_TTL = 10 * 60 * 1000 // 10 minutes (permissions don't change often)

function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// Query validation
const permissionQuerySchema = z.object({
  category: z.string().optional(),
  resource: z.string().optional(),
  includeInactive: z.string().optional().default('false').transform(val => val === 'true'),
})

// GET /api/system-permissions - Get all available system permissions
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'system-permissions', 'read')

    const { searchParams } = new URL(request.url)
    const queryParams = Object.fromEntries(searchParams.entries())
    console.log('System permissions API: Query params:', queryParams)

    const validation = permissionQuerySchema.safeParse(queryParams)
    if (!validation.success) {
      console.log('System permissions API: Validation failed:', validation.error.errors)
      return createErrorResponse("Invalid query parameters", 400, {
        errors: validation.error.errors
      })
    }

    const { category, resource, includeInactive } = validation.data
    console.log('System permissions API: Validated params:', { category, resource, includeInactive })

    // Generate user-specific cache key to prevent cross-user contamination
    const userCacheIdentifier = `user_${user._id || user.id}_${user.role?.name || 'no_role'}`
    const cacheKey = `system_permissions:${userCacheIdentifier}:${category}:${resource}:${includeInactive}`

    // Check cache
    const cached = cache.get(cacheKey)
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return NextResponse.json({
        success: true,
        ...cached.data,
        message: 'System permissions retrieved successfully (cached)'
      })
    }

    // Build query
    const filter: any = {}
    if (!includeInactive) {
      filter.status = 'active'
    }
    if (category) {
      filter.category = category.toLowerCase()
    }
    if (resource) {
      filter.resource = resource.toLowerCase()
    }

    // Get permissions with automatic connection management
    const permissions = await executeGenericDbQuery(async () => {
      return await SystemPermission.find(filter)
        .sort({ category: 1, displayName: 1 })
        .lean()
        .exec()
    }, `system-permissions-${cacheKey}`, 300000) // 5-minute cache

    console.log('System permissions API: Found permissions:', permissions.length)
    console.log('System permissions API: Permission categories:', [...new Set(permissions.map((p: any) => p.category))])

    // Group permissions by category
    const groupedPermissions = permissions.reduce((acc: any, permission: any) => {
      if (!acc[permission.category]) {
        acc[permission.category] = []
      }
      acc[permission.category].push(permission)
      return acc
    }, {})

    console.log('System permissions API: Grouped permissions keys:', Object.keys(groupedPermissions))

    // Get statistics with automatic connection management
    const stats = await executeGenericDbQuery(async () => {
      return await SystemPermission.aggregate([
        { $match: filter },
        {
          $group: {
            _id: '$category',
            count: { $sum: 1 },
            coreCount: { $sum: { $cond: ['$isCore', 1, 0] } }
          }
        },
        {
          $group: {
            _id: null,
            totalCategories: { $sum: 1 },
            totalPermissions: { $sum: '$count' },
            totalCorePermissions: { $sum: '$coreCount' },
            categoriesStats: { $push: { category: '$_id', count: '$count', coreCount: '$coreCount' } }
          }
        }
      ])
    }, `system-permissions-stats-${cacheKey}`, 300000) // 5-minute cache

    const responseData = {
      permissions: groupedPermissions,
      categories: Object.keys(groupedPermissions),
      statistics: stats[0] || {
        totalCategories: 0,
        totalPermissions: 0,
        totalCorePermissions: 0,
        categoriesStats: []
      }
    }

    // Cache result
    cache.set(cacheKey, {
      data: responseData,
      timestamp: Date.now()
    })

    return NextResponse.json({
      success: true,
      data: responseData,
      message: 'System permissions retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error in GET /api/system-permissions:', error)
    return createErrorResponse("Internal server error", 500)
  }
}