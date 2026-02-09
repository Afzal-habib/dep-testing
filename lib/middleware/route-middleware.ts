/**
 * OPTIMIZED Generic Route Middleware
 * Performance improvements: caching, lazy loading, reduced DB calls
 */

import { type NextRequest } from "next/server"
import { applyRateLimit } from "@/lib/security/rate-limiter"
import { validateRouteAccess, type PermissionOptions } from "@/lib/permissions/server"
import { MiddlewareLogger, createLogData } from "./middleware-logger"
import { handleMiddlewareError } from "@/lib/utils/api-responses"
import { QueryFilters, type FilterContext } from "@/lib/permissions/query-filters"

// Performance Cache - In-memory caching for 30 seconds
const middlewareCache = new Map<string, { data: any, timestamp: number }>()
const CACHE_TTL = 30 * 1000 // 30 seconds
const MAX_CACHE_SIZE = 100

export interface RouteMiddlewareOptions extends PermissionOptions {
  rateLimitType?: "api" | "sensitive" | "auth"
  skipRateLimit?: boolean
  skipAuth?: boolean
  useCache?: boolean // New option to enable caching
}

export interface RouteMiddlewareResult {
  session: any
  user: any
  userEmail: string
  filterContext?: any
  isSuperAdmin?: boolean
  applyFilters: (baseQuery: any) => Promise<any>
}

/**
 * Get cached middleware result if available and fresh
 */
function getCachedResult(cacheKey: string): RouteMiddlewareResult | null {
  const cached = middlewareCache.get(cacheKey)
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    // Return a shallow copy to prevent mutations affecting the cache
    return {
      ...cached.data,
      applyFilters: cached.data.applyFilters // Keep the function reference
    }
  }
  return null
}

/**
 * Cache middleware result
 */
function setCachedResult(cacheKey: string, result: RouteMiddlewareResult): void {
  middlewareCache.set(cacheKey, {
    data: result,
    timestamp: Date.now()
  })
  
  // Clean old cache entries (simple cleanup)
  if (middlewareCache.size > MAX_CACHE_SIZE) {
    const now = Date.now()
    for (const [key, value] of middlewareCache.entries()) {
      if (now - value.timestamp > CACHE_TTL) {
        middlewareCache.delete(key)
      }
    }
  }
}

/**
 * OPTIMIZED Universal route middleware
 */
export async function routeMiddleware(
  request: NextRequest,
  resource: string,
  action: string,
  options: RouteMiddlewareOptions = {}
): Promise<RouteMiddlewareResult> {
  const {
    rateLimitType = "api",
    skipRateLimit = false,
    skipAuth = false,
    enableLogging = false, // Default to false for performance
    useCache = true, // Enable caching by default
    ...permissionOptions
  } = options

  const startTime = Date.now()

  // Create cache key for non-sensitive operations (using hash for shorter keys)
  const authHeader = request.headers.get('authorization')
  const cacheKey = skipAuth ? null : `${resource}:${action}:${authHeader ? authHeader.slice(-8) : 'anon'}`
  
  // Check cache for non-sensitive operations (only for read operations)
  if (useCache && cacheKey && action === 'read' && !skipAuth) {
    const cachedResult = getCachedResult(cacheKey)
    if (cachedResult) {
      // Return cached result - significant performance boost
      return cachedResult
    }
  }

  try {
    // 1. Apply rate limiting (if not skipped) - Skip for read operations in development
    if (!skipRateLimit && (process.env.NODE_ENV === 'production' || !['read'].includes(action))) {
      const rateLimitResponse = await applyRateLimit(request, rateLimitType)
      if (rateLimitResponse) {
        // Minimal logging for rate limits
        if (enableLogging) {
          console.warn('Rate limit exceeded for:', resource, action)
        }
        throw rateLimitResponse
      }
    }

    // 2. Skip auth entirely if requested (for public routes)
    if (skipAuth) {
      const applyFilters = async (baseQuery: any) => baseQuery
      
      const result = {
        session: null,
        user: null,
        userEmail: 'anonymous',
        filterContext: undefined,
        isSuperAdmin: false,
        applyFilters
      }
      
      return result
    }

    // 3. Check authentication and permissions - OPTIMIZED
    const { session, user } = await validateRouteAccess(request, resource, action, {
      ...permissionOptions,
      enableLogging: false // Disable logging for performance
    })

    // 4. Extract user email for convenience - OPTIMIZED
    const sessionUser = session.user as any
    const userEmail = sessionUser?.email || sessionUser?.user?.email || 'unknown'
    const userId = user?._id || user?.id || sessionUser?.id

    // 5. OPTIMIZED permission-based filtering context
    const isSuperAdmin = QueryFilters.isSuperAdmin(user)
    
    // Get subordinate IDs with caching and error handling
    let subordinateIds: string[] = []
    try {
      // Only fetch subordinates for non-superadmins and when needed
      if (!isSuperAdmin && ['read', 'update', 'delete'].includes(action)) {
        subordinateIds = await QueryFilters.getSubordinateIds(userId)
      }
    } catch (error) {
      // Silently continue without subordinates for performance
      subordinateIds = []
    }
    
    // OPTIMIZED department extraction - simplified logic
    let userDepartment: string | undefined
    
    if (user.department) {
      if (typeof user.department === 'object' && user.department._id) {
        userDepartment = user.department._id.toString()
      } else if (typeof user.department === 'string') {
        userDepartment = user.department
      } else if (user.department.toString) {
        userDepartment = user.department.toString()
      }
    } else if (sessionUser.department && typeof sessionUser.department === 'string') {
      userDepartment = sessionUser.department
    }
    
    const filterContext: FilterContext = {
      userId: userId,
      userEmail: userEmail,
      userDepartment: userDepartment,
      userRole: user.role,
      subordinateIds,
      isSuperAdmin
    }

    // 6. Create OPTIMIZED applyFilters function
    const applyFilters = async (baseQuery: any) => {
      // For superadmins, skip filtering entirely
      if (isSuperAdmin) {
        return baseQuery
      }
      
      // Extract permissions - simplified logic
      let permissions = user.permissions || user.role?.permissions || []
      
      return await QueryFilters.applyPermissionFilters(
        baseQuery,
        resource,
        permissions,
        filterContext
      )
    }

    const result = {
      session,
      user,
      userEmail,
      filterContext,
      isSuperAdmin,
      applyFilters
    }

    // Cache the result for read operations
    if (useCache && cacheKey && action === 'read') {
      setCachedResult(cacheKey, result)
    }

    return result

  } catch (error: any) {
    // Simplified error handling for performance
    throw handleMiddlewareError(error, resource, action)
  }
}



/**
 * OPTIMIZED Generic middleware function - Main entry point
 */
export async function genericApiRoutesMiddleware(
  request: NextRequest,
  resource: string,
  action: string,
  options: RouteMiddlewareOptions = {}
): Promise<RouteMiddlewareResult> {
  // Simplified rate limit detection
  const sensitiveActions = ['create', 'update', 'delete', 'manage', 'configure', 'assign']
  const authActions = ['login', 'register', 'logout', 'refresh']
  
  let defaultRateLimitType: "api" | "sensitive" | "auth" = "api"
  
  if (authActions.includes(action)) {
    defaultRateLimitType = "auth"
  } else if (sensitiveActions.includes(action)) {
    defaultRateLimitType = "sensitive"
  }

  const rateLimitType = options.rateLimitType || defaultRateLimitType

  return routeMiddleware(request, resource, action, {
    ...options,
    rateLimitType,
    useCache: options.useCache !== false // Default to true
  })
}

/**
 * OPTIMIZED Convenience wrappers with performance defaults
 */

// For standard API routes (GET, etc.)
export async function apiMiddleware(
  request: NextRequest,
  resource: string,
  action: string,
  options: Omit<RouteMiddlewareOptions, 'rateLimitType'> = {}
): Promise<RouteMiddlewareResult> {
  return routeMiddleware(request, resource, action, {
    ...options,
    rateLimitType: "api",
    useCache: true
  })
}

// For sensitive operations (POST, PUT, DELETE)
export async function sensitiveMiddleware(
  request: NextRequest,
  resource: string,
  action: string,
  options: Omit<RouteMiddlewareOptions, 'rateLimitType'> = {}
): Promise<RouteMiddlewareResult> {
  return routeMiddleware(request, resource, action, {
    ...options,
    rateLimitType: "sensitive",
    useCache: false // Don't cache sensitive operations
  })
}

// For authentication routes
export async function authMiddleware(
  request: NextRequest,
  resource: string,
  action: string,
  options: Omit<RouteMiddlewareOptions, 'rateLimitType'> = {}
): Promise<RouteMiddlewareResult> {
  return routeMiddleware(request, resource, action, {
    ...options,
    rateLimitType: "auth",
    useCache: false // Don't cache auth operations
  })
}

// For public routes (no auth required)
export async function publicMiddleware(
  request: NextRequest,
  options: Omit<RouteMiddlewareOptions, 'skipAuth'> = {}
): Promise<RouteMiddlewareResult> {
  return routeMiddleware(request, '', '', {
    ...options,
    skipAuth: true,
    skipRateLimit: true, // Skip rate limiting for public routes
    useCache: false
  })
}