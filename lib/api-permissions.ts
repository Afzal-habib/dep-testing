import { NextRequest } from "next/server"
import { getServerSession } from "next-auth/next"
import { authOptions } from "@/lib/auth-config"
import { COMMON_PERMISSIONS, type PermissionCheck } from "@/lib/constants/permissions"
import connectDB from '@/lib/mongodb'
import User from '@/models/User'
// PermissionCheck is now imported from constants/permissions

export interface ApiPermissionOptions {
  /** Fallback roles for legacy compatibility */
  fallbackRoles?: string[]
  /** Additional custom validation function */
  customValidator?: (user: any, session: any) => Promise<boolean>
  /** Whether to log permission checks for debugging */
  enableLogging?: boolean
}

export interface PermissionResult {
  success: boolean
  user?: any
  session?: any
  error?: string
  statusCode?: number
}

/**
 * Comprehensive API permission checker that works with the dynamic role system
 * This replaces hardcoded permission checks with a flexible, generic approach
 */
export class ApiPermissionManager {
  private static defaultOptions: ApiPermissionOptions = {
    fallbackRoles: ['admin', 'super_admin'],
    enableLogging: true
  }

  /**
   * Check session authentication
   */
  static async checkAuthentication(request: NextRequest): Promise<PermissionResult> {
    try {
      const session = await getServerSession(authOptions)
      
      if (!session?.user) {
        return {
          success: false,
          error: "Unauthorized - No valid session",
          statusCode: 401
        }
      }

      return {
        success: true,
        session,
        user: session.user
      }
    } catch (error: any) {
      return {
        success: false,
        error: `Authentication error: ${error.message}`,
        statusCode: 401
      }
    }
  }

  /**
   * Check if user has required permission using the dynamic permission system
   */
  static async checkPermission(
    sessionUser: any,
    permission: PermissionCheck,
    options: ApiPermissionOptions = {}
  ): Promise<PermissionResult> {
    try {
      await connectDB()
      
      const opts = { ...this.defaultOptions, ...options }
      const userEmail = sessionUser?.email || sessionUser?.user?.email
      const userId = sessionUser?.id || sessionUser?._id || sessionUser?.user?.id

      // Super admin bypass
      if (sessionUser?.role?.name === 'super_admin') {
        if (opts.enableLogging) {
          console.log(`Super admin access granted: ${userEmail} -> ${permission.resource}:${permission.action}`)
        }
        return { success: true, user: sessionUser }
      }

      // Get effective user ID
      let effectiveUserId = userId
      if (!effectiveUserId && userEmail) {
        const userDoc = await User.findOne({ email: userEmail }).lean()
        effectiveUserId = userDoc?._id?.toString()
      }

      if (!effectiveUserId) {
        return {
          success: false,
          error: "Unable to determine user ID for permission check",
          statusCode: 403
        }
      }

      // Check dynamic permission
      const hasAccess = await hasPermission(
        effectiveUserId, 
        permission.resource, 
        permission.action
      )

      if (hasAccess) {
        if (opts.enableLogging) {
          console.log(`Permission granted: ${userEmail} -> ${permission.resource}:${permission.action}`)
        }
        return { success: true, user: sessionUser }
      }

      // Fallback to legacy role-based check if configured
      if (opts.fallbackRoles?.length) {
        const userRole = sessionUser?.role || sessionUser?.user?.role
        if (userRole && opts.fallbackRoles.includes(userRole)) {
          if (opts.enableLogging) {
            console.log(`Fallback role access granted: ${userEmail} (${userRole}) -> ${permission.resource}:${permission.action}`)
          }
          return { success: true, user: sessionUser }
        }
      }

      // Custom validator
      if (opts.customValidator) {
        const customResult = await opts.customValidator(sessionUser, null)
        if (customResult) {
          if (opts.enableLogging) {
            console.log(`Custom validator granted access: ${userEmail} -> ${permission.resource}:${permission.action}`)
          }
          return { success: true, user: sessionUser }
        }
      }

      if (opts.enableLogging) {
        console.log(`Permission denied: ${userEmail} -> ${permission.resource}:${permission.action}`)
      }

      return {
        success: false,
        error: `Insufficient permissions for ${permission.resource}:${permission.action}`,
        statusCode: 403
      }

    } catch (error: any) {
      console.error('Permission check error:', error)
      return {
        success: false,
        error: `Permission check failed: ${error.message}`,
        statusCode: 500
      }
    }
  }

  /**
   * Check if user has any of the specified permissions
   */
  static async checkAnyPermission(
    sessionUser: any,
    permissions: PermissionCheck[],
    options: ApiPermissionOptions = {}
  ): Promise<PermissionResult> {
    try {
      await connectDB()
      
      const opts = { ...this.defaultOptions, ...options }
      const userEmail = sessionUser?.email || sessionUser?.user?.email
      const userId = sessionUser?.id || sessionUser?._id || sessionUser?.user?.id

      // Super admin bypass
      if (sessionUser?.role?.name === 'super_admin' || sessionUser?.role === 'super_admin') {
        if (opts.enableLogging) {
          console.log(`Super admin access granted: ${userEmail}`)
        }
        return { success: true, user: sessionUser }
      }

      // Get effective user ID
      let effectiveUserId = userId
      if (!effectiveUserId && userEmail) {
        const userDoc = await User.findOne({ email: userEmail }).lean()
        effectiveUserId = userDoc?._id?.toString()
      }

      if (!effectiveUserId) {
        return {
          success: false,
          error: "Unable to determine user ID for permission check",
          statusCode: 403
        }
      }

      // Check if user has any of the permissions
      const permissionChecks = permissions.map(p => ({ resource: p.resource, action: p.action }))
      const hasAccess = await hasAnyPermission(effectiveUserId, permissionChecks)

      if (hasAccess) {
        if (opts.enableLogging) {
          console.log(`Any permission granted: ${userEmail}`)
        }
        return { success: true, user: sessionUser }
      }

      // Fallback to legacy role-based check
      if (opts.fallbackRoles?.length) {
        const userRole = sessionUser?.role || sessionUser?.user?.role
        if (userRole && opts.fallbackRoles.includes(userRole)) {
          if (opts.enableLogging) {
            console.log(`Fallback role access granted: ${userEmail} (${userRole})`)
          }
          return { success: true, user: sessionUser }
        }
      }

      if (opts.enableLogging) {
        console.log(`All permissions denied: ${userEmail}`)
      }

      return {
        success: false,
        error: "Insufficient permissions",
        statusCode: 403
      }

    } catch (error: any) {
      console.error('Permission check error:', error)
      return {
        success: false,
        error: `Permission check failed: ${error.message}`,
        statusCode: 500
      }
    }
  }

  /**
   * Check if user has all specified permissions
   */
  static async checkAllPermissions(
    sessionUser: any,
    permissions: PermissionCheck[],
    options: ApiPermissionOptions = {}
  ): Promise<PermissionResult> {
    try {
      await connectDB()
      
      const opts = { ...this.defaultOptions, ...options }
      const userEmail = sessionUser?.email || sessionUser?.user?.email
      const userId = sessionUser?.id || sessionUser?._id || sessionUser?.user?.id

      // Super admin bypass
      if (sessionUser?.role?.name === 'super_admin' || sessionUser?.role === 'super_admin') {
        if (opts.enableLogging) {
          console.log(`Super admin access granted: ${userEmail}`)
        }
        return { success: true, user: sessionUser }
      }

      // Get effective user ID
      let effectiveUserId = userId
      if (!effectiveUserId && userEmail) {
        const userDoc = await User.findOne({ email: userEmail }).lean()
        effectiveUserId = userDoc?._id?.toString()
      }

      if (!effectiveUserId) {
        return {
          success: false,
          error: "Unable to determine user ID for permission check",
          statusCode: 403
        }
      }

      // Check if user has all permissions
      const permissionChecks = permissions.map(p => ({ resource: p.resource, action: p.action }))
      const hasAccess = await hasAllPermissions(effectiveUserId, permissionChecks)

      if (hasAccess) {
        if (opts.enableLogging) {
          console.log(`All permissions granted: ${userEmail}`)
        }
        return { success: true, user: sessionUser }
      }

      // Fallback to legacy role-based check
      if (opts.fallbackRoles?.length) {
        const userRole = sessionUser?.role || sessionUser?.user?.role
        if (userRole && opts.fallbackRoles.includes(userRole)) {
          if (opts.enableLogging) {
            console.log(`Fallback role access granted: ${userEmail} (${userRole})`)
          }
          return { success: true, user: sessionUser }
        }
      }

      if (opts.enableLogging) {
        console.log(`Not all permissions granted: ${userEmail}`)
      }

      return {
        success: false,
        error: "Insufficient permissions",
        statusCode: 403
      }

    } catch (error: any) {
      console.error('Permission check error:', error)
      return {
        success: false,
        error: `Permission check failed: ${error.message}`,
        statusCode: 500
      }
    }
  }

  /**
   * Convenient method to check both authentication and permission in one call
   */
  static async validateAccess(
    request: NextRequest,
    permission: PermissionCheck,
    options: ApiPermissionOptions = {}
  ): Promise<PermissionResult> {
    // First check authentication
    const authResult = await this.checkAuthentication(request)
    if (!authResult.success) {
      return authResult
    }

    // Then check permission
    const permissionResult = await this.checkPermission(
      authResult.session!.user,
      permission,
      options
    )

    return {
      ...permissionResult,
      session: authResult.session,
      user: authResult.user
    }
  }

  /**
   * Validate access with any of multiple permissions
   */
  static async validateAnyAccess(
    request: NextRequest,
    permissions: PermissionCheck[],
    options: ApiPermissionOptions = {}
  ): Promise<PermissionResult> {
    // First check authentication
    const authResult = await this.checkAuthentication(request)
    if (!authResult.success) {
      return authResult
    }

    // Then check permissions
    const permissionResult = await this.checkAnyPermission(
      authResult.session!.user,
      permissions,
      options
    )

    return {
      ...permissionResult,
      session: authResult.session,
      user: authResult.user
    }
  }

  /**
   * Validate access with all permissions required
   */
  static async validateAllAccess(
    request: NextRequest,
    permissions: PermissionCheck[],
    options: ApiPermissionOptions = {}
  ): Promise<PermissionResult> {
    // First check authentication
    const authResult = await this.checkAuthentication(request)
    if (!authResult.success) {
      return authResult
    }

    // Then check permissions
    const permissionResult = await this.checkAllPermissions(
      authResult.session!.user,
      permissions,
      options
    )

    return {
      ...permissionResult,
      session: authResult.session,
      user: authResult.user
    }
  }
}

/**
 * Helper function to create error responses
 */
export function createPermissionErrorResponse(result: PermissionResult) {
  return new Response(
    JSON.stringify({
      success: false,
      error: result.error || 'Permission denied'
    }),
    {
      status: result.statusCode || 403,
      headers: { 'Content-Type': 'application/json' }
    }
  )
}


//utility functions for permission checks


/**
 * Check if a user has permission for a specific resource and action
 * @param userId - The user ID
 * @param resource - The resource (e.g., 'users', 'roles', 'departments')
 * @param action - The action (e.g., 'create', 'read', 'update', 'delete')
 * @returns Promise<boolean>
 */
export async function hasPermission(
  userId: string,
  resource: string,
  action: string
): Promise<boolean> {
  try {
    await connectDB()

    // Find the user and populate their role (permissions are embedded, not referenced)
    const user = await User.findById(userId)
      .populate({
        path: 'role',
        select: 'name displayName hierarchyLevel permissions'
      })
      .lean()

    if (!user) {
      console.log(`User not found: ${userId}`)
      return false
    }

    // CRITICAL: Super admin bypass - grants ALL permissions automatically
    if (user.role && (user.role as any).name === 'super_admin') {
      console.log(`Super admin access granted for ${resource}:${action}`)
      return true
    }

    // Check if user has the role populated
    if (!user.role) {
      console.log(`User ${userId} has no role assigned`)
      return false
    }

    const userRole = user.role as any

    // Check if the role has permissions
    if (!userRole.permissions || !Array.isArray(userRole.permissions)) {
      console.log(`Role ${userRole._id} has no permissions`)
      return false
    }

    // Check if any of the role's embedded permissions match the requested resource and action
    const hasAccess = userRole.permissions.some((permission: any) => {
      // Permissions are embedded objects from Role model with structure: { resource, actions, conditions }
      if (permission && typeof permission === 'object') {
        // Check embedded permission structure (from Role model)
        if (permission.resource && Array.isArray(permission.actions)) {
          return permission.resource === resource && permission.actions.includes(action)
        }
        
        // Legacy fallback for other permission structures
        const permResource = permission.resource || permission.name?.split(':')[0] || permission.name?.split('_')[0]
        const permAction = permission.action || permission.name?.split(':')[1] || permission.name?.split('_')[1]

        // Check for exact match, wildcard resource, wildcard action, or full wildcard
        return (
          (permResource === resource && permAction === action) ||
          (permResource === resource && permAction === '*') ||
          (permResource === '*' && permAction === action) ||
          (permResource === '*' && permAction === '*') ||
          permission.name === `${resource}:${action}` ||
          permission.name === `${resource}:*` ||
          permission.name === '*:*'
        )
      }
      
      // Fallback for string-based permissions
      if (typeof permission === 'string') {
        return permission === `${resource}:${action}` || permission === `${resource}:*` || permission === '*:*'
      }

      return false
    })

    console.log(`Permission check for user ${userId}:`, {
      resource,
      action,
      hasAccess,
      roleId: userRole._id,
      roleName: userRole.name,
      permissionCount: userRole.permissions.length
    })

    return hasAccess
  } catch (error) {
    console.error('Error checking permissions:', error)
    return false
  }
}

/**
 * Check if a user has any of the specified permissions
 * @param userId - The user ID
 * @param permissions - Array of permission objects with resource and action
 * @returns Promise<boolean>
 */
export async function hasAnyPermission(
  userId: string,
  permissions: Array<{ resource: string; action: string }>
): Promise<boolean> {
  for (const perm of permissions) {
    const hasAccess = await hasPermission(userId, perm.resource, perm.action)
    if (hasAccess) {
      return true
    }
  }
  return false
}

/**
 * Check if a user has all of the specified permissions
 * @param userId - The user ID
 * @param permissions - Array of permission objects with resource and action
 * @returns Promise<boolean>
 */
export async function hasAllPermissions(
  userId: string,
  permissions: Array<{ resource: string; action: string }>
): Promise<boolean> {
  for (const perm of permissions) {
    const hasAccess = await hasPermission(userId, perm.resource, perm.action)
    if (!hasAccess) {
      return false
    }
  }
  return true
}