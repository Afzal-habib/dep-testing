/**
 * Server-Side Permission Manager
 * Contains server-only permission logic with database access
 */

import { NextRequest } from "next/server"
import { getServerSession } from "next-auth/next"
import { authOptions } from "@/lib/auth-config"
import connectDB from '@/lib/mongodb'
import User from '@/models/User'
import { QueryFilters } from './query-filters'

// Types
export interface Permission {
  resource: string
  actions: string[]
  conditions: {
    own?: boolean
    department?: boolean
    assigned?: boolean
    subordinates?: boolean
  }
}

export interface PermissionResult {
  success: boolean
  user?: any
  session?: any
  error?: string
  statusCode?: number
}

export interface PermissionOptions {
  superAdminEmail?: string
  fallbackRoles?: string[]
  enableLogging?: boolean
}

/**
 * Server-side permission manager with database access
 */
export class ServerPermissionManager {
  /**
   * Validate permission for a request
   */
  static async validatePermission(
    request: NextRequest,
    resource: string,
    action: string,
    options: PermissionOptions = {}
  ): Promise<PermissionResult> {
    try {
      // Get session
      const session = await getServerSession(authOptions)
      
      if (!session?.user) {
        return {
          success: false,
          error: 'Authentication required',
          statusCode: 401
        }
      }

      const userEmail = session.user.email;
      
      // Check if user is super admin
      const isSuperAdmin = QueryFilters.isSuperAdmin(session.user)
      
      if (isSuperAdmin) {
        return {
          success: true,
          user: session.user,
          session
        }
      }

      // Try to use permissions from session first (more efficient)
      let userPermissions = session.user.permissions
      let user = session.user

      if (userPermissions && Array.isArray(userPermissions) && userPermissions.length > 0) {
        // Use session permissions - faster and works for Postman
        const hasPermission = this.checkUserPermission(userPermissions, resource, action)
        
        if (hasPermission) {
          return {
            success: true,
            user,
            session
          }
        }

        return {
          success: false,
          error: `Access denied: ${action} permission required for ${resource}`,
          statusCode: 403
        }
      }

      // Fallback: Database lookup if session doesn't have permissions
      console.log('⚠️ Session missing permissions, falling back to database lookup for:', userEmail)
      
      await connectDB()

      // Get user with populated role and permissions
      const dbUser = await User.findOne({ email: userEmail })
        .populate({
          path: 'role',
          populate: {
            path: 'permissions',
            model: 'SystemPermission'
          }
        })
        .lean()

      if (!dbUser) {
        return {
          success: false,
          error: 'User not found',
          statusCode: 403
        }
      }

      // Check if user is super admin based on database user
      if (QueryFilters.isSuperAdmin(dbUser)) {
        return {
          success: true,
          user: dbUser,
          session
        }
      }

      // Check role-based permissions from database
      const userRole = dbUser.role as any
      if (!userRole || !userRole.permissions) {
        // Fallback to role name check if specified
        if (options.fallbackRoles && userRole?.name) {
          const hasRoleAccess = options.fallbackRoles.includes(userRole.name)
          if (hasRoleAccess) {
            return {
              success: true,
              user: dbUser,
              session
            }
          }
        }

        return {
          success: false,
          error: 'Insufficient permissions',
          statusCode: 403
        }
      }

      // Check specific permission from database
      const hasPermission = this.checkUserPermission(userRole.permissions, resource, action)
      
      if (hasPermission) {
        return {
          success: true,
          user: dbUser,
          session
        }
      }

      return {
        success: false,
        error: `Access denied: ${action} permission required for ${resource}`,
        statusCode: 403
      }

    } catch (error: any) {
      console.error('Permission validation error:', error)
      return {
        success: false,
        error: 'Permission validation failed',
        statusCode: 500
      }
    }
  }

  /**
   * Check if user has specific permission
   */
  private static checkUserPermission(
    permissions: Permission[],
    resource: string,
    action: string
  ): boolean {
    return permissions.some(permission => {
      if (permission.resource !== resource) {
        return false
      }

      return permission.actions.includes(action)
    })
  }

  /**
   * Generic hasPermission function for both server and client
   */
  static hasPermission(
    permissions: Permission[],
    resource: string,
    action: string,
    sessionUserRole?: string
  ): boolean {
    // Super admin check
    if (sessionUserRole === 'super_admin') {
      return true
    }

    return permissions.some(permission => {
      if (permission.resource !== resource) {
        return false
      }

      return permission.actions.includes(action)
    })
  }
}

/**
 * Ultra-generic permission middleware that automatically handles everything
 * Returns either the user session data OR throws/returns the error response
 * 
 * Usage: const { session, user } = await validateRouteAccess(request, 'users', 'read')
 */
export async function validateRouteAccess(
  request: NextRequest,
  resource: string,
  action: string,
  options: PermissionOptions = { enableLogging: true }
): Promise<{
  session: any
  user: any
}> {
  try {
    const permissionResult = await ServerPermissionManager.validatePermission(request, resource, action, options)
    
    if (!permissionResult.success) {
      // Directly throw the response to be caught by Next.js
      throw Response.json({
        success: false,
        error: permissionResult.error,
        timestamp: new Date().toISOString()
      }, { 
        status: permissionResult.statusCode || 403 
      })
    }

    return {
      session: permissionResult.session!,
      user: permissionResult.user!
    }
  } catch (error: any) {
    // If it's already a Response, re-throw it
    if (error instanceof Response) {
      throw error
    }
    
    // Otherwise create new error response
    throw Response.json({
      success: false,
      error: `Permission check failed: ${error.message}`,
      timestamp: new Date().toISOString()
    }, { 
      status: 500 
    })
  }
}

/**
 * Create permission-based API response helper
 */
export function createPermissionError(message: string, statusCode: number = 403) {
  return {
    success: false,
    error: message,
    statusCode,
    timestamp: new Date().toISOString()
  }
}

/**
 * Require permission for API route (throws on failure)
 */
export async function requirePermission(
  request: NextRequest,
  resource: string,
  action: string,
  options: PermissionOptions = {}
): Promise<PermissionResult> {
  const result = await ServerPermissionManager.validatePermission(request, resource, action, options)
  
  if (!result.success) {
    // Log the permission denial if logging is enabled
    if (options.enableLogging) {
      console.log('Permission denied:', {
        resource,
        action,
        error: result.error,
        timestamp: new Date().toISOString()
      })
    }
  }
  
  return result
}