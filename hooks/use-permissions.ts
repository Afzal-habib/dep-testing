import { useState, useEffect, useCallback, useMemo } from 'react'
import { useSession } from 'next-auth/react'
import { ClientPermissionManager } from '@/lib/permissions/client'
import type { Permission } from '@/types'

interface UsePermissionsReturn {
  permissions: Permission[]
  loading: boolean
  hasPermission: (resource: string, action: string, condition?: string) => boolean
  canAccess: (resource: string, actions?: string[]) => boolean
  canCreate: (resource: string) => boolean
  canRead: (resource: string) => boolean
  canUpdate: (resource: string) => boolean
  canDelete: (resource: string) => boolean
  canAssign: (resource: string) => boolean
}

export function usePermissions(): UsePermissionsReturn {
  const { data: session, status } = useSession()
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [loading, setLoading] = useState(status === 'loading')

  // Memoize permission manager to prevent recreation on every render
  const permissionManager = useMemo(() => {
    if (!session?.user) return null

    const sessionUser = session.user as any
    // Pass the complete role object or role string for better super admin detection
    const userRole = sessionUser?.role || 'user'

    return new ClientPermissionManager(permissions, userRole)
  }, [permissions, session?.user])

  // Load permissions directly from NextAuth session
  useEffect(() => {
    setLoading(status === 'loading')

    if (status === 'loading') return

    if (session?.user) {
      const sessionUser = session.user as any

      // Extract permissions from role-based system or fallback to user permissions
      let userPermissions: Permission[] = []

      // Try to get permissions from role first (new system)
      if (sessionUser?.role?.permissions && Array.isArray(sessionUser.role.permissions)) {
        userPermissions = sessionUser.role.permissions
      }
      // Fallback to direct user permissions (legacy system)
      else if (sessionUser?.permissions && Array.isArray(sessionUser.permissions)) {
        userPermissions = sessionUser.permissions
      }

      setPermissions(userPermissions)

      console.log('🔍 Permissions loaded from session:', {
        userEmail: sessionUser?.email,
        userRole: sessionUser?.role,
        roleObj: typeof sessionUser?.role,
        hasRolePermissions: !!(sessionUser?.role?.permissions),
        hasUserPermissions: !!(sessionUser?.permissions),
        permissionsCount: userPermissions.length,
        permissions: userPermissions,
        sessionUser: sessionUser
      })
    } else if (status === 'unauthenticated') {
      // Clear permissions when no session
      setPermissions([])
      console.log('Permissions cleared - user unauthenticated')
    }
  }, [session, status])

  const hasPermission = useCallback((resource: string, action: string, condition?: string): boolean => {
    // If still loading or no permission manager, deny access
    if (loading || !permissionManager) return false
    return permissionManager.hasPermission(resource, action, condition)
  }, [permissionManager, loading])

  const canAccess = useCallback((resource: string, actions: string[] = ['read']): boolean => {
    if (!permissionManager) return false
    return permissionManager.canAccess(resource, actions)
  }, [permissionManager])

  const canCreate = useCallback((resource: string): boolean => {
    if (!permissionManager) return false
    return permissionManager.canCreate(resource)
  }, [permissionManager])

  const canRead = useCallback((resource: string): boolean => {
    if (!permissionManager) return false
    return permissionManager.canRead(resource)
  }, [permissionManager])

  const canUpdate = useCallback((resource: string): boolean => {
    if (!permissionManager) return false
    return permissionManager.canUpdate(resource)
  }, [permissionManager])

  const canDelete = useCallback((resource: string): boolean => {
    if (!permissionManager) return false
    return permissionManager.canDelete(resource)
  }, [permissionManager])

  const canAssign = useCallback((resource: string): boolean => {
    if (!permissionManager) return false
    return permissionManager.canAssign(resource)
  }, [permissionManager])

  return {
    permissions,
    loading,
    hasPermission,
    canAccess,
    canCreate,
    canRead,
    canUpdate,
    canDelete,
    canAssign,
  }
}