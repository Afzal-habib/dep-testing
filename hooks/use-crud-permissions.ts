import { useMemo } from 'react'
import { usePermissions } from '@/hooks/use-permissions'

/**
 * Generic interface for CRUD resources
 */
export interface CRUDResource {
  name: string
  displayName: string
  permissions: {
    create?: boolean
    read?: boolean
    update?: boolean
    delete?: boolean
    assign?: boolean
    export?: boolean
    import?: boolean
  }
}

/**
 * Hook to manage permissions for multiple CRUD resources
 */
export function useCRUDPermissions() {
  const { hasPermission, canCreate, canRead, canUpdate, canDelete, canAssign } = usePermissions()

  /**
   * Get permissions for a specific resource
   */
  const getResourcePermissions = (resource: string): CRUDResource['permissions'] => {
    return {
      create: canCreate(resource),
      read: canRead(resource),
      update: canUpdate(resource),
      delete: canDelete(resource),
      assign: canAssign(resource),
      export: hasPermission(resource, 'export'),
      import: hasPermission(resource, 'import'),
    }
  }

  /**
   * Get permissions for multiple resources
   */
  const getMultipleResourcePermissions = (resources: string[]) => {
    return resources.reduce((acc, resource) => {
      acc[resource] = getResourcePermissions(resource)
      return acc
    }, {} as Record<string, CRUDResource['permissions']>)
  }

  /**
   * Check if user has any CRUD permission for a resource
   */
  const hasAnyPermission = (resource: string): boolean => {
    const perms = getResourcePermissions(resource)
    return Object.values(perms).some(Boolean)
  }

  /**
   * Get available resources based on user permissions
   */
  const getAvailableResources = (resources: string[]): string[] => {
    return resources.filter(resource => hasAnyPermission(resource))
  }

  /**
   * Common resource definitions
   */
  const commonResources = useMemo(() => ({
    users: {
      name: 'users',
      displayName: 'User Management',
      permissions: getResourcePermissions('users')
    },
    roles: {
      name: 'roles',
      displayName: 'Role Management',
      permissions: getResourcePermissions('roles')
    },
    departments: {
      name: 'departments',
      displayName: 'Department Management',
      permissions: getResourcePermissions('departments')
    },
    permissions: {
      name: 'permissions',
      displayName: 'Permission Management',
      permissions: getResourcePermissions('permissions')
    },
    dashboard: {
      name: 'dashboard',
      displayName: 'Dashboard',
      permissions: getResourcePermissions('dashboard')
    },
    reports: {
      name: 'reports',
      displayName: 'Reports',
      permissions: getResourcePermissions('reports')
    },
    settings: {
      name: 'settings',
      displayName: 'System Settings',
      permissions: getResourcePermissions('settings')
    }
  }), [getResourcePermissions])

  return {
    getResourcePermissions,
    getMultipleResourcePermissions,
    hasAnyPermission,
    getAvailableResources,
    commonResources,
    // Direct access to permission methods
    hasPermission,
    canCreate,
    canRead,
    canUpdate,
    canDelete,
    canAssign,
  }
}

/**
 * Utility functions for permission-based navigation and UI
 */
export class PermissionUtils {
  /**
   * Filter navigation items based on user permissions
   */
  static filterNavItems(items: any[], userPermissions: Record<string, CRUDResource['permissions']>) {
    return items.filter(item => {
      if (!item.resource) return true // Allow items without resource requirements
      
      const perms = userPermissions[item.resource]
      if (!perms) return false
      
      // Check if user has any permission for this resource
      return Object.values(perms).some(Boolean)
    })
  }

  /**
   * Get conditional route protection
   */
  static getRouteProtection(resource: string, action: string = 'read') {
    return { resource, action }
  }

  /**
   * Generate permission-aware table actions
   */
  static generateTableActions(
    resource: string,
    permissions: CRUDResource['permissions'],
    handlers: {
      onView?: (item: any) => void
      onEdit?: (item: any) => void
      onDelete?: (item: any) => void
      onAssign?: (item: any) => void
    }
  ) {
    const actions = []

    if (permissions.read && handlers.onView) {
      actions.push({
        key: 'view',
        label: 'View',
        icon: 'Eye',
        handler: handlers.onView,
        variant: 'ghost' as const
      })
    }

    if (permissions.update && handlers.onEdit) {
      actions.push({
        key: 'edit',
        label: 'Edit',
        icon: 'Edit',
        handler: handlers.onEdit,
        variant: 'ghost' as const
      })
    }

    if (permissions.assign && handlers.onAssign) {
      actions.push({
        key: 'assign',
        label: 'Assign',
        icon: 'UserPlus',
        handler: handlers.onAssign,
        variant: 'ghost' as const
      })
    }

    if (permissions.delete && handlers.onDelete) {
      actions.push({
        key: 'delete',
        label: 'Delete',
        icon: 'Trash2',
        handler: handlers.onDelete,
        variant: 'ghost' as const,
        destructive: true
      })
    }

    return actions
  }
}

/**
 * Type definitions for generic CRUD operations
 */
export type CRUDAction = 'create' | 'read' | 'update' | 'delete' | 'assign' | 'export' | 'import'

export interface CRUDConfig {
  resource: string
  displayName: string
  endpoints: {
    list: string
    create: string
    read: string
    update: string
    delete: string
  }
  permissions: {
    [K in CRUDAction]?: boolean
  }
}

/**
 * Hook for generic CRUD operations with permissions
 */
export function useGenericCRUD(config: CRUDConfig) {
  const { getResourcePermissions } = useCRUDPermissions()
  const permissions = getResourcePermissions(config.resource)

  const canPerformAction = (action: CRUDAction): boolean => {
    return permissions[action] === true
  }

  const getEndpoint = (action: keyof CRUDConfig['endpoints']): string | null => {
    if (!canPerformAction(action as CRUDAction)) return null
    return config.endpoints[action]
  }

  return {
    permissions,
    canPerformAction,
    getEndpoint,
    config
  }
}