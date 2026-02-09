/**
 * ========================================
 * CENTRALIZED PERMISSION SYSTEM
 * ========================================
 * Single source of truth for ALL permissions in the application
 * This replaces multiple permission files with one unified system
 */

// ===== CORE PERMISSION BUILDING BLOCKS =====
export const RESOURCES = {
  USERS: 'users',
  ROLES: 'roles',
  DEPARTMENTS: 'departments',
  PERMISSIONS: 'permissions',
  SYSTEM: 'system',
  PROJECTS: 'projects',
  TASKS: 'tasks',
  LEADS: 'leads',
  PROPOSALS: 'proposals',
  REPORTS: 'reports',
  DASHBOARD: 'dashboard',
  AUDIT_LOGS: 'audit_logs',
  SETTINGS: 'settings',
  BACKUP: 'backup',
  COMMUNICATIONS: 'communications',
  PROFILE: 'profile',
  EMAIL: 'email',
  UPLOAD: 'upload',
  CLIENT_PORTAL: 'client_portal',
} as const

export const ACTIONS = {
  CREATE: 'create',
  READ: 'read',
  UPDATE: 'update',
  DELETE: 'delete',
  ASSIGN: 'assign',
  APPROVE: 'approve',
  REJECT: 'reject',
  EXPORT: 'export',
  IMPORT: 'import',
  ARCHIVE: 'archive',
  MANAGE: 'manage',
  CONFIGURE: 'configure',
  AUDIT: 'audit',
} as const

export const CONDITIONS = {
  OWN: 'own',
  DEPARTMENT: 'department',
  ASSIGNED: 'assigned',
  SUBORDINATES: 'subordinates',
  UNRESTRICTED: 'unrestricted',
} as const

// ===== COMPREHENSIVE PERMISSION DEFINITIONS =====
export interface PermissionDefinition {
  resource: string
  displayName?: string
  description?: string
  category: string
  availableActions?: Array<{
    action: string
    description: string
    conditions?: string[]
  }>
  isCore?: boolean
}

// ===== MAIN COMPREHENSIVE PERMISSION DEFINITIONS =====
/**
 * Single source of truth for all permissions
 * Contains both simple permission objects and detailed definitions
 */
export const COMPREHENSIVE_PERMISSIONS: Record<string, PermissionDefinition> = {
  // ===== USER MANAGEMENT =====
  USERS: {
    resource: 'users',
    displayName: 'User Management',
    description: 'Manage user accounts and profiles',
    category: 'user_management',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Create new users', conditions: ['department', 'subordinates'] },
      { action: 'read', description: 'View user information', conditions: ['own', 'department', 'subordinates', 'unrestricted'] },
      { action: 'update', description: 'Update user information', conditions: ['own', 'department', 'subordinates', 'unrestricted'] },
      { action: 'delete', description: 'Delete/deactivate users', conditions: ['department', 'subordinates'] },
      { action: 'assign', description: 'Assign users to roles or departments', conditions: ['department', 'subordinates'] },
    ]
  },

  // ===== DEPARTMENT MANAGEMENT =====
  DEPARTMENTS: {
    resource: 'departments',
    displayName: 'Department Management',
    description: 'Manage organizational departments',
    category: 'department_management',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Create new departments' },
      { action: 'read', description: 'View department information', conditions: ['own', 'unrestricted'] },
      { action: 'update', description: 'Update department information', conditions: ['own', 'unrestricted'] },
      { action: 'delete', description: 'Delete/deactivate departments' },
      { action: 'assign', description: 'Assign users to departments' },
    ]
  },

  // ===== COMMUNICATION MANAGEMENT =====
  COMMUNICATIONS: {
    resource: 'communications',
    displayName: 'Communication Management',
    description: 'Manage organizational communications',
    category: 'communication_management',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Create new communications' },
      { action: 'read', description: 'View communication information', conditions: ['own', 'unrestricted'] },
      { action: 'update', description: 'Update communication information', conditions: ['own', 'unrestricted'] },
      { action: 'delete', description: 'Delete/deactivate communications' },
      { action: 'assign', description: 'Assign users to communications' },
    ]
  },

  // ===== ROLE MANAGEMENT =====
  ROLES: {
    resource: 'roles',
    displayName: 'Role Management',
    description: 'Manage user roles and permissions',
    category: 'role_management',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Create new roles', conditions: ['department'] },
      { action: 'read', description: 'View role information', conditions: ['department', 'unrestricted'] },
      { action: 'update', description: 'Update role permissions', conditions: ['department', 'unrestricted'] },
      { action: 'delete', description: 'Delete roles', conditions: ['department'] },
      { action: 'assign', description: 'Assign roles to users', conditions: ['department', 'subordinates'] },
    ]
  },

  // ===== PROJECT MANAGEMENT =====
  PROJECTS: {
    resource: 'projects',
    displayName: 'Projects Management',
    description: 'Manage organizational projects',
    category: 'project_management',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Create new projects' },
      { action: 'read', description: 'View project information', conditions: ['own', 'unrestricted'] },
      { action: 'update', description: 'Update project information', conditions: ['own', 'unrestricted'] },
      { action: 'delete', description: 'Delete/deactivate projects' },
      { action: 'assign', description: 'Assign users to projects' },
    ]
  },

  // ===== TASK MANAGEMENT =====
  TASKS: {
    resource: 'tasks',
    displayName: 'Tasks Management',
    description: 'Manage organizational tasks',
    category: 'task_management',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Create new tasks' },
      { action: 'read', description: 'View task information', conditions: ['own', 'unrestricted'] },
      { action: 'update', description: 'Update task information', conditions: ['own', 'unrestricted'] },
      { action: 'delete', description: 'Delete/deactivate tasks' },
      { action: 'assign', description: 'Assign users to tasks' },
    ]
  },

  // ===== LEAD MANAGEMENT =====
  LEADS: {
    resource: 'leads',
    displayName: 'Leads Management',
    description: 'Manage organizational leads',
    category: 'lead_management',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Create new leads' },
      { action: 'read', description: 'View lead information', conditions: ['own', 'unrestricted'] },
      { action: 'update', description: 'Update lead information', conditions: ['own', 'unrestricted'] },
      { action: 'delete', description: 'Delete/deactivate leads' },
      { action: 'assign', description: 'Assign users to leads' },
    ]
  },

  // ===== PROPOSAL MANAGEMENT =====
  PROPOSALS: {
    resource: 'proposals',
    displayName: 'Proposals Management',
    description: 'Manage organizational proposals',
    category: 'proposal_management',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Create new proposals' },
      { action: 'read', description: 'View proposal information', conditions: ['own', 'unrestricted'] },
      { action: 'update', description: 'Update proposal information', conditions: ['own', 'unrestricted'] },
      { action: 'delete', description: 'Delete/deactivate proposals' },
      { action: 'assign', description: 'Assign users to proposals' },
    ]
  },

  // ===== SYSTEM ADMINISTRATION =====
  SYSTEM: {
    resource: 'system',
    displayName: 'System Administration',
    description: 'System-wide configuration and maintenance',
    category: 'system_administration',
    isCore: true,
    availableActions: [
      { action: 'read', description: 'View system information' },
      { action: 'manage', description: 'Manage system operations' },
      { action: 'configure', description: 'Configure system settings' },
      { action: 'audit', description: 'Audit system activities' },
      { action: 'archive', description: 'Archive system data' },
      { action: 'export', description: 'Export system data' },
      { action: 'import', description: 'Import system data' },
    ]
  },

  // ===== PERMISSION MANAGEMENT =====
  PERMISSIONS: {
    resource: 'permissions',
    displayName: 'Permission Management',
    description: 'Manage system permissions',
    category: 'system_administration',
    isCore: true,
    availableActions: [
      { action: 'read', description: 'View permissions' },
      { action: 'manage', description: 'Manage permissions' },
    ]
  },

  // ===== REPORTING =====
  REPORTS: {
    resource: 'reports',
    displayName: 'Reports and Analytics',
    description: 'Generate and view system reports',
    category: 'reporting',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Generate reports', conditions: ['department', 'unrestricted'] },
      { action: 'read', description: 'View reports', conditions: ['own', 'department', 'unrestricted'] },
      { action: 'update', description: 'Modify existing reports', conditions: ['own', 'department'] },
      { action: 'delete', description: 'Delete reports', conditions: ['own', 'department'] },
      { action: 'export', description: 'Export report data' },
    ]
  },

  // ===== DASHBOARD =====
  DASHBOARD: {
    resource: 'dashboard',
    displayName: 'Dashboard Access',
    description: 'Access to various dashboard views',
    category: 'reporting',
    isCore: true,
    availableActions: [
      { action: 'read', description: 'View dashboard', conditions: ['own', 'department', 'unrestricted'] },
      { action: 'export', description: 'Export dashboard data' },
    ]
  },

  // ===== AUDIT LOGS =====
  AUDIT_LOGS: {
    resource: 'audit_logs',
    displayName: 'Audit Logs',
    description: 'View and manage audit logs',
    category: 'security',
    isCore: true,
    availableActions: [
      { action: 'read', description: 'View audit logs', conditions: ['department', 'unrestricted'] },
      { action: 'export', description: 'Export audit logs' },
      { action: 'archive', description: 'Archive old audit logs' },
    ]
  },

  // ===== SETTINGS =====
  SETTINGS: {
    resource: 'settings',
    displayName: 'System Settings',
    description: 'Manage application settings',
    category: 'system_administration',
    isCore: true,
    availableActions: [
      { action: 'read', description: 'View settings', conditions: ['own', 'department', 'unrestricted'] },
      { action: 'update', description: 'Update settings', conditions: ['own', 'department', 'unrestricted'] },
    ]
  },

  // ===== BACKUP =====
  BACKUP: {
    resource: 'backup',
    displayName: 'Backup and Recovery',
    description: 'System backup and data recovery operations',
    category: 'system_administration',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Create system backups' },
      { action: 'read', description: 'View backup status' },
      { action: 'export', description: 'Export backup files' },
      { action: 'import', description: 'Import/restore from backups' },
    ]
  },

  // ===== PROFILE =====
  PROFILE: {
    resource: 'profile',
    displayName: 'Profile Management',
    description: 'Manage personal profile and settings',
    category: 'user_management',
    isCore: true,
    availableActions: [
      { action: 'read', description: 'View own profile', conditions: ['own'] },
      { action: 'update', description: 'Update own profile', conditions: ['own'] },
    ]
  },

  // ===== EMAIL =====
  EMAIL: {
    resource: 'email',
    displayName: 'Email Management',
    description: 'Send and manage emails through the system',
    category: 'communication_management',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Send emails', conditions: ['own', 'department', 'unrestricted'] },
      { action: 'read', description: 'View email analytics and logs', conditions: ['own', 'department', 'unrestricted'] },
      { action: 'update', description: 'Update email settings' },
      { action: 'delete', description: 'Delete email records' },
    ]
  },

  // ===== UPLOAD =====
  UPLOAD: {
    resource: 'upload',
    displayName: 'File Upload Management',
    description: 'Upload and manage files in the system',
    category: 'system_administration',
    isCore: true,
    availableActions: [
      { action: 'create', description: 'Upload files', conditions: ['own', 'department', 'unrestricted'] },
      { action: 'read', description: 'View uploaded files', conditions: ['own', 'department', 'unrestricted'] },
      { action: 'update', description: 'Update file information' },
      { action: 'delete', description: 'Delete uploaded files', conditions: ['own', 'department'] },
    ]
  },

  // ===== CLIENT PORTAL =====
  CLIENT_PORTAL: {
    resource: 'client_portal',
    displayName: 'Client Portal Access',
    description: 'Access client portal features and communications',
    category: 'communication_management',
    isCore: true,
    availableActions: [
      { action: 'read', description: 'Access client portal', conditions: ['own', 'department', 'unrestricted'] },
      { action: 'create', description: 'Create client portal content' },
      { action: 'update', description: 'Update client portal settings' },
    ]
  },

  // ===== DEBUG =====
  DEBUG: {
    resource: 'debug',
    displayName: 'Debug and Testing',
    description: 'Debug endpoints for testing permissions and authentication',
    category: 'system_administration',
    isCore: false,
    availableActions: [
      { action: 'read', description: 'Access debug information and test endpoints' },
    ]
  },
}

// ===== LEGACY PERMISSIONS FOR BACKWARD COMPATIBILITY =====
/**
 * Generate simple permission objects from comprehensive definitions
 * This eliminates duplication while maintaining backward compatibility
 */
const generateSimplePermissions = (): Record<string, { resource: string; action: string }> => {
  const permissions: Record<string, { resource: string; action: string }> = {}

  Object.values(COMPREHENSIVE_PERMISSIONS).forEach(permission => {
    const resourceUpper = permission.resource.toUpperCase()
    permission.availableActions?.forEach(action => {
      const actionUpper = action.action.toUpperCase()
      const key = `${resourceUpper}_${actionUpper}`
      permissions[key] = {
        resource: permission.resource,
        action: action.action
      }
    })
  })

  return permissions
}

export const PERMISSIONS = generateSimplePermissions()

// ===== PERMISSION INTERFACES =====
export interface PermissionCheck {
  resource: string
  action: string
  condition?: 'own' | 'department' | 'assigned' | 'subordinates' | 'unrestricted'
}

// ===== UTILITY FUNCTIONS =====
/**
 * Get all comprehensive permission definitions as an array
 */
export const getAllComprehensivePermissions = (): PermissionDefinition[] => {
  return Object.values(COMPREHENSIVE_PERMISSIONS) as PermissionDefinition[]
}

/**
 * Get comprehensive permission definition by resource
 */
export const getComprehensivePermissionByResource = (resource: string): PermissionDefinition | undefined => {
  return Object.values(COMPREHENSIVE_PERMISSIONS).find(perm => perm.resource === resource) as PermissionDefinition | undefined
}

/**
 * Get all core permissions
 */
export const getCorePermissions = (): PermissionDefinition[] => {
  return Object.values(COMPREHENSIVE_PERMISSIONS).filter(perm => perm.isCore) as PermissionDefinition[]
}

/**
 * Get permissions by category
 */
export const getPermissionsByCategory = (category: string): PermissionDefinition[] => {
  return Object.values(COMPREHENSIVE_PERMISSIONS).filter(perm => perm.category === category) as PermissionDefinition[]
}

/**
 * Get all available actions for a resource
 */
export const getAvailableActionsForResource = (resource: string): string[] => {
  const permission = getComprehensivePermissionByResource(resource)
  return permission?.availableActions?.map(action => action.action) || []
}

/**
 * Alias for the main permissions - keeps existing code working
 */
export const COMMON_PERMISSIONS = PERMISSIONS