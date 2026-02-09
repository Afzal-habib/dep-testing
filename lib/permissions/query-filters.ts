import mongoose from 'mongoose'
import type { Permission } from '@/types'

export interface FilterContext {
  userId: string
  userEmail: string
  userDepartment?: string
  userRole?: any
  subordinateIds?: string[]
  isSuperAdmin?: boolean
}

export class QueryFilters {
  /**
   * Apply permission-based filters to any MongoDB query
   * Superadmin bypasses all filters by default
   */
  static async applyPermissionFilters(
    baseQuery: any,
    resource: string,
    userPermissions: Permission[],
    context: FilterContext
  ): Promise<any> {
    console.log('QueryFilters: Applying filters for resource:', resource, {
      userId: context.userId,
      userEmail: context.userEmail,
      userDepartment: context.userDepartment,
      isSuperAdmin: context.isSuperAdmin,
      permissionsCount: userPermissions.length,
      permissions: userPermissions.map(p => ({ resource: p.resource, conditions: p.conditions }))
    })

    // Superadmin gets all records - no filtering needed
    if (context.isSuperAdmin) {
      console.log('QueryFilters: Superadmin access - no filtering applied')
      return baseQuery
    }

    // Find permission for this resource
    const permission = userPermissions.find(p => p.resource === resource)
    
    if (!permission) {
      // Check if user has system unrestricted access
      const systemPermission = userPermissions.find(p => p.resource === 'system')
      if (systemPermission && systemPermission.conditions?.unrestricted === true) {
        console.log('QueryFilters: ✅ System unrestricted access granted for resource:', resource)
        return baseQuery
      }
      
      // No permission = no access to any records
      console.log('QueryFilters: ❌ No permission found for resource, blocking access', {
        availableResources: userPermissions.map(p => p.resource),
        requestedResource: resource,
        userId: context.userId,
        userEmail: context.userEmail
      })
      return { _id: { $exists: false } }
    }

    console.log('QueryFilters: 🔍 Found permission for resource:', {
      resource,
      permission: {
        resource: permission.resource,
        actions: permission.actions,
        conditions: permission.conditions
      },
      userContext: {
        userId: context.userId,
        userEmail: context.userEmail,
        userDepartment: context.userDepartment,
        isSuperAdmin: context.isSuperAdmin
      }
    })

    // Check if this permission allows access to ALL records
    const hasUnrestricted = this.hasUnrestrictedAccess(permission)
    if (hasUnrestricted) {
      console.log('QueryFilters: ✅ UNRESTRICTED ACCESS GRANTED - no filtering applied', {
        resource,
        reason: 'Permission has unrestricted access',
        originalQuery: baseQuery,
        permission: permission.conditions
      })
      return baseQuery
    } else {
      console.log('QueryFilters: 🔒 RESTRICTED ACCESS - will apply condition filters', {
        resource,
        conditions: permission.conditions
      })
    }

    // Handle default behavior for users resource when no conditions are defined
    // For users resource: no conditions = own: true behavior (except for superadmin)
    // For other resources: no conditions = full access
    if (!permission.conditions || Object.keys(permission.conditions).length === 0) {
      if (resource === 'users' && !context.isSuperAdmin) {
        console.log('QueryFilters: Users resource with no conditions - defaulting to own: true behavior')
        // Apply default 'own: true' behavior for users resource
        const ownFilter = this.getOwnershipFilter(resource, context.userId)
        if (ownFilter) {
          const filteredQuery = {
            ...baseQuery,
            $and: [
              baseQuery,
              ownFilter
            ]
          }
          console.log('QueryFilters: Applied default own filter for users:', ownFilter)
          return filteredQuery
        }
      } else {
        console.log('QueryFilters: No conditions set - full access granted')
        return baseQuery
      }
    }

    // Build condition filters
    const conditionFilters = await this.buildConditionFilters(
      resource,
      permission.conditions,
      context
    )

    // If no conditions are active, return base query (full access)
    // This can happen when unrestricted=true or no valid conditions are found
    if (conditionFilters.length === 0) {
      console.log('QueryFilters: ⚠️ NO CONDITION FILTERS BUILT - granting full access', {
        resource,
        reason: 'No condition filters were built',
        permissionConditions: permission.conditions,
        originalQuery: baseQuery,
        warning: 'This might be unintended - check permission conditions'
      })
      return baseQuery
    }

    // Apply condition filters with OR logic
    const filteredQuery = {
      ...baseQuery,
      $and: [
        baseQuery,
        { $or: conditionFilters }
      ]
    }

    console.log('QueryFilters: 🎯 APPLIED CONDITION FILTERS:', {
      resource,
      originalQuery: baseQuery,
      conditionFilters,
      conditionFiltersCount: conditionFilters.length,
      finalQuery: filteredQuery,
      filterLogic: 'OR - user can see records matching ANY of the conditions'
    })

    return filteredQuery
  }

  /**
   * Check if permission allows unrestricted access
   */
  private static hasUnrestrictedAccess(permission: Permission): boolean {
    console.log('QueryFilters: Checking unrestricted access for permission:', {
      resource: permission.resource,
      actions: permission.actions,
      conditions: permission.conditions,
      hasDirectUnrestricted: 'unrestricted' in permission,
      directUnrestrictedValue: (permission as any).unrestricted
    })

    // Check for direct unrestricted property on permission object
    if ('unrestricted' in permission && (permission as any).unrestricted === true) {
      console.log('QueryFilters: ✅ Direct unrestricted=true found on permission - granting full access')
      return true
    }

    // Check for unrestricted in conditions object
    if (permission.conditions && 'unrestricted' in permission.conditions && permission.conditions.unrestricted === true) {
      console.log('QueryFilters: ✅ conditions.unrestricted=true found - granting full access')
      return true
    }

    // ONLY grant full access if ALL non-unrestricted conditions are explicitly false
    // This prevents granting full access when conditions like own:true or department:true exist
    if (permission.conditions) {
      const conditionEntries = Object.entries(permission.conditions)
      const restrictiveConditions = conditionEntries.filter(([key]) => key !== 'unrestricted')
      
      console.log('QueryFilters: Restrictive conditions analysis:', {
        allConditions: conditionEntries,
        restrictiveConditions,
        hasRestrictiveConditions: restrictiveConditions.length > 0
      })
      
      // If there are restrictive conditions, check if any are true
      if (restrictiveConditions.length > 0) {
        const hasActiveTrueConditions = restrictiveConditions.some(([, val]) => val === true)
        
        if (hasActiveTrueConditions) {
          console.log('QueryFilters: 🔒 Has active restrictive conditions - will apply filtering:', {
            activeConditions: restrictiveConditions.filter(([, val]) => val === true)
          })
          return false
        } else {
          console.log('QueryFilters: ✅ All restrictive conditions are false - granting full access')
          return true
        }
      }
      
      // No restrictive conditions found (only unrestricted or empty)
      console.log('QueryFilters: ✅ No restrictive conditions - granting full access')
      return true
    }

    // No conditions object at all
    console.log('QueryFilters: ✅ No conditions object - granting full access')
    return true
  }

  /**
   * Build filters for each condition type
   */
  private static async buildConditionFilters(
    resource: string,
    conditions: Permission['conditions'],
    context: FilterContext
  ): Promise<any[]> {
    const filters: any[] = []
    const { userId, userDepartment, subordinateIds } = context

    const activeConditionsList = conditions ? Object.entries(conditions).filter(([, value]) => value === true) : []
    
    console.log('QueryFilters: 🔍 Building condition filters:', {
      resource,
      conditions,
      userId,
      userDepartment,
      subordinateIds,
      activeConditions: activeConditionsList,
      activeConditionsCount: activeConditionsList.length
    })

    if (!conditions) return filters

    // Check for unrestricted access first - this should override all other conditions
    if (conditions.unrestricted === true) {
      console.log('QueryFilters: Unrestricted condition found - no filters will be applied')
      // Return empty filters array to indicate no restrictions
      return []
    }

    // Only for records they own
    if (conditions.own === true) {
      console.log('QueryFilters: 👤 Processing own condition:', {
        resource,
        userId
      })
      
      const ownFilter = this.getOwnershipFilter(resource, userId)
      if (ownFilter) {
        filters.push(ownFilter)
        console.log('QueryFilters: ✅ Added ownership filter:', ownFilter)
      } else {
        console.log('QueryFilters: ❌ Failed to create ownership filter')
      }
    }

    // Only within their department
    if (conditions.department === true) {
      if (userDepartment) {
        console.log('QueryFilters: 🏢 Processing department condition:', {
          resource,
          userDepartment,
          departmentType: typeof userDepartment
        })
        
        const deptFilter = await this.getDepartmentFilter(resource, userDepartment)
        if (deptFilter) {
          filters.push(deptFilter)
          console.log('QueryFilters: ✅ Added department filter:', deptFilter)
        } else {
          console.log('QueryFilters: ❌ Failed to create department filter')
        }
      } else {
        console.log('QueryFilters: ⚠️ Department condition is true but userDepartment is missing - denying access:', {
          'conditions.department': conditions.department,
          userDepartment,
          userDepartmentType: typeof userDepartment,
          userId: userId,
          result: 'Will add impossible filter'
        })
        // Add an impossible filter to deny access when department condition is required but missing
        filters.push({ _id: { $exists: false } })
      }
    }

    // Only for assigned records
    if (conditions.assigned === true) {
      const assignedFilter = this.getAssignedFilter(resource, userId)
      if (assignedFilter) {
        filters.push(assignedFilter)
        console.log('QueryFilters: Added assigned filter:', assignedFilter)
      }
    }

    // Only for subordinate users
    if (conditions.subordinates === true && subordinateIds?.length) {
      const subordinateFilter = this.getSubordinateFilter(resource, subordinateIds)
      if (subordinateFilter) {
        filters.push(subordinateFilter)
        console.log('QueryFilters: Added subordinate filter:', subordinateFilter)
      }
    }

    console.log('QueryFilters: Final condition filters built:', {
      resource,
      filtersCount: filters.length,
      filters: filters
    })

    return filters
  }

  /**
   * Resource-specific ownership field mapping
   */
  private static getOwnershipFilter(resource: string, userId: string): any {
    const resourceOwnershipMap: Record<string, string> = {
      users: '_id', // Users can see their own record by matching their ID
      departments: 'metadata.createdBy',
      roles: 'metadata.createdBy',
      projects: 'ownerId',
      tasks: 'createdBy',
      leads: 'ownerId',
      proposals: 'createdBy',
      reports: 'createdBy',
      'audit_logs': 'userId',
      // Add more resources as needed
    }

    const ownerField = resourceOwnershipMap[resource]
    if (!ownerField) return null

    // For users resource, match by their own ID
    // For other resources with metadata.createdBy, match by userId
    return { [ownerField]: userId }
  }

  // Simple cache for department lookups to avoid repeated DB queries
  private static departmentCache = new Map<string, string>()

  /**
   * Resource-specific department field mapping
   */
  private static async getDepartmentFilter(resource: string, departmentInfo: string): Promise<any> {
    const resourceDepartmentMap: Record<string, string> = {
      users: 'department',
      projects: 'department',
      tasks: 'department',
      leads: 'department',
      proposals: 'department',
      reports: 'department',
      roles: 'department',
      // Some resources might not have department filtering
    }

    const deptField = resourceDepartmentMap[resource]
    if (!deptField) {
      console.log(`QueryFilters: No department field mapping for resource: ${resource}`)
      return null
    }

    let departmentFilter: any

    // Check if departmentInfo is an ObjectId or department name
    if (mongoose.Types.ObjectId.isValid(departmentInfo)) {
      // It's already an ObjectId
      departmentFilter = { [deptField]: departmentInfo }
      console.log('QueryFilters: Using ObjectId department filter:', departmentFilter)
    } else {
      // Check cache first
      const cached = this.departmentCache.get(departmentInfo)
      if (cached) {
        departmentFilter = { [deptField]: cached }
        console.log('QueryFilters: Using cached department filter:', departmentFilter)
      } else {
        // It's a department name, need to look up the ObjectId
        try {
          const { default: Department } = await import('@/models/Department')
          const department = await Department.findOne({ 
            name: departmentInfo,
            status: 'active' 
          }).select('_id').lean()
          
          if (department) {
            const deptId = (department as any)._id.toString()
            this.departmentCache.set(departmentInfo, deptId) // Cache for future use
            departmentFilter = { [deptField]: (department as any)._id }
            console.log('QueryFilters: Department lookup successful:', { departmentInfo, deptId })
          } else {
            console.warn(`Department '${departmentInfo}' not found, using name-based filter as fallback`)
            // Fallback: try to match by string if field supports it
            departmentFilter = { [deptField]: departmentInfo }
          }
        } catch (error) {
          console.error('Error looking up department:', error)
          // Fallback to original string match
          departmentFilter = { [deptField]: departmentInfo }
        }
      }
    }

    console.log('QueryFilters: 🏢 Department filter created:', {
      resource,
      departmentInfo,
      deptField,
      departmentFilter,
      success: !!departmentFilter
    })

    return departmentFilter
  }

  /**
   * Resource-specific assignment field mapping
   */
  private static getAssignedFilter(resource: string, userId: string): any {
    const resourceAssignmentMap: Record<string, string> = {
      users: 'assignedTo',
      projects: 'assignedUsers',
      tasks: 'assignedTo',
      leads: 'assignedTo',
      proposals: 'assignedTo',
      // Add more as needed
    }

    const assignedField = resourceAssignmentMap[resource]
    if (!assignedField) return null

    // Handle array vs single value assignments
    if (assignedField.includes('assignedUsers')) {
      return { [assignedField]: { $in: [userId] } }
    }

    return { [assignedField]: userId }
  }

  /**
   * Resource-specific subordinate filtering
   */
  private static getSubordinateFilter(resource: string, subordinateIds: string[]): any {
    // For most resources, subordinate access means records owned by subordinates
    const ownerFilter = this.getOwnershipFilter(resource, subordinateIds[0])
    if (!ownerFilter) return null

    const ownerField = Object.keys(ownerFilter)[0]
    return { [ownerField]: { $in: subordinateIds } }
  }

  /**
   * Get user's subordinate IDs with caching
   */
  static async getSubordinateIds(userId: string): Promise<string[]> {
    try {
      // Use dynamic import to avoid ES module issues
      const { default: User } = await import('@/models/User')
      const subordinates = await User.find({ 
        reportsTo: userId,
        status: 'active' 
      }).select('_id').lean()
      
      return subordinates.map((user: any) => user._id.toString())
    } catch (error) {
      console.error('Error getting subordinate IDs:', error)
      return []
    }
  }

  /**
   * Check if user is superadmin
   */
  static isSuperAdmin(user: any): boolean {
    // Check multiple ways a user might be superadmin
    const isSuper = (
      user.role?.name === 'super_admin' ||
      user.role === 'super_admin' ||
      user.isSuperAdmin === true
    )
    
    console.log('QueryFilters: Superadmin check:', {
      user:user,
      userEmail: user.email,
      roleName: user.role,
      roleDisplayName: user.displayName,
      hierarchyLevel: user.role?.hierarchyLevel,
      isSuperAdmin: isSuper
    })
    
    return isSuper
  }

  /**
   * Clear department cache (useful for testing or when departments change)
   */
  static clearDepartmentCache(): void {
    this.departmentCache.clear()
    console.log('QueryFilters: Department cache cleared')
  }
}