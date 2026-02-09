import { useCallback } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import { 
  fetchSystemPermissions,
  setFilters,
  clearError,
  resetSystemPermissions,
  type SystemPermissionFilters,
} from '@/store/slices/systemPermissionSlice'

export function useSystemPermissions() {
  const dispatch = useAppDispatch()
  
  const {
    permissions,
    groupedPermissions,
    loading,
    error,
    filters,
  } = useAppSelector((state) => state.systemPermissions)
  
  // Fetch operations
  const handleFetchSystemPermissions = useCallback((permissionFilters?: SystemPermissionFilters) => {
    return dispatch(fetchSystemPermissions(permissionFilters || filters))
  }, [dispatch, filters])

  // Filter operations
  const handleSetFilters = useCallback((newFilters: Partial<SystemPermissionFilters>) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleResetSystemPermissions = useCallback(() => {
    dispatch(resetSystemPermissions())
  }, [dispatch])

  const refreshSystemPermissions = useCallback(() => {
    return handleFetchSystemPermissions()
  }, [handleFetchSystemPermissions])

  // Computed values
  const hasPermissions = permissions.length > 0
  const categories = Object.keys(groupedPermissions)
  const totalPermissions = permissions.length

  // Permission utilities
  const getPermissionsByCategory = useCallback((category: string) => {
    return groupedPermissions[category] || []
  }, [groupedPermissions])

  const getPermissionByResource = useCallback((resource: string) => {
    return permissions.find(permission => permission.resource === resource)
  }, [permissions])

  const getCorePermissions = useCallback(() => {
    return permissions.filter(permission => permission.isCore)
  }, [permissions])

  const getActivePermissions = useCallback(() => {
    return permissions.filter(permission => permission.status === 'active')
  }, [permissions])

  const getPermissionActions = useCallback((resource: string) => {
    const permission = getPermissionByResource(resource)
    return permission?.availableActions.map(action => action.action) || []
  }, [getPermissionByResource])

  const getPermissionActionDescription = useCallback((resource: string, action: string) => {
    const permission = getPermissionByResource(resource)
    const actionInfo = permission?.availableActions.find(a => a.action === action)
    return actionInfo?.description || action
  }, [getPermissionByResource])

  const getPermissionConditions = useCallback((resource: string, action: string) => {
    const permission = getPermissionByResource(resource)
    const actionInfo = permission?.availableActions.find(a => a.action === action)
    return actionInfo?.conditions || []
  }, [getPermissionByResource])
  return {
    // State
    permissions,
    groupedPermissions,
    loading,
    error,
    filters,
    
    // Actions
    fetchSystemPermissions: handleFetchSystemPermissions,
    
    // Filters
    setFilters: handleSetFilters,
    
    // Utilities
    clearError: handleClearError,
    resetSystemPermissions: handleResetSystemPermissions,
    refreshSystemPermissions,
    
    // Computed values
    hasPermissions,
    categories,
    totalPermissions,
    
    // Permission utilities
    getPermissionsByCategory,
    getPermissionByResource,
    getCorePermissions,
    getActivePermissions,
    getPermissionActions,
    getPermissionActionDescription,
    getPermissionConditions,
  }
}