import { useCallback, useMemo } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import {
  setRoles,
  setSelectedRole,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats,
  resetState,
} from '@/store/slices/roleSlice'
import {
  useGenericQuery,
  useGenericQueryById,
  useGenericCreate,
  useGenericUpdate,
  useGenericDelete,
  type UseGenericQueryOptions,
} from './use-generic-query'
import { apiRequest, handleAPIError } from '@/lib/utils/api-client'
import type {
  Role,
  RoleFilters,
  RoleSort,
  CreateRoleData,
} from '@/types'

export interface FetchRolesParams {
  page?: number
  limit?: number
  filters?: RoleFilters
  sort?: RoleSort
}

export interface UpdateRoleData extends Partial<CreateRoleData> {
  _id: string
  status?: "active" | "inactive" | "archived"
}

export function useRoles() {
  const dispatch = useAppDispatch()

  const {
    roles,
    selectedRole,
    loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.roles)

  // Define options for generic hooks
  const roleOptions: UseGenericQueryOptions<any> = {
    entityName: 'roles',
    baseUrl: '/api/roles',
    reduxDispatchers: {
      setEntities: (entities) => dispatch(setRoles(entities)),
      setEntity: (entity) => dispatch(setSelectedRole(entity)),
      setPagination: (pagination) => dispatch(setPagination(pagination)),
      setStats: (stats) => dispatch(setStats(stats)),
      setLoading: (loading) => dispatch(setLoading(loading)),
      setActionLoading: (loading) => dispatch(setActionLoading(loading)),
      setError: (error) => dispatch(setError(error)),
      clearError: () => dispatch(clearError()),
    },
  }

  // Memoize query params to prevent unnecessary re-renders
  const queryParams = useMemo(() => ({
    page: pagination.page,
    limit: pagination.limit,
    filters,
    sort: {
      field: sort.field,
      direction: sort.direction as 'asc' | 'desc',
    },
  }), [pagination.page, pagination.limit, filters, sort.field, sort.direction])

  const allRolesParams = useMemo(() => ({
    page: 1,
    limit: 100,
    filters: {},
    sort: {
      field: 'name' as const,
      direction: 'asc' as const,
    },
  }), [])

  // Use generic hooks
  const { data: fetchedRoles, isLoading: queryLoading, refetch: refetchRoles } = useGenericQuery(
    roleOptions,
    queryParams,
    true
  )

  // Separate query for fetching all roles (for filters/dropdowns)
  const { data: allRoles } = useGenericQuery(
    roleOptions,
    allRolesParams,
    true
  )

  const createMutation = useGenericCreate(roleOptions)
  const updateMutation = useGenericUpdate(roleOptions)
  const deleteMutation = useGenericDelete(roleOptions)

  // Fetch operations - Stable function that doesn't change on re-renders
  const handleFetchRoles = useCallback((params?: FetchRolesParams) => {
    refetchRoles()
  }, [refetchRoles])

  // CRUD operations
  const handleCreateRole = useCallback((roleData: CreateRoleData) => {
    return createMutation.mutateAsync(roleData)
  }, [createMutation])

  const handleUpdateRole = useCallback((id: string, data: UpdateRoleData) => {
    return updateMutation.mutateAsync({ id, data })
  }, [updateMutation])

  const handleDeleteRole = useCallback((roleId: string) => {
    return deleteMutation.mutateAsync(roleId)
  }, [deleteMutation])

  const handleRestoreRole = useCallback(async (roleId: string) => {
    return await updateMutation.mutateAsync({
      id: roleId,
      data: {
        isDeleted: false,
        status: 'active'
      }
    })
  }, [updateMutation])

  // Role-specific operations
  const handleFetchRoleById = useCallback(async (roleId: string) => {
    try {
      dispatch(setActionLoading(true))
      const response = await apiRequest(`/api/roles/${roleId}`)
      const role = response.data || response
      dispatch(setSelectedRole(role))
      dispatch(setActionLoading(false))
      return role
    } catch (error) {
      dispatch(setError(error))
      dispatch(setActionLoading(false))
      handleAPIError(error, 'Failed to fetch role')
      throw error
    }
  }, [dispatch])

  const handleFetchRolesByDepartment = useCallback(async (departmentId: string) => {
    try {
      dispatch(setLoading(true))
      const response = await apiRequest(`/api/departments/${departmentId}/roles`)
      const data = response?.data || response || []
      dispatch(setLoading(false))
      return data
    } catch (error) {
      dispatch(setError(error))
      dispatch(setLoading(false))
      handleAPIError(error, 'Failed to fetch roles by department')
      throw error
    }
  }, [dispatch])

  const handleUpdateRolePermissions = useCallback(async (roleId: string, permissions: any[]) => {
    try {
      dispatch(setActionLoading(true))
      const response = await apiRequest(`/api/roles/${roleId}/permissions`, {
        method: 'PUT',
        body: JSON.stringify({ permissions })
      })

      // Update the role in state
      const updatedRole = response.data || response
      const index = roles.findIndex(role => role._id === updatedRole._id)
      if (index !== -1) {
        const updatedRoles = [...roles]
        updatedRoles[index] = updatedRole
        dispatch(setRoles(updatedRoles))
      }
      if (selectedRole?._id === updatedRole._id) {
        dispatch(setSelectedRole(updatedRole))
      }

      dispatch(setActionLoading(false))
      return response
    } catch (error) {
      dispatch(setError(error))
      dispatch(setActionLoading(false))
      handleAPIError(error, 'Failed to update role permissions')
      throw error
    }
  }, [dispatch, roles, selectedRole])

  // Filter and sort operations
  const handleSetFilters = useCallback((newFilters: Partial<RoleFilters>) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  const handleSetSort = useCallback((newSort: RoleSort) => {
    dispatch(setSort(newSort))
  }, [dispatch])

  const handleSetPagination = useCallback((newPagination: { page?: number; limit?: number }) => {
    dispatch(setPagination(newPagination))
  }, [dispatch])

  const handleSetSelectedRole = useCallback((role: any) => {
    dispatch(setSelectedRole(role))
  }, [dispatch])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleResetRoles = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  const refreshRoles = useCallback(() => {
    return handleFetchRoles()
  }, [handleFetchRoles])

  // Computed values
  const hasRoles = roles.length > 0
  const isFirstPage = pagination.page === 1
  const isLastPage = pagination.page >= pagination.pages
  const totalPages = pagination.pages
  const totalItems = pagination.total

  // Role utilities
  const getRoleById = useCallback((roleId: string) => {
    return roles.find(role => role._id === roleId)
  }, [roles])

  const getRolesByDepartment = useCallback((departmentId: string) => {
    return roles.filter(role => role.department === departmentId ||
      (typeof role.department === 'object' && role.department?._id === departmentId))
  }, [roles])

  const getSystemRoles = useCallback(() => {
    return roles.filter(role => role.isSystemRole)
  }, [roles])

  const getDepartmentRoles = useCallback(() => {
    return roles.filter(role => !role.isSystemRole)
  }, [roles])

  const getActiveRoles = useCallback(() => {
    return roles.filter(role => role.status === 'active')
  }, [roles])

  return {
    // State
    roles: fetchedRoles || roles,
    allRoles: allRoles || [],
    selectedRole,
    loading: queryLoading || loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,

    // Actions
    fetchRoles: handleFetchRoles,
    fetchRoleById: handleFetchRoleById,
    fetchRolesByDepartment: handleFetchRolesByDepartment,
    createRole: handleCreateRole,
    updateRole: handleUpdateRole,
    updateRolePermissions: handleUpdateRolePermissions,
    deleteRole: handleDeleteRole,
    restoreRole: handleRestoreRole,

    // Filters and pagination
    setFilters: handleSetFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,
    setSelectedRole: handleSetSelectedRole,

    // Utilities
    clearError: handleClearError,
    resetRoles: handleResetRoles,
    refreshRoles,

    // Computed values
    hasRoles,
    isFirstPage,
    isLastPage,
    totalPages,
    totalItems,

    // Role utilities
    getRoleById,
    getRolesByDepartment,
    getSystemRoles,
    getDepartmentRoles,
    getActiveRoles,
  }
}