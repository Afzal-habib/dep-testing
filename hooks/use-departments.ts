import { useCallback, useMemo } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import {
  setDepartments,
  setSelectedDepartment,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats, // ✅ ADD THIS IMPORT
  resetState,
} from '@/store/slices/departmentSlice'
import {
  useGenericQuery,
  useGenericQueryById,
  useGenericCreate,
  useGenericUpdate,
  useGenericDelete,
  type UseGenericQueryOptions,
} from './use-generic-query'
import type {
  FetchDepartmentsParams,
  CreateDepartmentData,
  UpdateDepartmentData,
  DepartmentFilters,
  DepartmentSort,
} from '@/types'

export function useDepartments() {
  const dispatch = useAppDispatch()

  const {
    departments,
    selectedDepartment,
    loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats, // ✅ ADD THIS LINE
  } = useAppSelector((state) => state.departments)

  // Define options for generic hooks
  const departmentOptions: UseGenericQueryOptions<any> = {
    entityName: 'departments',
    baseUrl: '/api/departments',
    reduxDispatchers: {
      setEntities: (entities) => dispatch(setDepartments(entities)),
      setEntity: (entity) => dispatch(setSelectedDepartment(entity)),
      setPagination: (pagination) => dispatch(setPagination(pagination)),
      setStats: (stats) => dispatch(setStats(stats)), // ✅ ADD THIS LINE
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

  const allDepartmentsParams = useMemo(() => ({
    page: 1,
    limit: 100,
    filters: { status: 'active', category: '' },
    sort: {
      field: 'name' as const,
      direction: 'asc' as const,
    },
  }), [])

  // Use generic hooks with better caching
  const { data: fetchedDepartments, isLoading: queryLoading, refetch: refetchDepartments } = useGenericQuery(
    departmentOptions,
    queryParams,
    true,
    {
      staleTime: 10 * 60 * 1000, // 10 minutes (departments change less frequently)
      gcTime: 30 * 60 * 1000, // 30 minutes
      refetchOnWindowFocus: false,
      refetchOnMount: false,
      retry: 2,
    }
  )

  // Separate query for fetching all departments (for filters/dropdowns) with longer cache
  const { data: allDepartments } = useGenericQuery(
    departmentOptions,
    allDepartmentsParams,
    true,
    {
      staleTime: 15 * 60 * 1000, // 15 minutes
      gcTime: 60 * 60 * 1000, // 1 hour
      refetchOnWindowFocus: false,
      refetchOnMount: false,
      retry: 2,
    }
  )

  const createMutation = useGenericCreate(departmentOptions)
  const updateMutation = useGenericUpdate(departmentOptions)
  const deleteMutation = useGenericDelete(departmentOptions)

  // Fetch operations - Stable function that doesn't change on re-renders
  const handleFetchDepartments = useCallback((params?: FetchDepartmentsParams) => {
    refetchDepartments()
  }, [refetchDepartments])

  // CRUD operations
  const handleCreateDepartment = useCallback((departmentData: CreateDepartmentData) => {
    return createMutation.mutateAsync(departmentData)
  }, [createMutation])

  const handleUpdateDepartment = useCallback((id: string, data: UpdateDepartmentData) => {
    return updateMutation.mutateAsync({ id, data })
  }, [updateMutation])

  const handleDeleteDepartment = useCallback((departmentId: string) => {
    return deleteMutation.mutateAsync(departmentId)
  }, [deleteMutation])

  const handleRestoreDepartment = useCallback(async (departmentId: string) => {
    return await updateMutation.mutateAsync({
      id: departmentId,
      data: {
        isDeleted: false,
        status: 'active'
      }
    })
  }, [updateMutation])

  // Filter and sort operations
  const handleSetFilters = useCallback((newFilters: Partial<DepartmentFilters>) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  const handleSetSort = useCallback((newSort: DepartmentSort) => {
    dispatch(setSort(newSort))
  }, [dispatch])

  const handleSetPagination = useCallback((newPagination: { page?: number; limit?: number }) => {
    dispatch(setPagination(newPagination))
  }, [dispatch])

  const handleSetSelectedDepartment = useCallback((department: any) => {
    dispatch(setSelectedDepartment(department))
  }, [dispatch])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleResetDepartments = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  const refreshDepartments = useCallback(() => {
    return handleFetchDepartments()
  }, [handleFetchDepartments])

  // Computed values
  const hasDepartments = departments.length > 0
  const isFirstPage = pagination.page === 1
  const isLastPage = pagination.page >= pagination.pages
  const totalPages = pagination.pages
  const totalItems = pagination.total

  // Department utilities
  const getDepartmentById = useCallback((departmentId: string) => {
    return departments.find(dept => dept._id === departmentId)
  }, [departments])

  const getActiveDepartments = useCallback(() => {
    return departments.filter(dept => dept.status === 'active')
  }, [departments])

  return {
    // State
    departments: fetchedDepartments || departments,
    allDepartments: allDepartments || [],
    selectedDepartment,
    loading: queryLoading || loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats, // ✅ ADD THIS LINE

    // Actions
    fetchDepartments: handleFetchDepartments,
    createDepartment: handleCreateDepartment,
    updateDepartment: handleUpdateDepartment,
    deleteDepartment: handleDeleteDepartment,
    restoreDepartment: handleRestoreDepartment,

    // Filters and pagination
    setFilters: handleSetFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,
    setSelectedDepartment: handleSetSelectedDepartment,

    // Utilities
    clearError: handleClearError,
    resetDepartments: handleResetDepartments,
    refreshDepartments,

    // Computed values
    hasDepartments,
    isFirstPage,
    isLastPage,
    totalPages,
    totalItems,

    // Department utilities
    getDepartmentById,
    getActiveDepartments,
  }
}