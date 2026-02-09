import { useCallback, useMemo, useState } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import type { User } from '@/types'
import {
  useGenericQuery,
  useGenericQueryById,
  useGenericCreate,
  useGenericUpdate,
  useGenericDelete,
  type FetchParams,
} from './use-generic-query'
import {
  setUsers,
  setFilters,
  setSort,
  setPagination,
  setSelectedUser,
  setStats,
  clearError,
  resetState,
  type UserFilters,
  type UserSort,
  type CreateUserData,
  type UpdateUserData,
} from '@/store/slices/userSlice'

export function useUsers() {
  const dispatch = useAppDispatch()

  const {
    users,
    selectedUser,
    loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.users)

  // Local state for fetching user by ID
  const [userIdToFetch, setUserIdToFetch] = useState<string | undefined>(undefined)

  // Memoize query params to prevent unnecessary re-renders
  const queryParams = useMemo(() => ({
    page: pagination.page,
    limit: pagination.limit,
    filters: {
      search: filters.search || '',
      role: filters.role || '',
      status: filters.status || '',
      department: filters.department || '',
    },
    sort: {
      field: sort.field,
      direction: sort.direction as 'asc' | 'desc',
    },
  }), [pagination.page, pagination.limit, filters.search, filters.role, filters.status, filters.department, sort.field, sort.direction])

  // Generic hooks for users
  const { data: fetchedUsers, isLoading: queryLoading, error: queryError, refetch } = useGenericQuery<User>(
    {

      entityName: 'users',
      baseUrl: '/api/users',
      reduxDispatchers: {
        setEntities: (entities: User[]) => {
          dispatch(setUsers(entities))
        },
        setPagination: (paginationData: any) => {
          dispatch(setPagination(paginationData))
        },
        setStats: (statsData: any) => {
          dispatch(setStats(statsData))
        },
        setLoading: (loading: boolean) => {
          // Loading is handled by TanStack Query
        },
        setActionLoading: (loading: boolean) => {
          // Action loading is handled by mutations
        },
        setError: (error: any) => {
          // Error handling is done in the generic hook
        },
        clearError: () => dispatch(clearError()),
      },
    },
    queryParams
  )

  // Fetch single user by ID
  const { data: fetchedUserById, isLoading: userByIdLoading } = useGenericQueryById<User>(
    {
      entityName: 'users',
      baseUrl: '/api/users',
      reduxDispatchers: {
        setEntity: (entity: User | null) => dispatch(setSelectedUser(entity)),
        setLoading: (loading: boolean) => {
          // Loading handled by query
        },
        setError: (error: any) => {
          // Error handled in generic hook
        },
        clearError: () => dispatch(clearError()),
      },
    },
    userIdToFetch,
    !!userIdToFetch
  )

  // Mutations
  const createMutation = useGenericCreate<User>({
    entityName: 'users',
    baseUrl: '/api/users',
    reduxDispatchers: {
      setActionLoading: (loading: boolean) => {
        // Action loading handled by mutation
      },
      setError: (error: any) => {
        // Error handled in generic hook
      },
      clearError: () => dispatch(clearError()),
    },
  })

  const updateMutation = useGenericUpdate<User>({
    entityName: 'users',
    baseUrl: '/api/users',
    reduxDispatchers: {
      setActionLoading: (loading: boolean) => {
        // Action loading handled by mutation
      },
      setError: (error: any) => {
        // Error handled in generic hook
      },
      clearError: () => dispatch(clearError()),
    },
  })

  const deleteMutation = useGenericDelete<User>({
    entityName: 'users',
    baseUrl: '/api/users',
    reduxDispatchers: {
      setActionLoading: (loading: boolean) => {
        // Action loading handled by mutation
      },
      setError: (error: any) => {
        // Error handled in generic hook
      },
      clearError: () => dispatch(clearError()),
    },
  })

  // Stable CRUD operations
  const createUserData = useCallback(async (data: CreateUserData) => {
    return await createMutation.mutateAsync(data)
  }, [createMutation])

  const updateUserData = useCallback(async (data: UpdateUserData) => {
    const { _id, ...updateData } = data
    return await updateMutation.mutateAsync({ id: _id, data: updateData })
  }, [updateMutation])

  const deleteUserData = useCallback(async (userId: string) => {
    return await deleteMutation.mutateAsync(userId)
  }, [deleteMutation])

  const restoreUserData = useCallback(async (userId: string) => {
    return await updateMutation.mutateAsync({
      id: userId,
      data: {
        isDeleted: false,
        status: 'active'
      }
    })
  }, [updateMutation])

  const fetchUserByIdData = useCallback(async (userId: string) => {
    // Set the user ID to fetch
    setUserIdToFetch(userId)
  }, [])

  // Stable state setters
  const setFiltersData = useCallback((filters: UserFilters) => {
    dispatch(setFilters(filters))
  }, [dispatch])

  const setSortData = useCallback((sort: UserSort) => {
    dispatch(setSort(sort))
  }, [dispatch])

  const setPaginationData = useCallback((pagination: { page?: number; limit?: number; total?: number; pages?: number }) => {
    dispatch(setPagination(pagination))
  }, [dispatch])

  const setSelectedUserData = useCallback((user: User | null) => {
    dispatch(setSelectedUser(user))
  }, [dispatch])

  const clearErrorData = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const resetStateData = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  // Computed values
  const hasUsers = Array.isArray(users) && users.length > 0
  const isFirstPage = pagination?.page === 1
  const isLastPage = pagination ? pagination.page >= pagination.pages : false
  const totalPages = pagination?.pages || 0
  const totalItems = pagination?.total || 0

  // User utilities
  const getUserById = useCallback((userId: string) => {
    return Array.isArray(users) ? users.find(user => user._id === userId) : undefined
  }, [users])

  const getUsersByRole = useCallback((roleId: string) => {
    if (!Array.isArray(users)) return []
    return users.filter(user => user.role === roleId ||
      (typeof user.role === 'object' && user.role?._id === roleId))
  }, [users])

  const getUsersByDepartment = useCallback((departmentId: string) => {
    if (!Array.isArray(users)) return []
    return users.filter(user => user.department._id === departmentId ||
      (typeof user.department === 'object' && user.department?._id === departmentId))
  }, [users])

  const getActiveUsers = useCallback(() => {
    return Array.isArray(users) ? users.filter(user => user.status === 'active') : []
  }, [users])

  const getInactiveUsers = useCallback(() => {
    return Array.isArray(users) ? users.filter(user => user.status === 'inactive') : []
  }, [users])

  const getSuspendedUsers = useCallback(() => {
    return Array.isArray(users) ? users.filter(user => user.status === 'suspended') : []
  }, [users])

  const getUsersByStatus = useCallback((status: 'active' | 'inactive' | 'suspended') => {
    return Array.isArray(users) ? users.filter(user => user.status === status) : []
  }, [users])

  return {
    // State - combine Redux state with TanStack Query data
    users: fetchedUsers || users,
    selectedUser: fetchedUserById || selectedUser,
    loading: queryLoading || userByIdLoading || loading,
    actionLoading: createMutation.isPending || updateMutation.isPending || deleteMutation.isPending || actionLoading,
    error: queryError || error,
    filters,
    sort,
    pagination,
    stats,

    // Individual loading states
    queryLoading,
    userByIdLoading,

    // Actions
    fetchUsers: refetch, // Use TanStack Query refetch
    fetchUserById: fetchUserByIdData,
    createUser: createUserData,
    updateUser: updateUserData,
    deleteUser: deleteUserData,
    restoreUser: restoreUserData,

    // Filters and pagination
    setFilters: setFiltersData,
    setSort: setSortData,
    setPagination: setPaginationData,
    setSelectedUser: setSelectedUserData,

    // Utilities
    clearError: clearErrorData,
    resetState: resetStateData,

    // Computed values
    hasUsers,
    isFirstPage,
    isLastPage,
    totalPages,
    totalItems,

    // User utilities
    getUserById,
    getUsersByRole,
    getUsersByDepartment,
    getActiveUsers,
    getInactiveUsers,
    getSuspendedUsers,
    getUsersByStatus,
  }
}