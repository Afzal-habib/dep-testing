import { useCallback, useEffect, useMemo, useState } from 'react'
import { useAppDispatch, useAppSelector } from './redux'
import { handleAPIError } from '@/lib/utils/api-client'
import { useToast } from './use-toast'

export interface CRUDState<T> {
  items: T[]
  selectedItem: T | null
  loading: boolean
  actionLoading: boolean
  error: any
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
  filters: Record<string, any>
  sort: {
    field: string
    direction: 'asc' | 'desc'
  }
}

export interface CRUDActions<T, CreateData, UpdateData> {
  fetchItems: any // Async thunk
  fetchItemById: any // Async thunk
  createItem: any // Async thunk
  updateItem: any // Async thunk
  deleteItem: any // Async thunk
  setFilters: (filters: Record<string, any>) => any
  setSort: (sort: { field: string; direction: 'asc' | 'desc' }) => any
  setPagination: (pagination: Partial<CRUDState<T>['pagination']>) => any
  setSelectedItem: (item: T | null) => any
  clearError: () => any
}

export interface CRUDConfig<T, CreateData, UpdateData> {
  name: string // e.g., 'departments', 'users'
  actions: CRUDActions<T, CreateData, UpdateData>
  defaultSort?: { field: string; direction: 'asc' | 'desc' }
  defaultFilters?: Record<string, any>
  cache?: {
    enabled: boolean
    ttl?: number
  }
}

/**
 * Generic CRUD hook that can be used as a blueprint for any entity
 */
export function useGenericCRUD<T, CreateData, UpdateData>(
  config: CRUDConfig<T, CreateData, UpdateData>
) {
  const dispatch = useAppDispatch()
  const { toast } = useToast()

  const {
    name,
    actions,
    defaultSort = { field: 'createdAt', direction: 'desc' },
    defaultFilters = {},
    cache = { enabled: false, ttl: 5 * 60 * 1000 }
  } = config

  // Get state from Redux store
  const state = useAppSelector((state: any) => state[name]) as CRUDState<T>

  // Local state for preventing duplicate calls
  const [lastFetchParams, setLastFetchParams] = useState<string>('')

  // Memoized parameters to prevent unnecessary re-renders
  const memoizedFilters = useMemo(() => state.filters, [JSON.stringify(state.filters)])
  const memoizedSort = useMemo(() => state.sort, [state.sort.field, state.sort.direction])
  const memoizedPagination = useMemo(() => ({
    page: state.pagination.page,
    limit: state.pagination.limit
  }), [state.pagination.page, state.pagination.limit])

  // Fetch items with deduplication
  const fetchItems = useCallback(async (params?: any) => {
    const fetchParams = params || {
      page: memoizedPagination.page,
      limit: memoizedPagination.limit,
      filters: memoizedFilters,
      sort: memoizedSort
    }

    const paramsKey = JSON.stringify(fetchParams)

    // Prevent duplicate calls with same parameters
    if (paramsKey === lastFetchParams && state.loading) {
      return
    }

    setLastFetchParams(paramsKey)

    try {
      await dispatch(actions.fetchItems(fetchParams)).unwrap()
    } catch (error) {
      handleAPIError(error, `Failed to load ${name}`)
    }
  }, [dispatch, actions, memoizedPagination, memoizedFilters, memoizedSort, lastFetchParams, state.loading, name])

  // CRUD operations
  const createItem = useCallback(async (data: CreateData) => {
    try {
      const result = await dispatch(actions.createItem(data)).unwrap()
      toast({
        title: "Success",
        description: `${name.slice(0, -1)} created successfully`,
      })
      // Refresh the list
      fetchItems()
      return result
    } catch (error) {
      handleAPIError(error, `Failed to create ${name.slice(0, -1)}`)
      throw error
    }
  }, [dispatch, actions, toast, name, fetchItems])

  const updateItem = useCallback(async (id: string, data: UpdateData) => {
    try {
      const result = await dispatch(actions.updateItem(id, data)).unwrap()
      toast({
        title: "Success",
        description: `${name.slice(0, -1)} updated successfully`,
      })
      // Refresh the list
      fetchItems()
      return result
    } catch (error) {
      handleAPIError(error, `Failed to update ${name.slice(0, -1)}`)
      throw error
    }
  }, [dispatch, actions, toast, name, fetchItems])

  const deleteItem = useCallback(async (id: string) => {
    try {
      await dispatch(actions.deleteItem(id)).unwrap()
      toast({
        title: "Success",
        description: `${name.slice(0, -1)} deleted successfully`,
      })
      // Refresh the list
      fetchItems()
    } catch (error) {
      handleAPIError(error, `Failed to delete ${name.slice(0, -1)}`)
      throw error
    }
  }, [dispatch, actions, toast, name, fetchItems])

  const fetchItemById = useCallback(async (id: string) => {
    try {
      return await dispatch(actions.fetchItemById(id)).unwrap()
    } catch (error) {
      handleAPIError(error, `Failed to load ${name.slice(0, -1)}`)
      throw error
    }
  }, [dispatch, actions, name])

  // Filter and sort operations
  const setFilters = useCallback((filters: Record<string, any>) => {
    dispatch(actions.setFilters(filters))
  }, [dispatch, actions])

  const setSort = useCallback((sort: { field: string; direction: 'asc' | 'desc' }) => {
    dispatch(actions.setSort(sort))
  }, [dispatch, actions])

  const setPagination = useCallback((pagination: Partial<CRUDState<T>['pagination']>) => {
    dispatch(actions.setPagination(pagination))
  }, [dispatch, actions])

  const setSelectedItem = useCallback((item: T | null) => {
    dispatch(actions.setSelectedItem(item))
  }, [dispatch, actions])

  const clearError = useCallback(() => {
    dispatch(actions.clearError())
  }, [dispatch, actions])

  // Computed values
  const hasItems = state.items.length > 0
  const isFirstPage = state.pagination.page === 1
  const isLastPage = state.pagination.page >= state.pagination.pages
  const totalPages = state.pagination.pages
  const totalItems = state.pagination.total

  // Utility functions
  const getItemById = useCallback((id: string) => {
    return state.items.find((item: any) => item._id === id || item.id === id)
  }, [state.items])

  // Auto-fetch on mount and when dependencies change
  useEffect(() => {
    fetchItems()
  }, [memoizedPagination.page, memoizedPagination.limit, memoizedFilters, memoizedSort])

  // Error handling effect
  useEffect(() => {
    if (state.error) {
      handleAPIError(state.error, `Failed to load ${name}`)
      clearError()
    }
  }, [state.error, name, clearError])

  return {
    // State
    ...state,

    // Actions
    fetchItems,
    createItem,
    updateItem,
    deleteItem,
    fetchItemById,

    // Filters and pagination
    setFilters,
    setSort,
    setPagination,
    setSelectedItem,

    // Utilities
    clearError,

    // Computed values
    hasItems,
    isFirstPage,
    isLastPage,
    totalPages,
    totalItems,

    // Helper functions
    getItemById,
  }
}