import { useCallback, useEffect, useMemo, useState, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { refreshAnalytics } from '@/lib/utils/analytics-refresh'
import { useAppSelector, useAppDispatch } from './redux'
import {
  setPhases,
  setSelectedPhase,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats,
  resetState,
} from '@/store/slices/phaseSlice'
import {
  useGenericQuery,
  useGenericQueryById,
  useGenericCreate,
  useGenericUpdate,
  useGenericDelete,
  type UseGenericQueryOptions,
} from './use-generic-query'
import type {
  CreatePhaseData,
  UpdatePhaseData,
} from '@/lib/validations/phase'

// Extended type for update operations that may need projectId for analytics
type ExtendedUpdatePhaseData = UpdatePhaseData & { projectId?: string }

export function usePhases() {
  const dispatch = useAppDispatch()
  const queryClient = useQueryClient()

  const {
    phases,
    selectedPhase,
    loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.phases)

  // Define options for generic hooks
  const phaseOptions: UseGenericQueryOptions<any> = {
    entityName: 'phases',
    baseUrl: '/api/phases',
    reduxDispatchers: {
      setEntities: (entities) => dispatch(setPhases(entities)),
      setEntity: (entity) => dispatch(setSelectedPhase(entity)),
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

  // Use generic hooks
  const { data: fetchedPhases, isLoading: queryLoading, refetch: refetchPhases } = useGenericQuery(
    phaseOptions,
    queryParams,
    true
  )

  const createMutation = useGenericCreate(phaseOptions)
  const updateMutation = useGenericUpdate(phaseOptions)
  const deleteMutation = useGenericDelete(phaseOptions)

  // CRUD operations following Department pattern
  const handleFetchPhases = useCallback((params: any = {}) => {
    if (params.projectId !== undefined) {
      dispatch(setFilters({ projectId: params.projectId }))
    }
    return refetchPhases()
  }, [dispatch, refetchPhases])

  const handleCreatePhase = useCallback(async (phaseData: CreatePhaseData) => {
    try {
      const result = await createMutation.mutateAsync(phaseData)
      
      // Invalidate and refetch to ensure UI is in sync
      await refetchPhases()
      
      // Trigger analytics refresh
      if (phaseData.projectId) {
        refreshAnalytics({ projectId: phaseData.projectId, queryClient })
      }
      
      return result
    } catch (error) {
      console.error('Error creating phase:', error)
      throw error
    }
  }, [createMutation, refetchPhases, queryClient])

  const handleUpdatePhase = useCallback(async (id: string, data: ExtendedUpdatePhaseData) => {
    try {
      const result = await updateMutation.mutateAsync({ id, data })
      
      // Invalidate and refetch to ensure UI is in sync
      await refetchPhases()
      
      // Trigger analytics refresh
      const currentPhase = phases.find((p: any) => p._id === id)
      const projectId = data?.projectId || currentPhase?.projectId
      if (projectId) {
        refreshAnalytics({ projectId, queryClient })
      }
      
      return result
    } catch (error) {
      console.error('Error updating phase:', error)
      throw error
    }
  }, [updateMutation, refetchPhases, queryClient, phases])

  const handleDeletePhase = useCallback(async (phaseId: string) => {
    try {
      const phaseToDelete = phases.find((p: any) => p._id === phaseId)
      const result = await deleteMutation.mutateAsync(phaseId)
      
      // Invalidate and refetch to ensure UI is in sync
      await refetchPhases()
      
      // Trigger analytics refresh
      if (phaseToDelete?.projectId) {
        refreshAnalytics({ projectId: phaseToDelete.projectId, queryClient })
      }
      
      return result
    } catch (error) {
      console.error('Error deleting phase:', error)
      throw error
    }
  }, [deleteMutation, refetchPhases, queryClient, phases])

  // Individual phase loading states
  const [individualLoading, setIndividualLoading] = useState<Record<string, boolean>>({})

  // Quick status and end date updates with optimistic updates
  const handleUpdatePhaseStatus = useCallback(async (id: string, status: 'pending' | 'planning' | 'in-progress' | 'on-hold' | 'completed' | 'cancelled') => {
    setIndividualLoading(prev => ({ ...prev, [id]: true }))
    
    // Optimistic update
    const currentPhase = phases.find((p: any) => p._id === id)
    if (currentPhase) {
      const updatedPhases = phases.map((p: any) => 
        p._id === id ? { ...p, status } : p
      )
      dispatch(setPhases(updatedPhases))
    }
    
    try {
      await handleUpdatePhase(id, { status })
      // Refetch to ensure sync
      await refetchPhases()
    } catch (error) {
      // Revert optimistic update on error
      if (currentPhase) {
        const revertedPhases = phases.map((p: any) => 
          p._id === id ? currentPhase : p
        )
        dispatch(setPhases(revertedPhases))
      }
      throw error
    } finally {
      setIndividualLoading(prev => ({ ...prev, [id]: false }))
    }
  }, [dispatch, phases, handleUpdatePhase, refetchPhases])

  const handleUpdatePhaseEndDate = useCallback(async (id: string, endDate: string) => {
    setIndividualLoading(prev => ({ ...prev, [id]: true }))
    
    // Optimistic update
    const currentPhase = phases.find((p: any) => p._id === id)
    if (currentPhase) {
      const updatedPhases = phases.map((p: any) => 
        p._id === id ? { ...p, endDate } : p
      )
      dispatch(setPhases(updatedPhases))
    }
    
    try {
      await handleUpdatePhase(id, { endDate: new Date(endDate) })
      // Refetch to ensure sync
      await refetchPhases()
    } catch (error) {
      // Revert optimistic update on error
      if (currentPhase) {
        const revertedPhases = phases.map((p: any) => 
          p._id === id ? currentPhase : p
        )
        dispatch(setPhases(revertedPhases))
      }
      throw error
    } finally {
      setIndividualLoading(prev => ({ ...prev, [id]: false }))
    }
  }, [dispatch, phases, handleUpdatePhase, refetchPhases])

  // Check if individual phase is loading
  const isPhaseLoading = useCallback((id: string) => {
    return individualLoading[id] || false
  }, [individualLoading])

  // Filter and sort operations
  const handleSetFilters = useCallback((newFilters: any) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  const handleSetSort = useCallback((newSort: any) => {
    dispatch(setSort(newSort))
  }, [dispatch])

  const handleSetPagination = useCallback((newPagination: any) => {
    dispatch(setPagination(newPagination))
  }, [dispatch])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleResetState = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  const refreshPhases = useCallback(() => {
    return handleFetchPhases({ projectId: filters.projectId })
  }, [handleFetchPhases, filters.projectId])

  // Analytics operations
  const handleGetPhaseAnalytics = useCallback(async (projectId?: string, departmentId?: string) => {
    try {
      const params = new URLSearchParams()
      if (projectId) params.append('projectId', projectId)
      if (departmentId) params.append('departmentId', departmentId)
      params.append('type', 'overview')

      const response = await fetch(`/api/phases/analytics?${params.toString()}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to get phase analytics')
      }

      return result.data

    } catch (error: any) {
      dispatch(setError(error.message))
      throw error
    }
  }, [dispatch])

  const handleGetPhaseTimeline = useCallback(async (projectId: string) => {
    try {
      const response = await fetch(`/api/phases/analytics?projectId=${projectId}&type=timeline`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to get phase timeline')
      }

      return result.data

    } catch (error: any) {
      dispatch(setError(error.message))
      throw error
    }
  }, [dispatch])

  const handleGetPhaseTaskAnalytics = useCallback(async (phaseId: string) => {
    try {
      const response = await fetch(`/api/phases/analytics?phaseId=${phaseId}&type=tasks`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to get phase task analytics')
      }

      return result.data

    } catch (error: any) {
      dispatch(setError(error.message))
      throw error
    }
  }, [dispatch])

  const handleGetCustomAnalytics = useCallback(async (filters: any) => {
    try {
      const response = await fetch('/api/phases/analytics', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(filters),
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to get custom analytics')
      }

      return result.data

    } catch (error: any) {
      dispatch(setError(error.message))
      throw error
    }
  }, [dispatch])

  // Computed values
  const hasPhases = phases.length > 0
  const completedPhases = phases.filter(p => p.status === 'completed')
  const activePhases = phases.filter(p => p.status === 'in-progress')
  const plannedPhases = phases.filter(p => p.status === 'pending' || p.status === 'planning')
  const overduePhases = phases.filter(p => {
    if (p.status === 'completed') return false
    return new Date(p.endDate) < new Date()
  })

  const overallProgress = useMemo(() => {
    if (phases.length === 0) return 0
    const totalProgress = phases.reduce((sum: number, phase) => sum + (phase.progress || 0), 0)
    return Math.round(totalProgress / phases.length)
  }, [phases])

  return {
    // State
    phases: fetchedPhases || phases,
    selectedPhase,
    loading: queryLoading || loading,
    actionLoading: createMutation.isPending || updateMutation.isPending || deleteMutation.isPending || actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,

    // Computed values
    hasPhases,
    completedPhases,
    activePhases,
    plannedPhases,
    overduePhases,
    overallProgress,

    // CRUD operations
    fetchPhases: handleFetchPhases,
    createPhase: handleCreatePhase,
    updatePhase: handleUpdatePhase,
    deletePhase: handleDeletePhase,

    // Quick updates
    updatePhaseStatus: handleUpdatePhaseStatus,
    updatePhaseEndDate: handleUpdatePhaseEndDate,
    isPhaseLoading,
    individualLoading,

    // Filter and sort operations
    setFilters: handleSetFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,

    // Analytics operations
    getPhaseAnalytics: handleGetPhaseAnalytics,
    getPhaseTimeline: handleGetPhaseTimeline,
    getPhaseTaskAnalytics: handleGetPhaseTaskAnalytics,
    getCustomAnalytics: handleGetCustomAnalytics,

    // Utility operations
    clearError: handleClearError,
    resetState: handleResetState,
    refreshPhases,
    refetch: refetchPhases,
  }
}

// Single phase query hook using generic approach
export function usePhase(phaseId: string) {
  const dispatch = useAppDispatch()

  const phaseOptions: UseGenericQueryOptions<any> = {
    entityName: 'phases',
    baseUrl: '/api/phases',
    reduxDispatchers: {
      setEntity: (entity) => dispatch(setSelectedPhase(entity)),
      setLoading: (loading) => dispatch(setLoading(loading)),
      setError: (error) => dispatch(setError(error)),
      clearError: () => dispatch(clearError()),
    },
  }

  const { data: phase, isLoading, error, refetch } = useGenericQueryById(
    phaseOptions,
    phaseId,
    !!phaseId
  )

  return {
    phase,
    loading: isLoading,
    error,
    refetch,
  }
}

// Project-specific phases hook
export function useProjectPhases(projectId: string) {
  const { 
    phases, 
    setFilters, 
    refreshPhases,
    filters,
    ...rest 
  } = usePhases()

  const initializedRef = useRef(false)

  // Filter phases by project automatically using useEffect
  useEffect(() => {
    // Only set filters on first mount or if projectId changes
    if (projectId && (!initializedRef.current || filters.projectId !== projectId)) {
      setFilters({ projectId })
      initializedRef.current = true
    }
  }, [projectId, filters.projectId, setFilters])

  const projectPhases = useMemo(() => {
    // Since the API already filters by projectId, no need to filter again
    return phases
  }, [phases])

  return {
    phases: projectPhases,
    filters,
    ...rest,
    setFilters, // Add setFilters to the return
    refreshPhases: () => refreshPhases(),
  }
}

// Combined hook for ease of use (keeping backward compatibility)
export function usePhaseManagement(projectId?: string) {
  return projectId ? useProjectPhases(projectId) : usePhases()
}