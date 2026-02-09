import { useCallback, useMemo, useEffect, useState, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { refreshAnalytics } from '@/lib/utils/analytics-refresh'
import { useAppSelector, useAppDispatch } from './redux'
import {
  setMilestones,
  setSelectedMilestone,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats,
  resetState,
  updateMilestoneStatus,
  updateMilestoneProgress,
} from '@/store/slices/milestoneSlice'
import {
  useGenericQuery,
  useGenericQueryById,
  useGenericCreate,
  useGenericUpdate,
  useGenericDelete,
  type UseGenericQueryOptions,
} from './use-generic-query'
import type {
  CreateMilestoneData,
  UpdateMilestoneData,
} from '@/lib/validations/milestone'

// Extended type for update operations that may need projectId for analytics
type ExtendedUpdateMilestoneData = UpdateMilestoneData & { projectId?: string }

export function useMilestones() {
  const dispatch = useAppDispatch()
  const queryClient = useQueryClient()

  const {
    milestones,
    selectedMilestone,
    loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.milestones)

  // Define options for generic hooks
  const milestoneOptions: UseGenericQueryOptions<any> = {
    entityName: 'milestones',
    baseUrl: '/api/milestones',
    reduxDispatchers: {
      setEntities: (entities) => dispatch(setMilestones(entities)),
      setEntity: (entity) => dispatch(setSelectedMilestone(entity)),
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
  const { data: fetchedMilestones, isLoading: queryLoading, refetch: refetchMilestones } = useGenericQuery(
    milestoneOptions,
    queryParams,
    true
  )

  const createMutation = useGenericCreate(milestoneOptions)
  const updateMutation = useGenericUpdate(milestoneOptions)
  const deleteMutation = useGenericDelete(milestoneOptions)

  // CRUD operations following Department pattern
  const handleFetchMilestones = useCallback((params: any = {}) => {
    if (params.projectId !== undefined) {
      dispatch(setFilters({ projectId: params.projectId }))
    }
    if (params.phaseId !== undefined) {
      dispatch(setFilters({ phaseId: params.phaseId }))
    }
    return refetchMilestones()
  }, [dispatch, refetchMilestones])

  const handleCreateMilestone = useCallback(async (milestoneData: CreateMilestoneData) => {
    try {
      const result = await createMutation.mutateAsync(milestoneData)
      
      // Invalidate and refetch to ensure UI is in sync
      await refetchMilestones()
      
      // Trigger analytics refresh
      if (milestoneData.projectId) {
        refreshAnalytics({ projectId: milestoneData.projectId, queryClient })
      }
      
      return result
    } catch (error) {
      console.error('Error creating milestone:', error)
      throw error
    }
  }, [createMutation, queryClient])

  const handleUpdateMilestone = useCallback(async (id: string, data: ExtendedUpdateMilestoneData) => {
    try {
      const result = await updateMutation.mutateAsync({ id, data })
      
      // Invalidate and refetch to ensure UI is in sync
      await refetchMilestones()
      
      // Trigger analytics refresh
      const currentMilestone = milestones.find((m: any) => m._id === id)
      const projectId = data?.projectId || currentMilestone?.projectId
      if (projectId) {
        refreshAnalytics({ projectId, queryClient })
      }
      
      return result
    } catch (error) {
      console.error('Error updating milestone:', error)
      throw error
    }
  }, [updateMutation, queryClient, milestones])

  const handleDeleteMilestone = useCallback(async (milestoneId: string) => {
    try {
      const milestoneToDelete = milestones.find((m: any) => m._id === milestoneId)
      const result = await deleteMutation.mutateAsync(milestoneId)
      
      // Invalidate and refetch to ensure UI is in sync
      await refetchMilestones()
      
      // Trigger analytics refresh
      if (milestoneToDelete?.projectId) {
        refreshAnalytics({ projectId: milestoneToDelete.projectId, queryClient })
      }
      
      return result
    } catch (error) {
      console.error('Error deleting milestone:', error)
      throw error
    }
  }, [deleteMutation, refetchMilestones, queryClient, milestones])

  // Individual milestone loading states
  const [individualLoading, setIndividualLoading] = useState<Record<string, boolean>>({})

  // Quick status and progress updates with optimistic updates
  const handleUpdateMilestoneStatus = useCallback(async (id: string, status: 'pending' | 'in-progress' | 'completed' | 'overdue') => {
    setIndividualLoading(prev => ({ ...prev, [id]: true }))
    
    // Optimistic update
    const currentMilestone = milestones.find((m: any) => m._id === id)
    if (currentMilestone) {
      const updatedMilestones = milestones.map((m: any) => 
        m._id === id ? { ...m, status } : m
      )
      dispatch(setMilestones(updatedMilestones))
    }
    
    try {
      await handleUpdateMilestone(id, { status })
      // Refetch to ensure sync
      await refetchMilestones()
    } catch (error) {
      // Revert optimistic update on error
      if (currentMilestone) {
        const revertedMilestones = milestones.map((m: any) => 
          m._id === id ? currentMilestone : m
        )
        dispatch(setMilestones(revertedMilestones))
      }
      throw error
    } finally {
      setIndividualLoading(prev => ({ ...prev, [id]: false }))
    }
  }, [dispatch, milestones, handleUpdateMilestone, refetchMilestones])

  const handleUpdateMilestoneProgress = useCallback(async (id: string, progress: number) => {
    setIndividualLoading(prev => ({ ...prev, [id]: true }))
    
    // Optimistic update
    const currentMilestone = milestones.find((m: any) => m._id === id)
    if (currentMilestone) {
      const updatedMilestones = milestones.map((m: any) => 
        m._id === id ? { ...m, progress } : m
      )
      dispatch(setMilestones(updatedMilestones))
    }
    
    try {
      await handleUpdateMilestone(id, { progress })
      // Refetch to ensure sync
      await refetchMilestones()
    } catch (error) {
      // Revert optimistic update on error
      if (currentMilestone) {
        const revertedMilestones = milestones.map((m: any) => 
          m._id === id ? currentMilestone : m
        )
        dispatch(setMilestones(revertedMilestones))
      }
      throw error
    } finally {
      setIndividualLoading(prev => ({ ...prev, [id]: false }))
    }
  }, [dispatch, milestones, handleUpdateMilestone, refetchMilestones])

  // Handle inline due date update
  const handleUpdateMilestoneDueDate = useCallback(async (id: string, dueDate: string) => {
    setIndividualLoading(prev => ({ ...prev, [id]: true }))
    
    // Optimistic update
    const currentMilestone = milestones.find((m: any) => m._id === id)
    if (currentMilestone) {
      const updatedMilestones = milestones.map((m: any) => 
        m._id === id ? { ...m, dueDate } : m
      )
      dispatch(setMilestones(updatedMilestones))
    }
    
    try {
      await handleUpdateMilestone(id, { dueDate: new Date(dueDate) })
      // Refetch to ensure sync
      await refetchMilestones()
    } catch (error) {
      // Revert optimistic update on error
      if (currentMilestone) {
        const revertedMilestones = milestones.map((m: any) => 
          m._id === id ? currentMilestone : m
        )
        dispatch(setMilestones(revertedMilestones))
      }
      throw error
    } finally {
      setIndividualLoading(prev => ({ ...prev, [id]: false }))
    }
  }, [dispatch, milestones, handleUpdateMilestone, refetchMilestones])

  // Check if individual milestone is loading
  const isMilestoneLoading = useCallback((id: string) => {
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

  const refreshMilestones = useCallback(() => {
    return handleFetchMilestones({ 
      projectId: filters.projectId, 
      phaseId: filters.phaseId 
    })
  }, [handleFetchMilestones, filters.projectId, filters.phaseId])

  // Progress update operations
  const handleUpdateMilestoneProgressFromTasks = useCallback(async (milestoneId: string) => {
    try {
      dispatch(setActionLoading(true))
      
      const response = await fetch('/api/milestones/update-progress', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ milestoneId }),
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to update milestone progress')
      }

      // Update milestone progress in local state
      dispatch(updateMilestoneProgress({ 
        id: milestoneId, 
        progress: result.data.progress 
      }))

      // Update status if it changed
      if (result.data.status) {
        dispatch(updateMilestoneStatus({ 
          id: milestoneId, 
          status: result.data.status 
        }))
      }

      return result.data

    } catch (error: any) {
      dispatch(setError(error.message))
      throw error
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch])

  const handleUpdateProjectMilestoneProgress = useCallback(async (projectId: string) => {
    try {
      dispatch(setActionLoading(true))
      
      const response = await fetch('/api/milestones/update-progress', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ projectId }),
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to update project milestone progress')
      }

      // Refresh milestones to get updated data
      await refreshMilestones()

      return result.data

    } catch (error: any) {
      dispatch(setError(error.message))
      throw error
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch, refreshMilestones])

  const handleGetMilestoneProgressSummary = useCallback(async (projectId: string) => {
    try {
      const response = await fetch(`/api/milestones/update-progress?projectId=${projectId}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to get milestone progress summary')
      }

      return result.data

    } catch (error: any) {
      dispatch(setError(error.message))
      throw error
    }
  }, [dispatch])

  // Computed values
  const hasMilestones = milestones.length > 0
  const completedMilestones = milestones.filter((m: any) => m.status === 'completed')
  const pendingMilestones = milestones.filter((m: any) => m.status === 'pending')
  const inProgressMilestones = milestones.filter((m: any) => m.status === 'in-progress')
  const blockedMilestones = milestones.filter((m: any) => m.status === 'blocked')
  const overdueMilestones = milestones.filter((m: any) => {
    if (m.status === 'completed') return false
    return new Date(m.dueDate) < new Date()
  })

  const overallProgress = useMemo(() => {
    if (milestones.length === 0) return 0
    const totalProgress = milestones.reduce((sum: number, milestone: any) => sum + (milestone.progress || 0), 0)
    return Math.round(totalProgress / milestones.length)
  }, [milestones])

  const completionRate = useMemo(() => {
    if (milestones.length === 0) return 0
    return Math.round((completedMilestones.length / milestones.length) * 100)
  }, [milestones.length, completedMilestones.length])

  return {
    // State
    milestones: fetchedMilestones || milestones,
    selectedMilestone,
    loading: queryLoading || loading,
    actionLoading: createMutation.isPending || updateMutation.isPending || deleteMutation.isPending || actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,

    // Computed values
    hasMilestones,
    completedMilestones,
    pendingMilestones,
    inProgressMilestones,
    blockedMilestones,
    overdueMilestones,
    overallProgress,
    completionRate,

    // CRUD operations
    fetchMilestones: handleFetchMilestones,
    createMilestone: handleCreateMilestone,
    updateMilestone: handleUpdateMilestone,
    deleteMilestone: handleDeleteMilestone,

    // Quick updates
    updateMilestoneStatus: handleUpdateMilestoneStatus,
    updateMilestoneProgress: handleUpdateMilestoneProgress,
    updateMilestoneDueDate: handleUpdateMilestoneDueDate,
    updateMilestoneProgressFromTasks: handleUpdateMilestoneProgressFromTasks,
    updateProjectMilestoneProgress: handleUpdateProjectMilestoneProgress,
    getMilestoneProgressSummary: handleGetMilestoneProgressSummary,
    isMilestoneLoading,
    individualLoading,

    // Filter and sort operations
    setFilters: handleSetFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,

    // Utility operations
    clearError: handleClearError,
    resetState: handleResetState,
    refreshMilestones,
    refetch: refetchMilestones,
  }
}

// Single milestone query hook using generic approach
export function useMilestone(milestoneId: string) {
  const dispatch = useAppDispatch()

  const milestoneOptions: UseGenericQueryOptions<any> = {
    entityName: 'milestones',
    baseUrl: '/api/milestones',
    reduxDispatchers: {
      setEntity: (entity) => dispatch(setSelectedMilestone(entity)),
      setLoading: (loading) => dispatch(setLoading(loading)),
      setError: (error) => dispatch(setError(error)),
      clearError: () => dispatch(clearError()),
    },
  }

  const { data: milestone, isLoading, error, refetch } = useGenericQueryById(
    milestoneOptions,
    milestoneId,
    !!milestoneId
  )

  return {
    milestone,
    loading: isLoading,
    error,
    refetch,
  }
}

// Project-specific milestones hook
export function useProjectMilestones(projectId: string) {
  const { 
    milestones, 
    setFilters, 
    refreshMilestones,
    filters,
    ...rest 
  } = useMilestones()

  const initializedRef = useRef(false)

  // Filter milestones by project automatically using useEffect
  useEffect(() => {
    // Only set filters on first mount or if projectId changes
    if (projectId && (!initializedRef.current || filters.projectId !== projectId)) {
      setFilters({ projectId })
      initializedRef.current = true
    }
  }, [projectId, filters.projectId, setFilters])

  // Don't filter client-side since we're filtering server-side via API
  const projectMilestones = useMemo(() => {
    // Return all milestones since they should already be filtered by the API
    return milestones
  }, [milestones])

  return {
    milestones: projectMilestones,
    filters,
    ...rest,
    setFilters,
    refreshMilestones: () => refreshMilestones(),
  }
}

// Phase-specific milestones hook
export function usePhaseMilestones(phaseId: string) {
  const { 
    milestones, 
    setFilters, 
    refreshMilestones,
    filters,
    ...rest 
  } = useMilestones()

  const initializedRef = useRef(false)

  // Filter milestones by phase automatically using useEffect
  useEffect(() => {
    // Only set filters on first mount or if phaseId changes
    if (phaseId && (!initializedRef.current || filters.phaseId !== phaseId)) {
      setFilters({ phaseId })
      initializedRef.current = true
    }
  }, [phaseId, filters.phaseId, setFilters])

  const phaseMilestones = useMemo(() => {
    return milestones.filter((milestone: any) => milestone.phaseId === phaseId)
  }, [milestones, phaseId])

  return {
    milestones: phaseMilestones,
    filters,
    ...rest,
    setFilters,
    refreshMilestones: () => refreshMilestones(),
  }
}

// Combined hook for ease of use (keeping backward compatibility)
export function useMilestoneManagement(projectId?: string, phaseId?: string) {
  if (phaseId) {
    return usePhaseMilestones(phaseId)
  } else if (projectId) {
    return useProjectMilestones(projectId)
  } else {
    return useMilestones()
  }
}