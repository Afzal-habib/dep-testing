import { useCallback, useMemo, useEffect } from 'react'
import { useQueryClient } from "@tanstack/react-query"
import { refreshAnalytics } from '@/lib/utils/analytics-refresh'
import { useAppSelector, useAppDispatch } from './redux'
import {
  setProjects,
  setSelectedProject,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats,
  resetState,
} from '@/store/slices/projectSlice'
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
  FetchProjectsParams,
  CreateProjectData,
  CreateProjectFormData,
  UpdateProjectData,
  ProjectFilters,
  ProjectSort,
} from '@/types'

export function useProjects() {
  const dispatch = useAppDispatch()

  const {
    projects,
    selectedProject,
    loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.projects)

  // Define options for generic hooks
  const projectOptions: UseGenericQueryOptions<any> = {
    entityName: 'projects',
    baseUrl: '/api/projects',
    reduxDispatchers: {
      setEntities: (entities) => dispatch(setProjects(entities)),
      setEntity: (entity) => dispatch(setSelectedProject(entity)),
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
  const { data: fetchedProjects, isLoading: queryLoading, refetch: refetchProjects } = useGenericQuery(
    projectOptions,
    queryParams,
    true
  )

  const createMutation = useGenericCreate(projectOptions)
  const updateMutation = useGenericUpdate(projectOptions)
  const deleteMutation = useGenericDelete(projectOptions)

  const queryClient = useQueryClient()

  // Special operations that require direct API calls
  const handleApproveProject = useCallback(async (id: string) => {
    try {
      await apiRequest(`${projectOptions.baseUrl}/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ operation: 'approve' })
      })
      // Invalidate queries to refetch data
      queryClient.invalidateQueries({ queryKey: [projectOptions.entityName] })
      queryClient.invalidateQueries({ queryKey: [projectOptions.entityName, id] })
      
      // Invalidate analytics queries since project status change affects analytics
      queryClient.invalidateQueries({ 
        queryKey: ['analytics'], 
        type: 'all'
      })
      queryClient.invalidateQueries({ 
        queryKey: ['project-analytics', id],
        type: 'all'
      })
    } catch (error) {
      handleAPIError(error, `Failed to approve project`)
      throw error
    }
  }, [projectOptions.baseUrl, projectOptions.entityName, queryClient])

  // Fetch operations - Stable function that doesn't change on re-renders
  const handleFetchProjects = useCallback((params?: FetchProjectsParams) => {
    refetchProjects()
  }, [refetchProjects])

  // CRUD operations
  const handleCreateProject = useCallback(async (projectData: CreateProjectFormData) => {
    try {
      const result = await createMutation.mutateAsync(projectData)
      
      // Invalidate analytics queries to refresh project statistics
      await queryClient.invalidateQueries({ 
        queryKey: ['analytics'] 
      })
      // Also invalidate project-specific analytics for the new project
      if (result?.data?._id) {
        await queryClient.invalidateQueries({ 
          predicate: (query) => {
            const key = query.queryKey
            return key && key[0] === 'project-analytics' && key[1] === result.data._id
          }
        })
        // Refetch analytics immediately
        await queryClient.refetchQueries({
          predicate: (query) => {
            const key = query.queryKey
            return key && key[0] === 'project-analytics' && key[1] === result.data._id
          }
        })
      }
      
      return result
    } catch (error) {
      throw error
    }
  }, [createMutation, queryClient])

  const handleUpdateProject = useCallback(async (id: string, data: UpdateProjectData) => {
    try {
      const result = await updateMutation.mutateAsync({ id, data })
      
      // Trigger analytics refresh
      refreshAnalytics({ projectId: id, queryClient })
      
      return result
    } catch (error) {
      throw error
    }
  }, [updateMutation, queryClient])

  const handleDeleteProject = useCallback(async (projectId: string) => {
    try {
      const result = await deleteMutation.mutateAsync(projectId)
      
      // Trigger analytics refresh
      refreshAnalytics({ projectId, queryClient })
      
      return result
    } catch (error) {
      throw error
    }
  }, [deleteMutation, queryClient])

  const handleRestoreProject = useCallback(async (projectId: string) => {
    return await updateMutation.mutateAsync({
      id: projectId,
      data: {
        isDeleted: false,
        status: 'pending'
      }
    })
  }, [updateMutation])

  // Filter and sort operations
  const handleSetFilters = useCallback((newFilters: Partial<ProjectFilters>) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  const handleSetSort = useCallback((newSort: ProjectSort) => {
    dispatch(setSort(newSort))
  }, [dispatch])

  const handleSetPagination = useCallback((newPagination: { page?: number; limit?: number }) => {
    dispatch(setPagination(newPagination))
  }, [dispatch])

  const handleSetSelectedProject = useCallback((project: typeof selectedProject) => {
    dispatch(setSelectedProject(project))
  }, [dispatch])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleResetState = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  const refreshProjects = useCallback(() => {
    return handleFetchProjects()
  }, [handleFetchProjects])

  // Computed values
  const hasProjects = projects.length > 0
  const isFirstPage = pagination.page === 1
  const isLastPage = pagination.page >= pagination.pages
  const totalPages = pagination.pages
  const totalItems = pagination.total

  // Status-based getters
  const pendingProjects = projects.filter((p: any) => p.status === 'pending')
  const activeProjects = projects.filter((p: any) => p.status === 'active')
  const approvedProjects = projects.filter((p: any) => p.status === 'approved')
  const completedProjects = projects.filter((p: any) => p.status === 'completed')

  // Priority-based getters
  const urgentProjects = projects.filter((p: any) => p.priority === 'urgent')
  const highPriorityProjects = projects.filter((p: any) => p.priority === 'high')

  // Helper functions
  const getProjectsByStatus = useCallback((status: string) => {
    return projects.filter((p: any) => p.status === status)
  }, [projects])

  const getProjectsByPriority = useCallback((priority: string) => {
    return projects.filter((p: any) => p.priority === priority)
  }, [projects])

  const getProjectsByClient = useCallback((clientId: string) => {
    return projects.filter((p: any) => p.clientId === clientId)
  }, [projects])

  const getProjectsByDepartment = useCallback((departmentId: string) => {
    return projects.filter((p: any) => p.departmentIds.includes(departmentId))
  }, [projects])

  const canCreateProject = useCallback(() => {
    // Logic to determine if user can create projects
    // This would typically check user permissions
    return true // Simplified for now
  }, [])

  const canEditProject = useCallback((project: typeof selectedProject) => {
    // Logic to determine if user can edit a specific project
    // This would typically check user permissions and project status
    return project && project.status !== 'completed'
  }, [])

  const canDeleteProject = useCallback((project: typeof selectedProject) => {
    // Logic to determine if user can delete a specific project
    // This would typically check user permissions and project status
    return project && ['pending', 'inactive'].includes(project.status)
  }, [])

  const canCategorizeProject = useCallback((project: typeof selectedProject) => {
    // Logic to determine if user can categorize a project
    return project && project.status === 'pending'
  }, [])

  const canApproveProject = useCallback((project: typeof selectedProject) => {
    // Logic to determine if user can approve a project
    return project && project.status === 'pending' && project.departmentIds.length > 0
  }, [])

  return {
    // State
    projects: fetchedProjects || projects,
    selectedProject,
    loading: queryLoading || loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,

    // CRUD operations
    fetchProjects: handleFetchProjects,
    createProject: handleCreateProject,
    updateProject: handleUpdateProject,
    deleteProject: handleDeleteProject,
    restoreProject: handleRestoreProject,
    handleApproveProject,

    // Filter and sort operations
    setFilters: handleSetFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,
    setSelectedProject: handleSetSelectedProject,

    // Utility operations
    clearError: handleClearError,
    resetState: handleResetState,
    refreshProjects,

    // Computed values
    hasProjects,
    isFirstPage,
    isLastPage,
    totalPages,
    totalItems,

    // Status-based data
    pendingProjects,
    activeProjects,
    approvedProjects,
    completedProjects,
    urgentProjects,
    highPriorityProjects,

    // Helper functions
    getProjectsByStatus,
    getProjectsByPriority,
    getProjectsByClient,
    getProjectsByDepartment,

    // Permission checks
    canCreateProject,
    canEditProject,
    canDeleteProject,
    canCategorizeProject,
    canApproveProject,
  }
}

// Single project hook - doesn't fetch all projects, only handles individual project operations
export function useProject(projectId?: string) {
  const dispatch = useAppDispatch()
  const queryClient = useQueryClient()

  const {
    selectedProject,
    actionLoading,
    error,
  } = useAppSelector((state) => state.projects)

  // Define options for generic hooks  
  const projectOptions: UseGenericQueryOptions<any> = {
    entityName: 'projects',
    baseUrl: '/api/projects',
    reduxDispatchers: {
      setEntities: (entities) => dispatch(setProjects(entities)),
      setEntity: (entity) => dispatch(setSelectedProject(entity)),
      setPagination: (pagination) => dispatch(setPagination(pagination)),
      setStats: (stats) => dispatch(setStats(stats)),
      setLoading: (loading) => dispatch(setLoading(loading)),
      setActionLoading: (loading) => dispatch(setActionLoading(loading)),
      setError: (error) => dispatch(setError(error)),
      clearError: () => dispatch(clearError()),
    },
  }

  // Use generic hooks for update operations
  const updateMutation = useGenericUpdate(projectOptions)

  // Fetch single project by ID if provided
  const { data: fetchedProject, isLoading: queryLoading, refetch: refetchProject } = useGenericQueryById(
    projectOptions,
    projectId || '',
    !!projectId // Only enable query if projectId is provided
  )

  // Update the selected project when fetched data changes
  useEffect(() => {
    if (fetchedProject && projectId) {
      dispatch(setSelectedProject(fetchedProject))
    }
  }, [fetchedProject, projectId, dispatch])

  // CRUD operations - only update and approve needed for project details
  const handleUpdateProject = useCallback(async (id: string, data: UpdateProjectData) => {
    try {
      const result = await updateMutation.mutateAsync({ id, data })
      // Invalidate and refetch the specific project
      queryClient.invalidateQueries({ queryKey: [projectOptions.entityName, id] })
      return result
    } catch (error) {
      throw error
    }
  }, [updateMutation, queryClient, projectOptions.entityName])

  const handleApproveProject = useCallback(async (id: string) => {
    try {
      await apiRequest(`${projectOptions.baseUrl}/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ operation: 'approve' })
      })
      // Invalidate queries to refetch data
      queryClient.invalidateQueries({ queryKey: [projectOptions.entityName, id] })
    } catch (error) {
      console.error('Error approving project:', error)
      throw error
    }
  }, [projectOptions.baseUrl, projectOptions.entityName, queryClient])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleSetSelectedProject = useCallback((project: typeof selectedProject) => {
    dispatch(setSelectedProject(project))
  }, [dispatch])

  return {
    // State
    project: selectedProject,
    loading: queryLoading,
    actionLoading: updateMutation.isPending || actionLoading,
    error,

    // CRUD operations
    updateProject: handleUpdateProject,
    approveProject: handleApproveProject,

    // Utility operations
    setSelectedProject: handleSetSelectedProject,
    clearError: handleClearError,
    refetch: refetchProject,
  }
}