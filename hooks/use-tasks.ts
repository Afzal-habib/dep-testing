import { useCallback, useMemo } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import {
  setTasks,
  setSelectedTask,
  setLoading,
  setActionLoading,
  setActionLoadingForTask,
  setActionLoadingForDepartment,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setHierarchy,
  resetState,
} from '@/store/slices/taskSlice'
import {
  useGenericQuery,
  useGenericCreate,
  useGenericUpdate,
  useGenericDelete,
  type UseGenericQueryOptions,
} from './use-generic-query'
import { useQueryClient } from "@tanstack/react-query"
import { apiRequest, handleAPIError } from '@/lib/utils/api-client'
import { refreshAnalytics } from '@/lib/utils/analytics-refresh'
import type {
  Task,
  FetchTasksParams,
  CreateTaskData,
  UpdateTaskData,
  TaskFilters,
  TaskSort,
} from '@/types'

export function useTasks() {
  const dispatch = useAppDispatch()

  const {
    tasks,
    selectedTask,
    loading,
    actionLoading,
    actionLoadingTasks,
    actionLoadingDepartments,
    error,
    filters,
    sort,
    pagination,
    stats,
    hierarchy,
  } = useAppSelector((state) => state.tasks)

  // Define options for generic hooks
  const taskOptions: UseGenericQueryOptions<any> = {
    entityName: 'tasks',
    baseUrl: '/api/tasks',
    reduxDispatchers: {
      setEntities: (entities) => dispatch(setTasks(entities)),
      setEntity: (entity) => dispatch(setSelectedTask(entity)),
      setPagination: (pagination) => dispatch(setPagination(pagination)),
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

  // Use generic hooks with better caching
  const { data: fetchedTasks, isLoading: queryLoading, refetch: refetchTasks } = useGenericQuery(
    taskOptions,
    queryParams,
    true,
    {
      staleTime: 10 * 60 * 1000, // 10 minutes - prevent auto-refetch
      refetchOnWindowFocus: false,
      refetchOnMount: false,
      retry: 2,
    }
  )

  const createMutation = useGenericCreate(taskOptions)
  const updateMutation = useGenericUpdate(taskOptions)
  const deleteMutation = useGenericDelete(taskOptions)

  const queryClient = useQueryClient()

  // Fetch operations - Stable function that doesn't change on re-renders
  const handleFetchTasks = useCallback((params?: FetchTasksParams) => {
    // If params provided, temporarily set filters and refetch for targeted data
    if (params) {
      const originalFilters = filters
      // Omit "deleted" status if present, since TaskFilters does not allow it
      const { status, ...rest } = params || {}
      const safeStatus = status === "deleted" ? undefined : status
      dispatch(setFilters({ ...rest, ...(safeStatus !== undefined ? { status: safeStatus } : {}) }))
      // We will refetch and then restore filters - but we also leave as is so components remain stable
      refetchTasks()
      return
    }
    refetchTasks()
  }, [refetchTasks])

  // CRUD operations
  const handleCreateTask = useCallback(async (taskData: CreateTaskData) => {
    const departmentId = typeof taskData.departmentId === 'string' ? taskData.departmentId : undefined
    try {
      if (departmentId) dispatch(setActionLoadingForDepartment({ id: departmentId, loading: true }))
      
      const result = await createMutation.mutateAsync(taskData)
      
      // Optimistic update: add the new task to the current task list if it matches current filters
      const newTask = result?.data || result
      if (newTask && filters.projectId === taskData.projectId) {
        const shouldInclude = (
          (!filters.departmentId || filters.departmentId === departmentId) &&
          (!filters.status || filters.status === (newTask.status || 'pending')) &&
          (!filters.assigneeId || filters.assigneeId === taskData.assigneeId) &&
          (!filters.parentTaskId || filters.parentTaskId === taskData.parentTaskId)
        )
        
        if (shouldInclude) {
          const updatedTasks = [newTask, ...tasks]
          dispatch(setTasks(updatedTasks))
        }
      }
      
      // Targeted cache invalidation with background refresh including phase/milestone
      queryClient.invalidateQueries({ 
        predicate: (query) => {
          const key = query.queryKey
          if (!key || key[0] !== taskOptions.entityName) return false
          const qp = key[1] as any
          if (!qp?.filters) return true // Invalidate general queries
          if (departmentId && qp.filters.departmentId === departmentId) return true
          if (taskData.projectId && qp.filters.projectId === taskData.projectId) return true
          return false
        }
      })
      
      // Trigger analytics refresh
      if (taskData.projectId) {
        refreshAnalytics({ projectId: taskData.projectId, queryClient })
      }
      
      return result
    } catch (error) {
      throw error
    } finally {
      if (departmentId) dispatch(setActionLoadingForDepartment({ id: departmentId, loading: false }))
    }
  }, [createMutation, dispatch, queryClient, taskOptions.entityName, tasks, filters])

  const handleUpdateTask = useCallback(async (id: string, data: UpdateTaskData) => {
    const existingTask = tasks.find((t: any) => String(t._id) === String(id))
    
    try {
      dispatch(setActionLoadingForTask({ id, loading: true }))
      if (data?.departmentId) dispatch(setActionLoadingForDepartment({ id: data.departmentId as string, loading: true }))
      if (existingTask?.departmentId && existingTask.departmentId !== data?.departmentId) {
        dispatch(setActionLoadingForDepartment({ id: existingTask.departmentId as string, loading: true }))
      }
      
      // Create optimistic update with current timestamp - ensure all dates are serializable
      const serializedData = { ...data }
      if (serializedData.dueDate && typeof serializedData.dueDate === 'object') {
        serializedData.dueDate = serializedData.dueDate.toISOString()
      }
      
      const optimisticUpdate = { 
        ...existingTask, 
        ...serializedData, 
        updatedAt: new Date().toISOString() 
      }
      
      // Apply optimistic update to Redux state IMMEDIATELY
      const optimisticTasks = tasks.map((t: any) => 
        String(t._id) === String(id) ? optimisticUpdate : t
      )
      dispatch(setTasks(optimisticTasks))
      
      // Update ALL React Query caches IMMEDIATELY to prevent stale data
      queryClient.setQueriesData(
        { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
        (oldData: any) => {
          if (!oldData) return oldData
          
          if (Array.isArray(oldData)) {
            return oldData.map((t: any) => 
              String(t._id) === String(id) ? optimisticUpdate : t
            )
          }
          
          if (oldData.data && Array.isArray(oldData.data)) {
            return {
              ...oldData,
              data: oldData.data.map((t: any) => 
                String(t._id) === String(id) ? optimisticUpdate : t
              )
            }
          }
          
          return oldData
        }
      )
      
      // Make API call
      const result = await updateMutation.mutateAsync({ id, data })
      
      // Update with server response if available
      const serverTaskData = result?.data || result
      if (serverTaskData) {
        const finalTask = { ...existingTask, ...serverTaskData }
        
        // Update Redux with server data
        const finalTasks = tasks.map((t: any) => 
          String(t._id) === String(id) ? finalTask : t
        )
        dispatch(setTasks(finalTasks))
        
        // Update ALL cached queries with final server data
        queryClient.setQueriesData(
          { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
          (oldData: any) => {
            if (!oldData) return oldData
            
            if (Array.isArray(oldData)) {
              return oldData.map((t: any) => 
                String(t._id) === String(id) ? finalTask : t
              )
            }
            
            if (oldData.data && Array.isArray(oldData.data)) {
              return {
                ...oldData,
                data: oldData.data.map((t: any) => 
                  String(t._id) === String(id) ? finalTask : t
                )
              }
            }
            
            return oldData
          }
        )
      }
      
      // Trigger analytics refresh
      const projectId = existingTask?.projectId
      if (projectId) {
        refreshAnalytics({ projectId, queryClient })
      }
      
      return result
    } catch (error) {
      // Revert optimistic update on error
      if (existingTask) {
        const revertedTasks = tasks.map((t: any) => 
          String(t._id) === String(id) ? existingTask : t
        )
        dispatch(setTasks(revertedTasks))
        
        // Revert ALL cached queries
        queryClient.setQueriesData(
          { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
          (oldData: any) => {
            if (!oldData) return oldData
            
            if (Array.isArray(oldData)) {
              return oldData.map((t: any) => 
                String(t._id) === String(id) ? existingTask : t
              )
            }
            
            if (oldData.data && Array.isArray(oldData.data)) {
              return {
                ...oldData,
                data: oldData.data.map((t: any) => 
                  String(t._id) === String(id) ? existingTask : t
                )
              }
            }
            
            return oldData
          }
        )
      }
      throw error
    } finally {
      dispatch(setActionLoadingForTask({ id, loading: false }))
      if (data?.departmentId) dispatch(setActionLoadingForDepartment({ id: data.departmentId as string, loading: false }))
      if (existingTask?.departmentId && existingTask.departmentId !== data?.departmentId) {
        dispatch(setActionLoadingForDepartment({ id: existingTask.departmentId as string, loading: false }))
      }
    }
  }, [updateMutation, dispatch, queryClient, taskOptions.entityName, tasks])

  const handleDeleteTask = useCallback(async (taskId: string) => {
    try {
      const existingTask = tasks.find((t: any) => String(t._id) === String(taskId))
      if (existingTask?.departmentId) dispatch(setActionLoadingForDepartment({ id: existingTask.departmentId as string, loading: true }))
      dispatch(setActionLoadingForTask({ id: taskId, loading: true }))
      
      const result = await deleteMutation.mutateAsync(taskId)
      
      // Optimistic update: remove or update the task in local state
      if (existingTask) {
        // @ts-ignore
        const deletedTaskData = result?.data || result
        if (deletedTaskData?.status === 'cancelled' || deletedTaskData?.status === 'deleted') {
          // Update the task with cancelled/deleted status
          const updatedTask = { ...existingTask, ...deletedTaskData }
          const updatedTasks = tasks.map((t: any) => String(t._id) === String(taskId) ? updatedTask : t)
          dispatch(setTasks(updatedTasks))
        } else {
          // Remove the task completely if hard deleted
          const updatedTasks = tasks.filter((t: any) => String(t._id) !== String(taskId))
          dispatch(setTasks(updatedTasks))
        }
      }
      
      // Comprehensive cache invalidation
      queryClient.invalidateQueries({ 
        predicate: (query) => {
          const key = query.queryKey
          if (!key || key[0] !== taskOptions.entityName) return false
          const qp = key[1] as any
          if (!qp?.filters) return true // Invalidate general queries
          if (existingTask?.projectId && qp.filters.projectId === existingTask.projectId) return true
          if (existingTask?.departmentId && qp.filters.departmentId === existingTask.departmentId) return true
          if (qp.filters.parentTaskId === taskId) return true // Sub-tasks of this task
          return false
        }
      })
      
      // Trigger analytics refresh
      if (existingTask?.projectId) {
        refreshAnalytics({ projectId: existingTask.projectId, queryClient })
      }
      
      // Also invalidate specific task queries
      queryClient.invalidateQueries({ queryKey: [taskOptions.entityName, taskId] })
      
      return result
    } catch (error) {
      throw error
    } finally {
      dispatch(setActionLoadingForTask({ id: taskId, loading: false }))
      const existingTask = tasks.find((t: any) => String(t._id) === String(taskId))
      if (existingTask?.departmentId) dispatch(setActionLoadingForDepartment({ id: existingTask.departmentId as string, loading: false }))
    }
  }, [deleteMutation, dispatch, queryClient, taskOptions.entityName, tasks])

  const handleRestoreTask = useCallback(async (taskId: string) => {
    return await updateMutation.mutateAsync({
      id: taskId,
      data: {
        isDeleted: false,
        status: 'pending'
      }
    })
  }, [updateMutation])

  // Special operations that require direct API calls
  const handleAssignTask = useCallback(async (id: string, assigneeId: string) => {
    let originalTask: any = null
    try {
      const existingTask = tasks.find((t: any) => String(t._id) === String(id))
      originalTask = existingTask
      
      dispatch(setActionLoadingForTask({ id, loading: true }))
      if (existingTask?.departmentId) {
        dispatch(setActionLoadingForDepartment({ id: existingTask.departmentId as string, loading: true }))
      }
      
      // Optimistic update BEFORE API call
      const optimisticTask = { 
        ...existingTask, 
        assigneeId, 
        updatedAt: new Date().toISOString() 
      }      
      // Update Redux state immediately
      const optimisticTasks = tasks.map((t: any) => String(t._id) === String(id) ? optimisticTask : t)
      dispatch(setTasks(optimisticTasks))
      
      // Update cached queries immediately
      queryClient.setQueriesData(
        { queryKey: [taskOptions.entityName] },
        (oldData: any) => {
          if (!oldData) return oldData
          if (Array.isArray(oldData)) {
            return oldData.map((t: any) => String(t._id) === String(id) ? optimisticTask : t)
          }
          if (oldData.data && Array.isArray(oldData.data)) {
            return {
              ...oldData,
              data: oldData.data.map((t: any) => String(t._id) === String(id) ? optimisticTask : t)
            }
          }
          return oldData
        }
      )
      
      const result = await apiRequest(`${taskOptions.baseUrl}/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ operation: 'assign', assigneeId })
      })
      
      // Update with server response
      const serverTaskData = result?.data || result
      if (serverTaskData) {
        const finalTask = { ...existingTask, ...serverTaskData }
        
        // Update Redux with server data
        const finalTasks = tasks.map((t: any) => String(t._id) === String(id) ? finalTask : t)
        dispatch(setTasks(finalTasks))
        
        // Update ALL cached queries with final server data
        queryClient.setQueriesData(
          { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
          (oldData: any) => {
            if (!oldData) return oldData
            
            if (Array.isArray(oldData)) {
              return oldData.map((t: any) => 
                String(t._id) === String(id) ? finalTask : t
              )
            }
            
            if (oldData.data && Array.isArray(oldData.data)) {
              return {
                ...oldData,
                data: oldData.data.map((t: any) => 
                  String(t._id) === String(id) ? finalTask : t
                )
              }
            }
            
            return oldData
          }
        )
      }
      
      // Invalidate analytics queries to refresh task assignment statistics
      if (originalTask?.projectId) {
        // Invalidate all analytics queries
        await queryClient.invalidateQueries({ 
          queryKey: ['analytics'] 
        })
        // Invalidate project-specific analytics
        await queryClient.invalidateQueries({ 
          predicate: (query) => {
            const key = query.queryKey
            return key && key[0] === 'project-analytics' && key[1] === originalTask.projectId
          }
        })
        // Refetch analytics immediately
        await queryClient.refetchQueries({
          predicate: (query) => {
            const key = query.queryKey
            return key && key[0] === 'project-analytics' && key[1] === originalTask.projectId
          }
        })
      }
      
      return result
    } catch (error) {
      console.error('Error assigning task:', error)
      
      // Revert optimistic update on error
      if (originalTask) {
        const revertedTasks = tasks.map((t: any) => 
          String(t._id) === String(id) ? originalTask : t
        )
        dispatch(setTasks(revertedTasks))
        
        // Revert ALL cached queries
        queryClient.setQueriesData(
          { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
          (oldData: any) => {
            if (!oldData) return oldData
            
            if (Array.isArray(oldData)) {
              return oldData.map((t: any) => 
                String(t._id) === String(id) ? originalTask : t
              )
            }
            
            if (oldData.data && Array.isArray(oldData.data)) {
              return {
                ...oldData,
                data: oldData.data.map((t: any) => 
                  String(t._id) === String(id) ? originalTask : t
                )
              }
            }
            
            return oldData
          }
        )
      }
      
      handleAPIError(error, `Failed to assign task`)
      throw error
    } finally {
      dispatch(setActionLoadingForTask({ id, loading: false }))
      if (originalTask?.departmentId) {
        dispatch(setActionLoadingForDepartment({ id: originalTask.departmentId as string, loading: false }))
      }
    }
  }, [taskOptions.baseUrl, taskOptions.entityName, queryClient, tasks, dispatch])

  const handleUpdateTaskStatus = useCallback(async (id: string, status: string, actualHours?: number) => {
    const originalTask = tasks.find((t: any) => String(t._id) === String(id))
    
    try {
      dispatch(setActionLoadingForTask({ id, loading: true }))
      if (originalTask?.departmentId) {
        dispatch(setActionLoadingForDepartment({ id: originalTask.departmentId as string, loading: true }))
      }
      
      // Create optimistic update
      const optimisticUpdate = { 
        ...originalTask, 
        status, 
        actualHours: actualHours ?? originalTask?.actualHours,
        completedAt: status === 'completed' ? new Date().toISOString() : 
                    (status !== 'completed' ? undefined : originalTask?.completedAt),
        updatedAt: new Date().toISOString()
      }
      
      // Apply optimistic update to Redux IMMEDIATELY
      const optimisticTasks = tasks.map((t: any) => 
        String(t._id) === String(id) ? optimisticUpdate : t
      )
      dispatch(setTasks(optimisticTasks))
      
      // Update ALL React Query caches IMMEDIATELY
      queryClient.setQueriesData(
        { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
        (oldData: any) => {
          if (!oldData) return oldData
          
          if (Array.isArray(oldData)) {
            return oldData.map((t: any) => 
              String(t._id) === String(id) ? optimisticUpdate : t
            )
          }
          
          if (oldData.data && Array.isArray(oldData.data)) {
            return {
              ...oldData,
              data: oldData.data.map((t: any) => 
                String(t._id) === String(id) ? optimisticUpdate : t
              )
            }
          }
          
          return oldData
        }
      )
      
      // Make API request
      const result = await apiRequest(`${taskOptions.baseUrl}/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ operation: 'updateStatus', status, actualHours })
      })
      
      // Update with server response if available
      const serverTaskData = result?.data || result
      if (serverTaskData) {
        const finalTask = { ...originalTask, ...serverTaskData }
        
        // Update Redux with server data
        const finalTasks = tasks.map((t: any) => 
          String(t._id) === String(id) ? finalTask : t
        )
        dispatch(setTasks(finalTasks))
        
        // Update ALL cached queries with final server data
        queryClient.setQueriesData(
          { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
          (oldData: any) => {
            if (!oldData) return oldData
            
            if (Array.isArray(oldData)) {
              return oldData.map((t: any) => 
                String(t._id) === String(id) ? finalTask : t
              )
            }
            
            if (oldData.data && Array.isArray(oldData.data)) {
              return {
                ...oldData,
                data: oldData.data.map((t: any) => 
                  String(t._id) === String(id) ? finalTask : t
                )
              }
            }
            
            return oldData
          }
        )
      }
      
      // Invalidate analytics queries to refresh task statistics after status change
      if (originalTask?.projectId) {
        // Invalidate all analytics queries
        await queryClient.invalidateQueries({ 
          queryKey: ['analytics'] 
        })
        // Invalidate project-specific analytics
        await queryClient.invalidateQueries({ 
          predicate: (query) => {
            const key = query.queryKey
            return key && key[0] === 'project-analytics' && key[1] === originalTask.projectId
          }
        })
        // Refetch analytics immediately
        await queryClient.refetchQueries({
          predicate: (query) => {
            const key = query.queryKey
            return key && key[0] === 'project-analytics' && key[1] === originalTask.projectId
          }
        })
      }
      
      return result
    } catch (error) {
      console.error('Error updating task status:', error)
      
      // Revert optimistic update on error
      if (originalTask) {
        const revertedTasks = tasks.map((t: any) => 
          String(t._id) === String(id) ? originalTask : t
        )
        dispatch(setTasks(revertedTasks))
        
        // Revert ALL cached queries
        queryClient.setQueriesData(
          { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
          (oldData: any) => {
            if (!oldData) return oldData
            
            if (Array.isArray(oldData)) {
              return oldData.map((t: any) => 
                String(t._id) === String(id) ? originalTask : t
              )
            }
            
            if (oldData.data && Array.isArray(oldData.data)) {
              return {
                ...oldData,
                data: oldData.data.map((t: any) => 
                  String(t._id) === String(id) ? originalTask : t
                )
              }
            }
            
            return oldData
          }
        )
      }
      
      handleAPIError(error, `Failed to update task status`)
      throw error
    } finally {
      dispatch(setActionLoadingForTask({ id, loading: false }))
      if (originalTask?.departmentId) {
        dispatch(setActionLoadingForDepartment({ id: originalTask.departmentId as string, loading: false }))
      }
    }
  }, [taskOptions.baseUrl, taskOptions.entityName, queryClient, tasks, dispatch])

  // Fetch task hierarchy for a project
  const fetchTaskHierarchy = useCallback(async (projectId: string) => {
    try {
      const response = await apiRequest(`${taskOptions.baseUrl}?hierarchy=true&projectId=${projectId}`)
      const hierarchyData = response?.data || response
      dispatch(setHierarchy(hierarchyData))
      return hierarchyData
    } catch (error) {
      handleAPIError(error, `Failed to fetch task hierarchy`)
      throw error
    }
  }, [taskOptions.baseUrl, dispatch])

  // Enhanced bulk order update with cross-column support (no visual glitches)
  const handleBulkOrderUpdate = useCallback(async (updates: Array<{ id: string, order: number, status?: string }>) => {
    if (!updates || updates.length === 0) return

    // Store original state for potential rollback
    const originalTasks = [...tasks]
    
    try {
      // Create update maps for both order and status changes
      const orderMap = new Map(updates.map(({ id, order }) => [id, order]))
      const statusMap = new Map(
        updates.filter(({ status }) => status).map(({ id, status }) => [id, status])
      )
      
      // Create optimistic task list with BOTH order and status changes
      const optimisticTasks = tasks.map((task: any) => {
        const taskId = String(task._id)
        const newOrder = orderMap.get(taskId)
        const newStatus = statusMap.get(taskId)
        
        if (newOrder !== undefined || newStatus !== undefined) {
          const updatedTask = { 
            ...task, 
            updatedAt: new Date().toISOString(),
            _optimistic: true, // Flag for tracking optimistic updates
            _lockUpdate: true  // Prevent external cache updates from overriding
          }
          
          // Apply order change if provided
          if (newOrder !== undefined) {
            updatedTask.order = newOrder
          }
          
          // Apply status change if provided (for cross-column moves)
          if (newStatus !== undefined) {
            updatedTask.status = newStatus
            // Set completion timestamp for completed status
            if (newStatus === 'completed' && !task.completedAt) {
              updatedTask.completedAt = new Date().toISOString()
            } else if (newStatus !== 'completed') {
              updatedTask.completedAt = undefined
            }
          }
          
          return updatedTask
        }
        return task
      })
      
      // Sort by order within each status group for proper visual arrangement
      const sortedOptimisticTasks = [...optimisticTasks].sort((a: any, b: any) => {
        // First sort by status to group columns
        if (a.status !== b.status) {
          const statusOrder = { 'pending': 0, 'in-progress': 1, 'completed': 2, 'on-hold': 3 }
          return (statusOrder[a.status as keyof typeof statusOrder] || 999) - 
                 (statusOrder[b.status as keyof typeof statusOrder] || 999)
        }
        // Then sort by order within the same status
        const orderA = a.order !== undefined ? a.order : 999999
        const orderB = b.order !== undefined ? b.order : 999999
        return orderA - orderB
      })
      
      // Apply optimistic state to Redux IMMEDIATELY (prevents glitch)
      dispatch(setTasks(sortedOptimisticTasks))
      
      // LOCK all React Query caches to prevent external updates during drag operation
      queryClient.setQueriesData(
        { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
        (oldData: any) => {
          if (!oldData) return oldData
          
          if (Array.isArray(oldData)) {
            const updatedArray = oldData.map((task: any) => {
              // Skip updates for locked optimistic tasks
              if (task._lockUpdate) return task
              
              const taskId = String(task._id)
              const newOrder = orderMap.get(taskId)
              const newStatus = statusMap.get(taskId)
              
              if (newOrder !== undefined || newStatus !== undefined) {
                const updatedTask = { 
                  ...task, 
                  updatedAt: new Date().toISOString(),
                  _optimistic: true,
                  _lockUpdate: true
                }
                
                if (newOrder !== undefined) updatedTask.order = newOrder
                if (newStatus !== undefined) {
                  updatedTask.status = newStatus
                  if (newStatus === 'completed' && !task.completedAt) {
                    updatedTask.completedAt = new Date().toISOString()
                  } else if (newStatus !== 'completed') {
                    updatedTask.completedAt = undefined
                  }
                }
                
                return updatedTask
              }
              return task
            })
            
            return updatedArray.sort((a: any, b: any) => {
              if (a.status !== b.status) {
                const statusOrder = { 'pending': 0, 'in-progress': 1, 'completed': 2, 'on-hold': 3 }
                return (statusOrder[a.status as keyof typeof statusOrder] || 999) - 
                       (statusOrder[b.status as keyof typeof statusOrder] || 999)
              }
              const orderA = a.order !== undefined ? a.order : 999999
              const orderB = b.order !== undefined ? b.order : 999999
              return orderA - orderB
            })
          }
          
          if (oldData.data && Array.isArray(oldData.data)) {
            const updatedArray = oldData.data.map((task: any) => {
              if (task._lockUpdate) return task
              
              const taskId = String(task._id)
              const newOrder = orderMap.get(taskId)
              const newStatus = statusMap.get(taskId)
              
              if (newOrder !== undefined || newStatus !== undefined) {
                const updatedTask = { 
                  ...task, 
                  updatedAt: new Date().toISOString(),
                  _optimistic: true,
                  _lockUpdate: true
                }
                
                if (newOrder !== undefined) updatedTask.order = newOrder
                if (newStatus !== undefined) {
                  updatedTask.status = newStatus
                  if (newStatus === 'completed' && !task.completedAt) {
                    updatedTask.completedAt = new Date().toISOString()
                  } else if (newStatus !== 'completed') {
                    updatedTask.completedAt = undefined
                  }
                }
                
                return updatedTask
              }
              return task
            })
            
            return {
              ...oldData,
              data: updatedArray.sort((a: any, b: any) => {
                if (a.status !== b.status) {
                  const statusOrder = { 'pending': 0, 'in-progress': 1, 'completed': 2, 'on-hold': 3 }
                  return (statusOrder[a.status as keyof typeof statusOrder] || 999) - 
                         (statusOrder[b.status as keyof typeof statusOrder] || 999)
                }
                const orderA = a.order !== undefined ? a.order : 999999
                const orderB = b.order !== undefined ? b.order : 999999
                return orderA - orderB
              })
            }
          }
          
          return oldData
        }
      )

      // Prepare API request body - include status changes for cross-column moves
      const requestBody = {
        updates: updates.map(update => ({
          id: update.id,
          order: update.order,
          ...(update.status && { status: update.status })
        }))
      }

      // Make API call
      const response = await apiRequest(`${taskOptions.baseUrl}/bulk-order`, {
        method: 'PATCH',
        body: JSON.stringify(requestBody)
      })

      const serverData = response?.data || response
      
      if (serverData && Array.isArray(serverData)) {
        // Clean server data and unlock updates
        const cleanServerData = serverData.map((task: any) => {
          const { _optimistic, _lockUpdate, ...cleanTask } = task
          return cleanTask
        }).sort((a: any, b: any) => {
          // Maintain proper sorting by status then order
          if (a.status !== b.status) {
            const statusOrder = { 'pending': 0, 'in-progress': 1, 'completed': 2, 'on-hold': 3 }
            return (statusOrder[a.status as keyof typeof statusOrder] || 999) - 
                   (statusOrder[b.status as keyof typeof statusOrder] || 999)
          }
          const orderA = a.order !== undefined ? a.order : 999999
          const orderB = b.order !== undefined ? b.order : 999999
          return orderA - orderB
        })
        
        // Apply final server state smoothly
        dispatch(setTasks(cleanServerData))
        
        // Unlock and update all caches with clean server data
        queryClient.setQueriesData(
          { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
          (oldData: any) => {
            if (!oldData) return oldData
            
            if (Array.isArray(oldData)) {
              return cleanServerData
            }
            
            if (oldData.data && Array.isArray(oldData.data)) {
              return { ...oldData, data: cleanServerData }
            }
            
            return oldData
          }
        )
        
        // Invalidate analytics for affected projects
        const projectIds = new Set(cleanServerData.map((task: any) => task.projectId).filter(Boolean))
        if (projectIds.size > 0) {
          // Invalidate all analytics queries
          await queryClient.invalidateQueries({ 
            queryKey: ['analytics'] 
          })
          
          // Invalidate and refetch project-specific analytics
          for (const projectId of projectIds) {
            await queryClient.invalidateQueries({ 
              predicate: (query) => {
                const key = query.queryKey
                return key && key[0] === 'project-analytics' && key[1] === projectId
              }
            })
            // Refetch analytics immediately
            await queryClient.refetchQueries({
              predicate: (query) => {
                const key = query.queryKey
                return key && key[0] === 'project-analytics' && key[1] === projectId
              }
            })
          }
        }
      }

      return response
    } catch (error) {
      console.error('Bulk order update failed:', error)
      handleAPIError(error, 'Failed to update task order')
      
      // Clean revert to original state (remove optimistic flags)
      const cleanOriginalTasks = originalTasks.map((task: any) => {
        const { _optimistic, _lockUpdate, ...cleanTask } = task
        return cleanTask
      })
      
      dispatch(setTasks(cleanOriginalTasks))
      
      // Unlock and revert all cached queries
      queryClient.setQueriesData(
        { predicate: (query) => query.queryKey[0] === taskOptions.entityName },
        (oldData: any) => {
          if (!oldData) return oldData
          
          if (Array.isArray(oldData)) {
            return cleanOriginalTasks
          }
          
          if (oldData.data && Array.isArray(oldData.data)) {
            return { ...oldData, data: cleanOriginalTasks }
          }
          
          return oldData
        }
      )
      
      throw error
    }
  }, [taskOptions.baseUrl, taskOptions.entityName, queryClient, tasks, dispatch])

  // Filter and sort operations
  const handleSetFilters = useCallback((newFilters: Partial<TaskFilters>) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  const isActionLoadingForTask = useCallback((id?: string) => {
    if (!id) return false
    return !!actionLoadingTasks?.[id]
  }, [actionLoadingTasks])

  const isActionLoadingForDepartment = useCallback((id?: string) => {
    if (!id) return false
    return !!actionLoadingDepartments?.[id]
  }, [actionLoadingDepartments])

  const handleSetSort = useCallback((newSort: TaskSort) => {
    dispatch(setSort(newSort))
  }, [dispatch])

  const handleSetPagination = useCallback((newPagination: { page?: number; limit?: number }) => {
    dispatch(setPagination(newPagination))
  }, [dispatch])

  const handleSetSelectedTask = useCallback((task: typeof selectedTask) => {
    dispatch(setSelectedTask(task))
  }, [dispatch])

  // Utility operations
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleResetState = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  const refreshTasks = useCallback(() => {
    return handleFetchTasks()
  }, [handleFetchTasks])

  // Computed values
  const hasTasks = tasks.length > 0
  const hasTaskHierarchy = hierarchy ? true : false
  const isFirstPage = pagination.page === 1
  const isLastPage = pagination.page >= pagination.pages
  const totalPages = pagination.pages
  const totalItems = pagination.total

  // Status-based getters
  const pendingTasks = tasks.filter((t: any) => t.status === 'pending')
  const inProgressTasks = tasks.filter((t: any) => t.status === 'in-progress')
  const completedTasks = tasks.filter((t: any) => t.status === 'completed')
  const onHoldTasks = tasks.filter((t: any) => t.status === 'on-hold')
  const cancelledTasks = tasks.filter((t: any) => t.status === 'cancelled')

  // Type-based getters
  const mainTasks = tasks.filter((t: any) => t.type === 'task')
  const subTasks = tasks.filter((t: any) => t.type === 'sub-task')

  // Priority-based getters
  const urgentTasks = tasks.filter((t: any) => t.priority === 'urgent')
  const highPriorityTasks = tasks.filter((t: any) => t.priority === 'high')

  // Helper functions
  const getTasksByStatus = useCallback((status: string) => {
    return tasks.filter((t: any) => t.status === status)
  }, [tasks])

  const getTasksByPriority = useCallback((priority: string) => {
    return tasks.filter((t: any) => t.priority === priority)
  }, [tasks])

  const getTasksByProject = useCallback((projectId: string) => {
    return tasks.filter((t: any) => t.projectId === projectId)
  }, [tasks])

  const getTasksByDepartment = useCallback((departmentId: string) => {
    return tasks.filter((t: any) => t.departmentId === departmentId)
  }, [tasks])

  const getTasksByAssignee = useCallback((assigneeId: string) => {
    return tasks.filter((t: any) => t.assigneeId === assigneeId)
  }, [tasks])

  const getSubTasksByParent = useCallback((parentTaskId: string) => {
    return tasks.filter((t: any) => t.parentTaskId === parentTaskId)
  }, [tasks])

  const getMyTasks = useCallback((userId: string) => {
    return tasks.filter((t: any) => t.assigneeId === userId || t.createdBy === userId)
  }, [tasks])

  const getOverdueTasks = useCallback(() => {
    const now = new Date()
    return tasks.filter((t: any) => {
      if (!t.dueDate || t.status === 'completed' || t.status === 'cancelled') return false
      return new Date(t.dueDate) < now
    })
  }, [tasks])

  const getTasksCompletionRate = useCallback(() => {
    if (tasks.length === 0) return 0
    const completedCount = tasks.filter((t: any) => t.status === 'completed').length
    return Math.round((completedCount / tasks.length) * 100)
  }, [tasks])

  // Permission checks
  const canCreateTask = useCallback(() => {
    // Logic to determine if user can create tasks
    // This would typically check user permissions and role
    return true // Simplified for now
  }, [])

  const canEditTask = useCallback((task: typeof selectedTask) => {
    // Logic to determine if user can edit a specific task
    // This would typically check user permissions, role, and task status
    return task && task.status !== 'completed' && task.status !== 'cancelled'
  }, [])

  const canDeleteTask = useCallback((task: typeof selectedTask) => {
    // Logic to determine if user can delete a specific task
    // This would typically check user permissions and task status
    return task && task.status !== 'completed' && task.status !== 'cancelled'
  }, [])

  const canAssignTask = useCallback((task: typeof selectedTask) => {
    // Logic to determine if user can assign a task
    return task && task.status !== 'completed' && task.status !== 'cancelled'
  }, [])

  const canUpdateTaskStatus = useCallback((task: typeof selectedTask) => {
    // Logic to determine if user can update task status
    return task && task.status !== 'cancelled'
  }, [])

  const canCreateSubTask = useCallback((parentTask: typeof selectedTask) => {
    // Logic to determine if user can create sub-tasks for a parent task
    return parentTask && parentTask.type === 'task' && parentTask.status !== 'completed' && parentTask.status !== 'cancelled'
  }, [])

  // Convenience functions for inline operations
  const updateTaskDueDate = useCallback(async (taskId: string, dueDate: string) => {
    return handleUpdateTask(taskId, { dueDate: new Date(dueDate).toISOString() })
  }, [handleUpdateTask])

  const updateTaskPriority = useCallback(async (taskId: string, priority: string) => {
    return handleUpdateTask(taskId, { priority: priority as any })
  }, [handleUpdateTask])

  const updateTaskField = useCallback(async (taskId: string, field: string, value: any) => {
    return handleUpdateTask(taskId, { [field]: value })
  }, [handleUpdateTask])

  return {
    // State
    tasks: fetchedTasks || tasks,
    selectedTask,
    loading: queryLoading || loading,
    actionLoading,
    error,
    filters,
    sort,
    pagination,
    stats,
    hierarchy,

    // CRUD operations
    fetchTasks: handleFetchTasks,
    fetchTaskHierarchy,
    createTask: handleCreateTask,
    updateTask: handleUpdateTask,
    assignTask: handleAssignTask,
    updateTaskStatus: handleUpdateTaskStatus,
    deleteTask: handleDeleteTask,
    restoreTask: handleRestoreTask,
    bulkOrderUpdate: handleBulkOrderUpdate,

    // Filter and sort operations
    setFilters: handleSetFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,
    setSelectedTask: handleSetSelectedTask,

    // Utility operations
    clearError: handleClearError,
    resetState: handleResetState,
    refreshTasks,

    // Computed values
    hasTasks,
    hasTaskHierarchy,
    isFirstPage,
    isLastPage,
    totalPages,
    totalItems,

    // Status-based data
    pendingTasks,
    inProgressTasks,
    completedTasks,
    onHoldTasks,
    cancelledTasks,
    mainTasks,
    subTasks,
    urgentTasks,
    highPriorityTasks,

    // Helper functions
    getTasksByStatus,
    getTasksByPriority,
    getTasksByProject,
    getTasksByDepartment,
    getTasksByAssignee,
    getSubTasksByParent,
    getMyTasks,
    getOverdueTasks,
    getTasksCompletionRate,

    // Convenience functions for inline editing
    updateTaskDueDate,
    updateTaskPriority,
    updateTaskField,

    // Permission checks
    canCreateTask,
    canEditTask,
    canDeleteTask,
    canAssignTask,
    canUpdateTaskStatus,
    canCreateSubTask,
    // Loading helpers
    isActionLoadingForTask,
    isActionLoadingForDepartment,
  }
}