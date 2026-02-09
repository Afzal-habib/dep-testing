import { useCallback, useMemo } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import {
  useGenericQuery,
  useGenericCreate,
  useGenericUpdate,
  useGenericDelete,
  type UseGenericQueryOptions,
} from './use-generic-query'
import { useQueryClient } from "@tanstack/react-query"
import { apiRequest, handleAPIError } from '@/lib/utils/api-client'
import type {
  CreateCommentFormData,
  UpdateCommentFormData,
  CommentQueryParams,
} from '@/lib/validations/comment'

// Comment state type
interface CommentState {
  comments: any[]
  selectedComment: any | null
  loading: boolean
  actionLoading: boolean
  error: any
  filters: {
    taskId?: string
    projectId?: string
    authorId?: string
  }
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
}

export function useComments() {
  const dispatch = useAppDispatch()

  // Since we don't have a comment slice yet, we'll manage state locally
  // In a full implementation, you would create a commentSlice similar to taskSlice
  const initialState: CommentState = {
    comments: [],
    selectedComment: null,
    loading: false,
    actionLoading: false,
    error: null,
    filters: {},
    pagination: { page: 1, limit: 20, total: 0, pages: 0 },
  }

  // For now, we'll use a simplified approach with TanStack Query only
  // Define options for generic hooks
  const commentOptions: UseGenericQueryOptions<any> = {
    entityName: 'comments',
    baseUrl: '/api/comments',
    reduxDispatchers: {
      setEntities: () => {}, // Placeholder - would use Redux in full implementation
      setEntity: () => {},
      setPagination: () => {},
      setLoading: () => {},
      setActionLoading: () => {},
      setError: () => {},
      clearError: () => {},
    },
  }

  const queryClient = useQueryClient()

  // Helper: attempt to derive taskId for a comment by:
  // 1) checking provided normalizedResult
  // 2) scanning comment list caches
  // 3) hitting the single comment API endpoint as last resort
  const deriveTaskIdForComment = useCallback(async (commentId: string | undefined, normalizedResult?: any) => {
    if (!commentId) return undefined
    // If we already have a taskId, return immediately
    if (normalizedResult?.taskId) return String(normalizedResult.taskId)

    // Try to find a matching comment in the cached `comments` queries
    try {
      const caches = queryClient.getQueryCache().findAll()
      for (const q of caches) {
        const qk = q.queryKey
        if (!Array.isArray(qk) || qk[0] !== 'comments') continue
        const cachedData = q.state?.data
        if (Array.isArray(cachedData)) {
          for (const item of cachedData) {
            const id = String(item?._id ?? item?.id)
            if (id === String(commentId)) {
              if (item?.taskId) return String(item.taskId)
              // If we found the comment itself, maybe it's a reply for which the parent contains taskId
              if (item?.parentCommentId) {
                // look for parent
                const parent = cachedData.find((p: any) => String(p?._id ?? p?.id) === String(item.parentCommentId))
                if (parent?.taskId) return String(parent.taskId)
              }
            }
            // Check nested replies
            if (item?.replies && Array.isArray(item.replies)) {
              for (const r of item.replies) {
                const rid = String(r?._id ?? r?.id)
                if (rid === String(commentId)) {
                  if (item?.taskId) return String(item.taskId)
                }
              }
            }
          }
        }
      }
    } catch (e) {
      // ignore and fallback to server request
    }

    // If not found in cache, try server request
    try {
      const response = await apiRequest(`/api/comments/${commentId}`)
      const apiData = response?.data || response
      const commentObj = apiData?.data || apiData
      if (commentObj?.taskId) return String(commentObj.taskId)
    } catch (e) {
      // ignore further errors
    }

    return undefined
  }, [queryClient])

  // Fetch comments for a specific task
  // Fetch comments for a specific task
  // Use the canonical entity name ('comments') and pass taskId as a filter
  const useTaskComments = (taskId: string, projectId?: string) => {
    const queryParams = useMemo(() => ({
      page: 1,
      limit: 50, // Load more comments for tasks
      filters: {
        taskId: taskId || undefined,
        projectId: projectId || undefined,
      }
    }), [taskId, projectId])

    // Use the canonical `comments` entity name (commentOptions) so cache keys and
    // invalidation align across create/update/delete operations.
    return useGenericQuery(commentOptions, queryParams, !!taskId)
  }

  // CRUD operations
  const createMutation = useGenericCreate(commentOptions)
  const updateMutation = useGenericUpdate(commentOptions)
  const deleteMutation = useGenericDelete(commentOptions)

  // Create comment
  const createComment = useCallback(async (commentData: CreateCommentFormData) => {
    try {
      const result = await createMutation.mutateAsync(commentData)
      const normalizedResult = result ? { ...(result as any), _id: (result as any)._id ?? (result as any).id } : result
      // Try to optimistically update matching queries that are filtered by the
      // taskId we just created a comment for, then invalidate relevant queries.
      const taskFilterId = commentData.taskId
      // Update query cache for all `comments` queries filtered by taskId
      queryClient.getQueryCache().findAll().forEach((q) => {
        try {
          const qk = q.queryKey
          if (Array.isArray(qk) && qk[0] === 'comments' && qk.length >= 4) {
            const filters = qk[3] as any
                if (filters && filters.taskId && String(filters.taskId) === String(taskFilterId)) {
              queryClient.setQueryData(qk, (old: any) => {
                if (!old) return [normalizedResult]
                // prepend result so newest comment appears first as typical UX
                return [normalizedResult, ...old]
              })
            }
          }
        } catch (e) {
          /* ignore cache update errors */
        }
      })

      // Don't immediately refetch 'comments' list: server-side caching on
      // list endpoints might still be warm and return stale results which
      // would overwrite our optimistic update; instead, schedule a delayed
      // revalidation so the server cache has time to clear.
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['comments'] })
      }, 65000)

      // Also invalidate the specific task so that the Task Details modal
      // (which fetches task by id) can refresh and show up-to-date metadata
      // (e.g., comment counts) without needing to close and re-open.
      const tid = normalizedResult?.taskId || commentData.taskId
      if (tid) {
        await queryClient.invalidateQueries({ queryKey: ['tasks', String(tid)] })
      }
      
      return normalizedResult
    } catch (error) {
      handleAPIError(error, 'Failed to create comment')
      throw error
    }
  }, [createMutation, queryClient])

  // Update comment
  const updateComment = useCallback(async (id: string, data: UpdateCommentFormData) => {
    try {
      const result = await updateMutation.mutateAsync({ id, data })
      const normalizedResult = result ? { ...(result as any), _id: (result as any)._id ?? (result as any).id } : result
      // Attempt to perform a targeted invalidation based on the returned comment
      // (preferable), falling back to a broad invalidation otherwise.
      // Derive taskId using helper (from result, provided data, or cache/server)
      let taskId = (normalizedResult as any)?.taskId || (data as any)?.taskId
      if (!taskId) {
        taskId = await deriveTaskIdForComment(id, normalizedResult)
      }
      // Update comment in cached queries to keep UI snappy: replace the comment by _id
      try {
        queryClient.getQueryCache().findAll().forEach((q) => {
          const qk = q.queryKey
          if (!Array.isArray(qk) || qk[0] !== 'comments') return
          const cached = q.state?.data
          if (!Array.isArray(cached)) return
          const newArr = cached.map((c: any) => {
            if (String(c?._id ?? c?.id) === String(id)) {
              return { ...(c || {}), ...(normalizedResult || {}), _id: (normalizedResult as any)?._id ?? c?._id }
            }
            // check nested replies
            if (c?.replies && Array.isArray(c.replies)) {
              const newReplies = c.replies.map((r: any) => String(r?._id ?? r?.id) === String(id) ? { ...(r || {}), ...(normalizedResult || {}), _id: (normalizedResult as any)?._id ?? r?._id } : r)
              return { ...c, replies: newReplies }
            }
            return c
          })
          queryClient.setQueryData(qk, newArr)
        })
      } catch (e) {
        // ignore
      }

      if (taskId) {
        // schedule delayed revalidation for this task's comment lists
        setTimeout(() => {
          queryClient.invalidateQueries({ predicate: (query) => Array.isArray(query.queryKey) && query.queryKey[0] === 'comments' && query.queryKey.length >= 4 && (query.queryKey[3] as any).taskId === taskId })
        }, 65000)
        await queryClient.invalidateQueries({ queryKey: ['tasks', String(taskId)] })
      } else {
        setTimeout(() => {
          queryClient.invalidateQueries({ queryKey: ['comments'] })
        }, 65000)
      }
      
      return normalizedResult
    } catch (error) {
      handleAPIError(error, 'Failed to update comment')
      throw error
    }
  }, [updateMutation, queryClient])

  // Delete comment
  const deleteComment = useCallback(async (commentId: string) => {
    try {
      const result: any = await deleteMutation.mutateAsync(commentId)
      let normalizedResult: any = undefined
      if (result && typeof result === 'object') {
        normalizedResult = { ...(result as any), _id: (result as any)._id ?? (result as any).id }
      }
      // If possible, discover a matching query entry to invalidate only the
      // affected task comments; otherwise fall back to broad invalidation.
      const found = queryClient.getQueryCache().findAll().some((q) => {
        const qk = q.queryKey
        if (!Array.isArray(qk) || qk[0] !== 'comments' || qk.length < 4) return false
        const filters = qk[3] as any
        // Not all queries have filters but if they do, we'll look for parent relationship
        return !!filters?.taskId
      })
      if (found) {
        // Optimistically remove deleted comment from cached lists and nested replies
        try {
          queryClient.getQueryCache().findAll().forEach((q) => {
            const qk = q.queryKey
            if (!Array.isArray(qk) || qk[0] !== 'comments') return
            const cached = q.state?.data
            if (!Array.isArray(cached)) return
            const newArr = cached
              .map((c: any) => {
                if (String(c?._id ?? c?.id) === String(commentId)) return null
                if (c?.replies && Array.isArray(c.replies)) {
                  const newReplies = c.replies.filter((r: any) => String(r?._id ?? r?.id) !== String(commentId))
                  return { ...c, replies: newReplies }
                }
                return c
              })
              .filter(Boolean)
            queryClient.setQueryData(qk, newArr)
          })
        } catch (e) {
          // ignore
        }
        // Invalidate all comments queries that have task filters (targeted but not exact)
        setTimeout(() => {
          queryClient.invalidateQueries({ predicate: (query) => Array.isArray(query.queryKey) && query.queryKey[0] === 'comments' && query.queryKey.length >= 4 && !!((query.queryKey[3] as any)?.taskId) })
        }, 65000)
      } else {
        setTimeout(() => {
          queryClient.invalidateQueries({ queryKey: ['comments'] })
        }, 65000)
      }
      // Attempt to find the comment's taskId in cache and invalidate its task-specific query
      let targetTaskId: string | undefined
      try {
        const commentQuery = queryClient.getQueryCache().findAll().find((q) => {
          const k = q.queryKey
          return Array.isArray(k) && k[0] === 'comments' && q.state?.data && Array.isArray(q.state.data)
        })
        if (commentQuery?.state?.data) {
          for (const item of commentQuery.state.data as any[]) {
            if (String(item?._id || item?.id) === String(commentId)) {
              targetTaskId = item?.taskId
              break
            }
          }
        }
      } catch (e) {
        /* ignore */
      }
      // Final fallback: if targetTaskId still unknown, try server
      if (!targetTaskId) {
        try {
          const res = await apiRequest(`/api/comments/${commentId}`)
          const apiData = res?.data || res
          const commentObj = apiData?.data || apiData
          if (commentObj?.taskId) {
            targetTaskId = String(commentObj.taskId)
          }
        } catch (e) {
          // ignore
        }
      }
      if (targetTaskId) {
        await queryClient.invalidateQueries({ queryKey: ['tasks', String(targetTaskId)] })
      }
      
      return normalizedResult
    } catch (error) {
      handleAPIError(error, 'Failed to delete comment')
      throw error
    }
  }, [deleteMutation, queryClient])

  // Reply to comment
  const replyToComment = useCallback(async (commentData: CreateCommentFormData & { parentCommentId: string }) => {
    try {
      const result = await createMutation.mutateAsync(commentData)
      const normalizedResult = result ? { ...(result as any), _id: (result as any)._id ?? (result as any).id } : result
      // Update matching cache for the task for immediate UX
      const taskFilterId = commentData.taskId
      // If this is a reply, insert it into the parent comment's replies array
      if (normalizedResult?.parentCommentId) {
        const parentId = String(normalizedResult.parentCommentId || commentData.parentCommentId)
        try {
          queryClient.getQueryCache().findAll().forEach((q) => {
            const qk = q.queryKey
            if (!Array.isArray(qk) || qk[0] !== 'comments') return
            const cached = q.state?.data
            if (!Array.isArray(cached)) return
            const newArr = cached.map((c: any) => {
              if (String(c?._id ?? c?.id) === String(parentId)) {
                const existingReplies = Array.isArray(c.replies) ? c.replies : []
                return { ...c, replies: [...existingReplies, normalizedResult] }
              }
              return c
            })
            queryClient.setQueryData(qk, newArr)
          })
        } catch (e) {
          // ignore cache update errors
        }
      } else {
        queryClient.getQueryCache().findAll().forEach((q) => {
          try {
            const qk = q.queryKey
            if (Array.isArray(qk) && qk[0] === 'comments' && qk.length >= 4) {
              const filters = qk[3] as any
              if (filters && filters.taskId && String(filters.taskId) === String(taskFilterId)) {
                queryClient.setQueryData(qk, (old: any) => {
                  if (!old) return [normalizedResult]
                  return [normalizedResult, ...old]
                })
              }
            }
          } catch (e) {
            /* ignore cache update errors */
          }
        })
      }

      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['comments'] })
      }, 3000)
      if (normalizedResult?.taskId || commentData.taskId) {
        await queryClient.invalidateQueries({ queryKey: ['tasks', String(normalizedResult?.taskId || commentData.taskId)] })
      }
      
      return normalizedResult
    } catch (error) {
      handleAPIError(error, 'Failed to reply to comment')
      throw error
    }
  }, [createMutation, queryClient])

  // Refresh comments for a task
  const refreshTaskComments = useCallback(async (taskId?: string) => {
    if (taskId) {
      // Replace just the queries for this taskId
      await queryClient.invalidateQueries({ predicate: (query) => Array.isArray(query.queryKey) && query.queryKey[0] === 'comments' && query.queryKey.length >= 4 && (query.queryKey[3] as any).taskId === taskId })
      return
    }
    await queryClient.invalidateQueries({ queryKey: ['comments'] })
  }, [queryClient])

  return {
    // Hooks
    useTaskComments,
    
    // Actions
    createComment,
    updateComment,
    deleteComment,
    replyToComment,
    refreshTaskComments,
    
    // Mutation states
    creating: createMutation.isPending,
    updating: updateMutation.isPending,
    deleting: deleteMutation.isPending,
    
    // Errors
    createError: createMutation.error,
    updateError: updateMutation.error,
    deleteError: deleteMutation.error,
  }
}