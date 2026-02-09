'use client'

import { useEffect, useCallback } from 'react'
import { useAppDispatch, useAppSelector } from './redux'
import {
  fetchSystemNotifications,
  fetchUnreadCount,
  markNotificationsAsRead,
  markAllNotificationsAsRead,
  setFilters,
  resetPagination,
  clearNotifications,
  addRealtimeNotification,
  updateNotificationReadStatus,
  selectSystemNotifications,
  selectUnreadCount,
  selectIsLoading,
  selectError,
  selectPagination,
  selectFilters,
  selectUnreadNotifications,
  selectNotificationsByCategory,
  selectRecentNotifications,
  SystemNotification
} from '@/store/slices/system-notifications-slice'
import { toast } from './use-toast'
import { getRealtimeManager } from '@/lib/realtime-manager'

export interface UseSystemNotificationsOptions {
  autoFetch?: boolean
  enableRealtime?: boolean
  enableToasts?: boolean
  toastPriorityThreshold?: number
}

// Custom hook for Supabase realtime specifically for notifications
function useSupabaseRealtime(config: { 
  channel: string; 
  event: string; 
  callback: (payload: any) => void 
}, options?: { enabled?: boolean }) {
  useEffect(() => {
    if (!options?.enabled) return
    
    const realtimeManager = getRealtimeManager()
    
    // Subscribe to user-specific notifications
    const handleNotification = (payload: any) => {
      if (payload.event === config.event) {
        config.callback(payload.payload)
      }
    }
    
    // Add the handler
    realtimeManager.updateHandlers({
      onNewMessageNotification: handleNotification
    })
    
    return () => {
      // Cleanup if needed
    }
  }, [config.channel, config.event, config.callback, options?.enabled])
}

export function useSystemNotifications(options: UseSystemNotificationsOptions = {}) {
  const {
    autoFetch = true,
    enableRealtime = true,
    enableToasts = true,
    toastPriorityThreshold = 3
  } = options

  const dispatch = useAppDispatch()
  
  // Selectors
  const notifications = useAppSelector(selectSystemNotifications)
  const unreadCount = useAppSelector(selectUnreadCount)
  const isLoading = useAppSelector(selectIsLoading)
  const error = useAppSelector(selectError)
  const pagination = useAppSelector(selectPagination)
  const filters = useAppSelector(selectFilters)
  const unreadNotifications = useAppSelector(selectUnreadNotifications)

  // Initialize notifications
  useEffect(() => {
    if (autoFetch) {
      dispatch(fetchUnreadCount())
      dispatch(fetchSystemNotifications({ 
        limit: 20, 
        offset: 0, 
        refresh: true,
        unreadOnly: filters.unreadOnly,
        category: filters.category 
      }))
    }
  }, [dispatch, autoFetch, filters.unreadOnly, filters.category])

  // Setup realtime listener
  useSupabaseRealtime({
    channel: 'user_notifications',
    event: 'system_notification',
    callback: useCallback((payload: SystemNotification) => {
      if (!enableRealtime) return

      dispatch(addRealtimeNotification(payload))
      
      // Show toast for high priority notifications
      if (enableToasts && payload.priority >= toastPriorityThreshold) {
        toast({
          title: payload.title,
          description: payload.message
        })
      }
    }, [dispatch, enableRealtime, enableToasts, toastPriorityThreshold])
  }, { enabled: enableRealtime })

  // Actions
  const actions = {
    // Fetch notifications with options
    fetchNotifications: useCallback((options: {
      limit?: number
      offset?: number
      unreadOnly?: boolean
      category?: string
      refresh?: boolean
    } = {}) => {
      return dispatch(fetchSystemNotifications(options))
    }, [dispatch]),

    // Load more notifications
    loadMore: useCallback(() => {
      if (!isLoading && pagination.hasMore) {
        return dispatch(fetchSystemNotifications({
          limit: 20,
          offset: pagination.offset,
          unreadOnly: filters.unreadOnly,
          category: filters.category,
          refresh: false
        }))
      }
    }, [dispatch, isLoading, pagination, filters]),

    // Refresh notifications
    refresh: useCallback(() => {
      dispatch(resetPagination())
      return dispatch(fetchSystemNotifications({
        limit: 20,
        offset: 0,
        refresh: true,
        unreadOnly: filters.unreadOnly,
        category: filters.category
      }))
    }, [dispatch, filters]),

    // Mark specific notifications as read
    markAsRead: useCallback(async (notificationIds: string[]) => {
      try {
        await dispatch(markNotificationsAsRead(notificationIds)).unwrap()
        return { success: true }
      } catch (error) {
        toast({
          title: 'Error',
          description: 'Failed to mark notifications as read',
          variant: 'destructive'
        })
        return { success: false, error }
      }
    }, [dispatch]),

    // Mark all notifications as read
    markAllAsRead: useCallback(async () => {
      try {
        await dispatch(markAllNotificationsAsRead()).unwrap()
        toast({
          title: 'Success',
          description: 'All notifications marked as read'
        })
        return { success: true }
      } catch (error) {
        toast({
          title: 'Error',
          description: 'Failed to mark all notifications as read',
          variant: 'destructive'
        })
        return { success: false, error }
      }
    }, [dispatch]),

    // Update filters
    setFilters: useCallback((newFilters: {
      unreadOnly?: boolean
      category?: 'project' | 'task' | 'system' | 'department'
    }) => {
      dispatch(setFilters(newFilters))
    }, [dispatch]),

    // Clear all notifications (useful for logout)
    clear: useCallback(() => {
      dispatch(clearNotifications())
    }, [dispatch]),

    // Get unread count
    refreshUnreadCount: useCallback(() => {
      return dispatch(fetchUnreadCount())
    }, [dispatch])
  }

  // Computed values
  const computed = {
    hasUnread: unreadCount > 0,
    hasNotifications: notifications.length > 0,
    canLoadMore: pagination.hasMore && !isLoading,
    
    // Get notifications by category
    getByCategory: useCallback((category: string) => {
      return useAppSelector(selectNotificationsByCategory(category))
    }, []),

    // Get recent notifications
    getRecent: useCallback((limit: number = 5) => {
      return useAppSelector(selectRecentNotifications(limit))
    }, []),

    // Filter notifications
    filterNotifications: useCallback((filterFn: (notification: SystemNotification) => boolean) => {
      return notifications.filter(filterFn)
    }, [notifications])
  }

  // Stats
  const stats = {
    total: notifications.length,
    unread: unreadCount,
    read: notifications.length - unreadCount,
    byCategory: notifications.reduce((acc: Record<string, number>, notification: SystemNotification) => {
      acc[notification.category] = (acc[notification.category] || 0) + 1
      return acc
    }, {} as Record<string, number>),
    byPriority: notifications.reduce((acc: Record<number, number>, notification: SystemNotification) => {
      acc[notification.priority] = (acc[notification.priority] || 0) + 1
      return acc
    }, {} as Record<number, number>)
  }

  return {
    // State
    notifications,
    unreadNotifications,
    unreadCount,
    isLoading,
    error,
    pagination,
    filters,

    // Actions
    ...actions,

    // Computed
    ...computed,

    // Stats
    stats
  }
}

// Specialized hooks for specific use cases
export function useUnreadNotifications() {
  const { unreadNotifications, unreadCount, markAsRead } = useSystemNotifications({
    autoFetch: true,
    enableRealtime: true
  })

  return {
    unreadNotifications,
    unreadCount,
    markAsRead
  }
}

export function useNotificationsByCategory(category: 'project' | 'task' | 'system' | 'department') {
  const notifications = useAppSelector(selectNotificationsByCategory(category))
  const { markAsRead, refresh } = useSystemNotifications({ autoFetch: false })

  return {
    notifications,
    markAsRead,
    refresh
  }
}

export function useRecentNotifications(limit: number = 5) {
  const recent = useAppSelector(selectRecentNotifications(limit))
  const { markAsRead } = useSystemNotifications({ autoFetch: true })

  return {
    recent,
    markAsRead
  }
}