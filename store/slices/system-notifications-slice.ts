import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit'
import { createSystemNotificationSchema } from '@/lib/validations/system-notification'
import { z } from 'zod'

export interface SystemNotification {
  id: string
  type: 'project_created' | 'task_assigned' | 'project_approved' | 'task_completed' | 'project_status_changed' | 'department_assigned'
  category: 'project' | 'task' | 'system' | 'department'
  title: string
  message: string
  contentPreview?: string
  entityType: 'project' | 'task' | 'department' | 'user'
  entityId: string
  entityName?: string
  actionType: 'created' | 'updated' | 'assigned' | 'approved' | 'completed' | 'status_changed'
  actionUrl?: string
  senderName: string
  senderAvatar?: string
  priority: 1 | 2 | 3 | 4
  isRead: boolean
  readAt?: string
  createdAt: string
  metadata?: Record<string, any>
}

interface SystemNotificationsState {
  notifications: SystemNotification[]
  unreadCount: number
  isLoading: boolean
  error: string | null
  pagination: {
    hasMore: boolean
    offset: number
    limit: number
  }
  filters: {
    unreadOnly: boolean
    category?: 'project' | 'task' | 'system' | 'department'
  }
}

const initialState: SystemNotificationsState = {
  notifications: [],
  unreadCount: 0,
  isLoading: false,
  error: null,
  pagination: {
    hasMore: true,
    offset: 0,
    limit: 20
  },
  filters: {
    unreadOnly: false
  }
}

// Async Thunks
export const fetchSystemNotifications = createAsyncThunk(
  'systemNotifications/fetchSystemNotifications',
  async (params: {
    limit?: number
    offset?: number
    unreadOnly?: boolean
    category?: string
    refresh?: boolean
  } = {}) => {
    const { 
      limit = 20, 
      offset = 0, 
      unreadOnly = false, 
      category,
      refresh = false 
    } = params

    const queryParams = new URLSearchParams({
      limit: limit.toString(),
      offset: offset.toString(),
      unreadOnly: unreadOnly.toString()
    })

    if (category) {
      queryParams.append('category', category)
    }

    const response = await fetch(`/api/system-notifications?${queryParams}`)
    
    if (!response.ok) {
      throw new Error('Failed to fetch system notifications')
    }

    const data = await response.json()
    
    return {
      notifications: data.notifications,
      hasMore: data.hasMore,
      offset: refresh ? 0 : offset,
      refresh
    }
  }
)

export const fetchUnreadCount = createAsyncThunk(
  'systemNotifications/fetchUnreadCount',
  async () => {
    const response = await fetch('/api/system-notifications/unread-count')
    
    if (!response.ok) {
      throw new Error('Failed to fetch unread count')
    }

    const data = await response.json()
    return data.count
  }
)

export const markNotificationsAsRead = createAsyncThunk(
  'systemNotifications/markNotificationsAsRead',
  async (notificationIds: string[]) => {
    const response = await fetch('/api/system-notifications/mark-read', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ notificationIds })
    })

    if (!response.ok) {
      throw new Error('Failed to mark notifications as read')
    }

    return notificationIds
  }
)

export const markAllNotificationsAsRead = createAsyncThunk(
  'systemNotifications/markAllNotificationsAsRead',
  async () => {
    const response = await fetch('/api/system-notifications/mark-all-read', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      }
    })

    if (!response.ok) {
      throw new Error('Failed to mark all notifications as read')
    }

    return true
  }
)

const systemNotificationsSlice = createSlice({
  name: 'systemNotifications',
  initialState,
  reducers: {
    // Handle realtime notification updates
    addRealtimeNotification: (state, action: PayloadAction<SystemNotification>) => {
      // Add to the beginning of the array
      state.notifications.unshift(action.payload)
      
      // Update unread count if notification is unread
      if (!action.payload.isRead) {
        state.unreadCount += 1
      }
      
      // Keep only the latest notifications (prevent memory issues)
      if (state.notifications.length > 100) {
        state.notifications = state.notifications.slice(0, 100)
      }
    },

    // Handle realtime notification read status updates
    updateNotificationReadStatus: (state, action: PayloadAction<{
      notificationIds: string[]
      isRead: boolean
    }>) => {
      const { notificationIds, isRead } = action.payload
      
      state.notifications.forEach(notification => {
        if (notificationIds.includes(notification.id)) {
          const wasUnread = !notification.isRead
          notification.isRead = isRead
          
          if (isRead) {
            notification.readAt = new Date().toISOString()
            // Decrease unread count if was previously unread
            if (wasUnread) {
              state.unreadCount = Math.max(0, state.unreadCount - 1)
            }
          } else {
            notification.readAt = undefined
            // Increase unread count if was previously read
            if (!wasUnread) {
              state.unreadCount += 1
            }
          }
        }
      })
    },

    // Set filters
    setFilters: (state, action: PayloadAction<Partial<SystemNotificationsState['filters']>>) => {
      state.filters = { ...state.filters, ...action.payload }
      // Reset pagination when filters change
      state.pagination.offset = 0
      state.pagination.hasMore = true
    },

    // Reset pagination
    resetPagination: (state) => {
      state.pagination.offset = 0
      state.pagination.hasMore = true
    },

    // Clear error
    clearError: (state) => {
      state.error = null
    },

    // Clear all notifications (useful for logout)
    clearNotifications: (state) => {
      state.notifications = []
      state.unreadCount = 0
      state.pagination = { ...initialState.pagination }
    },

    // Update unread count directly (for optimistic updates)
    updateUnreadCount: (state, action: PayloadAction<number>) => {
      state.unreadCount = Math.max(0, action.payload)
    }
  },
  extraReducers: (builder) => {
    // Fetch system notifications
    builder.addCase(fetchSystemNotifications.pending, (state, action) => {
      state.isLoading = true
      state.error = null
    })
    
    builder.addCase(fetchSystemNotifications.fulfilled, (state, action) => {
      state.isLoading = false
      const { notifications, hasMore, offset, refresh } = action.payload
      
      if (refresh || offset === 0) {
        // Replace all notifications
        state.notifications = notifications
      } else {
        // Append new notifications
        state.notifications = [...state.notifications, ...notifications]
      }
      
      state.pagination.hasMore = hasMore
      state.pagination.offset = offset + notifications.length
    })
    
    builder.addCase(fetchSystemNotifications.rejected, (state, action) => {
      state.isLoading = false
      state.error = action.error.message || 'Failed to fetch notifications'
    })

    // Fetch unread count
    builder.addCase(fetchUnreadCount.fulfilled, (state, action) => {
      state.unreadCount = action.payload
    })

    // Mark notifications as read
    builder.addCase(markNotificationsAsRead.fulfilled, (state, action) => {
      const notificationIds = action.payload
      
      state.notifications.forEach(notification => {
        if (notificationIds.includes(notification.id) && !notification.isRead) {
          notification.isRead = true
          notification.readAt = new Date().toISOString()
          state.unreadCount = Math.max(0, state.unreadCount - 1)
        }
      })
    })

    // Mark all notifications as read
    builder.addCase(markAllNotificationsAsRead.fulfilled, (state) => {
      state.notifications.forEach(notification => {
        if (!notification.isRead) {
          notification.isRead = true
          notification.readAt = new Date().toISOString()
        }
      })
      state.unreadCount = 0
    })
  }
})

export const {
  addRealtimeNotification,
  updateNotificationReadStatus,
  setFilters,
  resetPagination,
  clearError,
  clearNotifications,
  updateUnreadCount
} = systemNotificationsSlice.actions

// Selectors
export const selectSystemNotifications = (state: any) => state.systemNotifications.notifications
export const selectUnreadCount = (state: any) => state.systemNotifications.unreadCount
export const selectIsLoading = (state: any) => state.systemNotifications.isLoading
export const selectError = (state: any) => state.systemNotifications.error
export const selectPagination = (state: any) => state.systemNotifications.pagination
export const selectFilters = (state: any) => state.systemNotifications.filters

// Filtered selectors
export const selectUnreadNotifications = (state: any) => 
  state.systemNotifications.notifications.filter((n: SystemNotification) => !n.isRead)

export const selectNotificationsByCategory = (category: string) => (state: any) =>
  state.systemNotifications.notifications.filter((n: SystemNotification) => n.category === category)

export const selectRecentNotifications = (limit: number = 5) => (state: any) =>
  state.systemNotifications.notifications
    .slice(0, limit)
    .sort((a: SystemNotification, b: SystemNotification) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    )

export default systemNotificationsSlice.reducer