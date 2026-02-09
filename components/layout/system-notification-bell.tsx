'use client'

import { useState, useEffect } from 'react'
import { Bell, BellRing, X, Check, CheckCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useAppDispatch, useAppSelector } from '@/hooks/redux'
import {
  fetchSystemNotifications,
  fetchUnreadCount,
  markNotificationsAsRead,
  markAllNotificationsAsRead,
  selectSystemNotifications,
  selectUnreadCount,
  selectIsLoading,
  selectPagination,
  addRealtimeNotification,
  updateNotificationReadStatus,
  SystemNotification
} from '@/store/slices/system-notifications-slice'
import { formatDistanceToNow } from 'date-fns'
import { cn } from '@/lib/utils'
import { toast } from '@/hooks/use-toast'
import { getRealtimeManager } from '@/lib/realtime-manager'

interface NotificationIconProps {
  unreadCount: number
  isOpen: boolean
}

const NotificationIcon = ({ unreadCount, isOpen }: NotificationIconProps) => (
  <div className="relative">
    {isOpen ? (
      <BellRing className="h-5 w-5" />
    ) : (
      <Bell className="h-5 w-5" />
    )}
    {unreadCount > 0 && (
      <Badge 
        variant="destructive" 
        className="absolute -top-2 -right-2 h-5 w-5 p-0 flex items-center justify-center text-[10px] font-bold"
      >
        {unreadCount > 99 ? '99+' : unreadCount}
      </Badge>
    )}
  </div>
)

interface NotificationItemProps {
  notification: SystemNotification
  onMarkAsRead: (id: string) => void
  onNavigate: (url: string) => void
}

const NotificationItem = ({ notification, onMarkAsRead, onNavigate }: NotificationItemProps) => {
  const handleClick = () => {
    if (!notification.isRead) {
      onMarkAsRead(notification.id)
    }
    if (notification.actionUrl) {
      onNavigate(notification.actionUrl)
    }
  }

  const getPriorityColor = (priority: number) => {
    switch (priority) {
      case 4: return 'border-l-red-500 bg-red-50'
      case 3: return 'border-l-orange-500 bg-orange-50'
      case 2: return 'border-l-blue-500 bg-blue-50'
      default: return 'border-l-gray-300 bg-gray-50'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'task_assigned':
        return '📋'
      case 'project_created':
        return '🚀'
      case 'project_approved':
        return '✅'
      case 'task_completed':
        return '🎉'
      case 'project_status_changed':
        return '🔄'
      case 'department_assigned':
        return '👥'
      default:
        return '🔔'
    }
  }

  return (
    <div
      className={cn(
        'p-3 border-l-4 cursor-pointer hover:bg-gray-100 transition-colors',
        notification.isRead ? 'bg-white border-l-gray-200' : getPriorityColor(notification.priority)
      )}
      onClick={handleClick}
    >
      <div className="flex items-start gap-3">
        <div className="text-lg flex-shrink-0 mt-1">
          {getTypeIcon(notification.type)}
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-1">
            <h4 className={cn(
              'text-sm font-medium truncate',
              !notification.isRead && 'font-semibold'
            )}>
              {notification.title}
            </h4>
            {!notification.isRead && (
              <div className="w-2 h-2 bg-blue-500 rounded-full flex-shrink-0 ml-2" />
            )}
          </div>
          
          <p className="text-xs text-gray-600 mb-2 line-clamp-2">
            {notification.message}
          </p>
          
          {notification.contentPreview && (
            <p className="text-xs text-gray-500 mb-2 line-clamp-1">
              {notification.contentPreview}
            </p>
          )}
          
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span className="flex items-center gap-1">
              {notification.senderAvatar && (
                <img
                  src={notification.senderAvatar}
                  alt={notification.senderName}
                  className="w-4 h-4 rounded-full"
                />
              )}
              {notification.senderName}
            </span>
            <span>
              {formatDistanceToNow(new Date(notification.createdAt), { addSuffix: true })}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default function SystemNotificationBell() {
  const dispatch = useAppDispatch()
  const notifications = useAppSelector(selectSystemNotifications)
  const unreadCount = useAppSelector(selectUnreadCount)
  const isLoading = useAppSelector(selectIsLoading)
  const pagination = useAppSelector(selectPagination)
  
  const [isOpen, setIsOpen] = useState(false)

  // Initialize notifications on component mount
  useEffect(() => {
    dispatch(fetchUnreadCount())
    dispatch(fetchSystemNotifications({ limit: 20, offset: 0, refresh: true }))
  }, [dispatch])

  // Setup realtime listeners for notifications
  useEffect(() => {
    const realtimeManager = getRealtimeManager()
    
    const handleNotification = (payload: any) => {
      if (payload.event === 'dm_notification' && payload.payload) {
        const notificationPayload = payload.payload as SystemNotification
        dispatch(addRealtimeNotification(notificationPayload))
        
        // Show toast notification for high priority
        if (notificationPayload.priority >= 3) {
          toast({
            title: notificationPayload.title,
            description: notificationPayload.message
          })
        }
      }
    }
    
    // Subscribe to notification updates
    realtimeManager.updateHandlers({
      onNewMessageNotification: handleNotification
    })
    
    return () => {
      // Cleanup if needed
    }
  }, [dispatch])

  const handleMarkAsRead = async (notificationId: string) => {
    try {
      await dispatch(markNotificationsAsRead([notificationId])).unwrap()
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to mark notification as read',
        variant: 'destructive'
      })
    }
  }

  const handleMarkAllAsRead = async () => {
    try {
      await dispatch(markAllNotificationsAsRead()).unwrap()
      toast({
        title: 'Success',
        description: 'All notifications marked as read'
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to mark all notifications as read',
        variant: 'destructive'
      })
    }
  }

  const handleLoadMore = () => {
    if (!isLoading && pagination.hasMore) {
      dispatch(fetchSystemNotifications({ 
        limit: 20, 
        offset: pagination.offset,
        refresh: false 
      }))
    }
  }

  const handleNavigate = (url: string) => {
    window.location.href = url
    setIsOpen(false)
  }

  const unreadNotifications = notifications.filter((n: SystemNotification) => !n.isRead)

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className={cn(
            'relative',
            unreadCount > 0 && 'text-blue-600 hover:text-blue-700'
          )}
        >
          <NotificationIcon unreadCount={unreadCount} isOpen={isOpen} />
        </Button>
      </DropdownMenuTrigger>
      
      <DropdownMenuContent 
        align="end" 
        className="w-96 p-0 max-h-[500px]"
      >
        <div className="p-4 border-b">
          <div className="flex items-center justify-between">
            <DropdownMenuLabel className="p-0 text-base font-semibold">
              Notifications
            </DropdownMenuLabel>
            
            <div className="flex items-center gap-2">
              {unreadCount > 0 && (
                <Badge variant="secondary">
                  {unreadCount} unread
                </Badge>
              )}
              
              {unreadCount > 0 && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleMarkAllAsRead}
                  className="text-xs h-6 px-2"
                  disabled={isLoading}
                >
                  <CheckCircle className="w-3 h-3 mr-1" />
                  Mark all read
                </Button>
              )}
            </div>
          </div>
        </div>

        <ScrollArea className="max-h-[400px]">
          {notifications.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              <Bell className="w-12 h-12 mx-auto mb-4 text-gray-300" />
              <p className="text-sm">No notifications yet</p>
              <p className="text-xs text-gray-400 mt-1">
                You'll see updates about projects and tasks here
              </p>
            </div>
          ) : (
            <div>
              {/* Show unread notifications first */}
              {unreadNotifications.length > 0 && (
                <div>
                  <div className="px-4 py-2 text-xs font-medium text-gray-600 bg-gray-50 border-b">
                    Unread ({unreadNotifications.length})
                  </div>
                  {unreadNotifications.map((notification: SystemNotification) => (
                    <NotificationItem
                      key={notification.id}
                      notification={notification}
                      onMarkAsRead={handleMarkAsRead}
                      onNavigate={handleNavigate}
                    />
                  ))}
                </div>
              )}
              
              {/* Show read notifications */}
              {notifications.filter((n: SystemNotification) => n.isRead).length > 0 && (
                <div>
                  {unreadNotifications.length > 0 && (
                    <div className="px-4 py-2 text-xs font-medium text-gray-600 bg-gray-50 border-b">
                      Read
                    </div>
                  )}
                  {notifications
                    .filter((n: SystemNotification) => n.isRead)
                    .map((notification: SystemNotification) => (
                      <NotificationItem
                        key={notification.id}
                        notification={notification}
                        onMarkAsRead={handleMarkAsRead}
                        onNavigate={handleNavigate}
                      />
                    ))}
                </div>
              )}
              
              {/* Load more button */}
              {pagination.hasMore && (
                <div className="p-4 border-t">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleLoadMore}
                    disabled={isLoading}
                    className="w-full"
                  >
                    {isLoading ? 'Loading...' : 'Load more'}
                  </Button>
                </div>
              )}
            </div>
          )}
        </ScrollArea>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}