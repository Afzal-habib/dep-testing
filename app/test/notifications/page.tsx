'use client'

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useSystemNotifications } from '@/hooks/use-system-notifications'
import { toast } from '@/hooks/use-toast'
import { SystemNotification } from '@/store/slices/system-notifications-slice'

export default function SystemNotificationTest() {
  const [isLoading, setIsLoading] = useState(false)
  const [formData, setFormData] = useState({
    type: 'project_created',
    message: 'This is a test notification',
    targetUserId: ''
  })

  const { 
    notifications, 
    unreadCount, 
    isLoading: notificationsLoading,
    refresh,
    markAsRead 
  } = useSystemNotifications()

  const handleSendTest = async () => {
    setIsLoading(true)
    try {
      const response = await fetch('/api/system-notifications/test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      })

      if (!response.ok) {
        throw new Error('Failed to send test notification')
      }

      const data = await response.json()
      
      toast({
        title: 'Success',
        description: data.message,
      })

      // Refresh notifications
      refresh()

    } catch (error) {
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to send test notification',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">System Notifications Test</h1>
        <div className="flex items-center gap-4">
          <span className="text-sm text-muted-foreground">
            Unread: {unreadCount}
          </span>
          <Button onClick={refresh} variant="outline" size="sm">
            Refresh
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Test Form */}
        <Card>
          <CardHeader>
            <CardTitle>Send Test Notification</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="type">Notification Type</Label>
              <Select 
                value={formData.type} 
                onValueChange={(value) => setFormData({ ...formData, type: value })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="project_created">Project Created</SelectItem>
                  <SelectItem value="task_assigned">Task Assigned</SelectItem>
                  <SelectItem value="project_approved">Project Approved</SelectItem>
                  <SelectItem value="task_completed">Task Completed</SelectItem>
                  <SelectItem value="project_status_changed">Project Status Changed</SelectItem>
                  <SelectItem value="department_assigned">Department Assigned</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="message">Message</Label>
              <Textarea
                id="message"
                value={formData.message}
                onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                rows={3}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="targetUserId">Target User ID (leave empty for self)</Label>
              <Input
                id="targetUserId"
                value={formData.targetUserId}
                onChange={(e) => setFormData({ ...formData, targetUserId: e.target.value })}
                placeholder="Optional: User ID to send notification to"
              />
            </div>

            <Button 
              onClick={handleSendTest} 
              disabled={isLoading}
              className="w-full"
            >
              {isLoading ? 'Sending...' : 'Send Test Notification'}
            </Button>
          </CardContent>
        </Card>

        {/* Notifications List */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Notifications</CardTitle>
          </CardHeader>
          <CardContent>
            {notificationsLoading ? (
              <div className="text-center py-4">Loading...</div>
            ) : notifications.length === 0 ? (
              <div className="text-center py-4 text-muted-foreground">
                No notifications yet
              </div>
            ) : (
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {notifications.slice(0, 10).map((notification : SystemNotification) => (
                  <div
                    key={notification.id}
                    className={`p-3 rounded border ${
                      notification.isRead 
                        ? 'bg-muted/50' 
                        : 'bg-primary/5 border-primary/20'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h4 className="font-medium text-sm">
                          {notification.title}
                        </h4>
                        <p className="text-xs text-muted-foreground mt-1">
                          {notification.message}
                        </p>
                        <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                          <span>{notification.senderName}</span>
                          <span>•</span>
                          <span>{notification.type.replace('_', ' ')}</span>
                          <span>•</span>
                          <span>Priority: {notification.priority}</span>
                        </div>
                      </div>
                      {!notification.isRead && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => markAsRead([notification.id])}
                          className="text-xs h-6"
                        >
                          Mark Read
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}