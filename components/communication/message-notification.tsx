"use client"

import { useState, memo, useCallback, useMemo } from "react"
import { useRouter } from "next/navigation"
import { useSession } from "next-auth/react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import {
  Bell,
  MessageSquare,
  X
} from "lucide-react"
import { cn } from "@/lib/utils"
import { useCommunications } from "@/hooks/use-communications"
import { formatDistanceToNow } from "date-fns"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"


interface MessageNotificationProps {
  className?: string
  showBadge?: boolean
}

export const MessageNotification = memo(function MessageNotification({
  className,
  showBadge = true
}: MessageNotificationProps) {
  const [isOpen, setIsOpen] = useState(false)
  const router = useRouter()
  const { data: session } = useSession()
  const currentUserId = (session?.user as any)?.id

  const {
    channels,
    unreadCount,
    notifications,
    selectChannel
  } = useCommunications()

  // Get channels with unread messages (exclude channels where the last message is from self)
  const unreadChannels = channels.filter(channel => {
    const hasUnread = (channel.unreadCount || 0) > 0
    // Also filter out channels where the last message is from current user
    const lastMessageFromSelf = channel.last_message?.mongo_sender_id === currentUserId
    return hasUnread && !lastMessageFromSelf
  })

  // Navigate to the channel and mark messages as read
  const handleNotificationClick = useCallback((channelId: string, messageId?: string) => {
    // Select the channel first
    selectChannel(channelId)
    
    // Navigate to communications page with the channel
    router.push(`/communications?channel=${channelId}`)
    
    // Mark message as read if provided (this happens via selectChannel which calls markAllChannelMessagesAsRead)
    // Notifications are cleared by selectChannel -> clearNotificationsForChannel
    
    setIsOpen(false)
  }, [selectChannel, router])

  // Get user info from notification message data
  const getUserInfo = useCallback((notification: any) => {
    // For new message notifications, use the message's sender data
    if (notification.message) {
      return {
        name: notification.message.sender_name || notification.message.sender?.name || notification.title || 'Unknown User',
        avatar: notification.message.sender_avatar || notification.message.sender?.avatar || undefined
      }
    }
    // For mention notifications, use the title
    return { 
      name: notification.title?.replace('Mention from ', '')?.replace(' mentioned you', '') || 'System', 
      avatar: undefined 
    }
  }, [])

  // Get display name for a channel
  const getChannelDisplayName = useCallback((channel: any) => {
    if (channel.type === 'dm') {
      const otherParticipant = channel.channel_members?.find((p: any) => p.mongo_member_id !== currentUserId)
      return otherParticipant?.name || 'Unknown User'
    }
    return channel.name || 'Channel'
  }, [currentUserId])

  // Strip HTML tags from message content for preview
  const stripHtml = useCallback((html: string) => {
    if (!html) return ''
    return html
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .replace(/&nbsp;/g, ' ') // Replace &nbsp; with space
      .replace(/&amp;/g, '&') // Replace &amp; with &
      .replace(/&lt;/g, '<') // Replace &lt; with <
      .replace(/&gt;/g, '>') // Replace &gt; with >
      .replace(/&quot;/g, '"') // Replace &quot; with "
      .replace(/\s+/g, ' ') // Collapse multiple spaces
      .trim()
  }, [])

  // Filter out notifications from self (should already be filtered on server, but double-check)
  const filteredNotifications = notifications.filter(n => {
    const senderId = n.message?.mongo_sender_id
    return senderId !== currentUserId
  })

  // Group notifications by channel for a cleaner view
  const groupedNotifications = useMemo(() => {
    const groups: Record<string, {
      channelId: string;
      channelName: string;
      channelType: string;
      messages: typeof filteredNotifications;
      latestTimestamp: Date;
      totalCount: number;
      avatar?: string;
    }> = {}

    filteredNotifications.forEach(notification => {
      const channelId = notification.channelId
      if (!channelId) return

      const channel = channels.find(c => c.id === channelId)
      const channelName = channel ? getChannelDisplayName(channel) : 'Unknown Channel'
      const channelType = channel?.type || 'group'

      if (!groups[channelId]) {
        // Get avatar for DM channels
        let avatar: string | undefined
        if (channel?.type === 'dm') {
          const otherMember = channel.channel_members?.find((p: any) => p.mongo_member_id !== currentUserId)
          avatar = otherMember?.avatar
        }

        groups[channelId] = {
          channelId,
          channelName,
          channelType,
          messages: [],
          latestTimestamp: new Date(notification.timestamp),
          totalCount: 0,
          avatar
        }
      }

      groups[channelId].messages.push(notification)
      groups[channelId].totalCount++
      
      const notifTime = new Date(notification.timestamp)
      if (notifTime > groups[channelId].latestTimestamp) {
        groups[channelId].latestTimestamp = notifTime
      }
    })

    // Sort by latest timestamp (newest first)
    return Object.values(groups).sort((a, b) => 
      b.latestTimestamp.getTime() - a.latestTimestamp.getTime()
    )
  }, [filteredNotifications, channels, getChannelDisplayName, currentUserId])

  // Merge grouped notifications with unread channels (avoid duplicates)
  const consolidatedNotifications = useMemo(() => {
    const notificationChannelIds = new Set(groupedNotifications.map(g => g.channelId))
    
    // Get unread channels that don't already have notifications
    const additionalUnreadChannels = unreadChannels.filter(
      channel => !notificationChannelIds.has(channel.id)
    )

    return {
      grouped: groupedNotifications,
      additional: additionalUnreadChannels
    }
  }, [groupedNotifications, unreadChannels])

  const hasNotifications = consolidatedNotifications.grouped.length > 0 || consolidatedNotifications.additional.length > 0

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className={cn("relative", className)}
        >
          <Bell className="h-4 w-4" />

          {showBadge && unreadCount > 0 && (
            <Badge
              variant="destructive"
              className="absolute -top-1 -right-1 h-5 min-w-[20px] flex items-center justify-center text-xs px-1"
            >
              {unreadCount > 99 ? '99+' : unreadCount}
            </Badge>
          )}
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent className="w-80 p-0" align="end">
        <div className="flex items-center justify-between p-4 border-b">
          <h4 className="font-semibold">Message Notifications</h4>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsOpen(false)}
            className="h-7 w-7 p-0"
          >
            <X className="h-3 w-3" />
          </Button>
        </div>

        <div className="max-h-96 overflow-auto">
          {!hasNotifications ? (
            <div className="p-8 text-center text-muted-foreground">
              <Bell className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No new messages</p>
            </div>
          ) : (
            <div className="space-y-1 p-2">
              {/* Grouped notifications by channel */}
              {consolidatedNotifications.grouped.map((group) => {
                const latestMessage = group.messages[0]?.message
                const latestSender = getUserInfo(group.messages[0])
                const rawContent = latestMessage?.content || group.messages[0]?.preview || ''
                const previewContent = stripHtml(rawContent)

                return (
                  <div
                    key={group.channelId}
                    onClick={() => handleNotificationClick(group.channelId)}
                    className="flex items-start gap-3 p-3 rounded-lg hover:bg-muted cursor-pointer transition-colors"
                  >
                    {group.channelType === 'dm' ? (
                      <Avatar className="h-10 w-10 mt-0.5">
                        <AvatarImage src={group.avatar} alt={group.channelName} />
                        <AvatarFallback className="text-xs bg-primary/10">
                          {group.channelName
                            ? (() => {
                              const parts = group.channelName.trim().split(' ');
                              if (parts.length === 1) {
                                return parts[0][0]?.toUpperCase() || '';
                              }
                              return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                            })()
                            : ''}
                        </AvatarFallback>
                      </Avatar>
                    ) : (
                      <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center mt-0.5">
                        <MessageSquare className="h-5 w-5 text-primary" />
                      </div>
                    )}

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium text-sm truncate">{group.channelName}</span>
                        <Badge variant="destructive" className="text-xs ml-2 shrink-0">
                          {group.totalCount}
                        </Badge>
                      </div>

                      <p className="text-sm text-muted-foreground line-clamp-1">
                        {group.channelType !== 'dm' && latestSender.name && `${latestSender.name}: `}
                        {previewContent}
                      </p>

                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs text-muted-foreground">
                          {formatDistanceToNow(group.latestTimestamp, { addSuffix: true })}
                        </span>
                        {group.channelType !== 'dm' && (
                          <Badge variant="outline" className="text-xs">
                            {group.channelType.replace('-', ' ')}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}

              {/* Additional channels with unread messages (not in notifications) */}
              {consolidatedNotifications.additional.map((channel) => {
                const displayName = getChannelDisplayName(channel)
                const last_message = channel.last_message
                const senderName = last_message?.sender_name || last_message?.sender?.name || ''

                return (
                  <div
                    key={channel.id}
                    onClick={() => handleNotificationClick(channel.id)}
                    className="flex items-start gap-3 p-3 rounded-lg hover:bg-muted cursor-pointer transition-colors"
                  >
                    {channel.type === 'dm' && channel.channel_members?.length > 0 ? (
                      <Avatar className="h-10 w-10 mt-0.5">
                        <AvatarImage
                          src={channel.channel_members.find((p: any) => p.mongo_member_id !== currentUserId)?.avatar}
                          alt={displayName}
                        />
                        <AvatarFallback className="text-xs bg-primary/10">
                          {displayName
                            ? (() => {
                              const parts = displayName.trim().split(' ');
                              if (parts.length === 1) {
                                return parts[0][0]?.toUpperCase() || '';
                              }
                              return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                            })()
                            : ''}
                        </AvatarFallback>
                      </Avatar>
                    ) : (
                      <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center mt-0.5">
                        <MessageSquare className="h-5 w-5 text-primary" />
                      </div>
                    )}

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium text-sm truncate">{displayName}</span>
                        <Badge variant="destructive" className="text-xs ml-2 shrink-0">
                          {channel.unreadCount || 0}
                        </Badge>
                      </div>

                      {last_message && (
                        <p className="text-sm text-muted-foreground line-clamp-1">
                          {senderName && channel.type !== 'dm' && `${senderName}: `}
                          {stripHtml(last_message.content)}
                        </p>
                      )}

                      <div className="flex items-center gap-2 mt-1">
                        {last_message && (
                          <span className="text-xs text-muted-foreground">
                            {formatDistanceToNow(new Date(last_message.created_at), { addSuffix: true })}
                          </span>
                        )}
                        {channel.type !== 'dm' && (
                          <Badge variant="outline" className="text-xs">
                            {channel.type.replace('-', ' ')}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {hasNotifications && (
          <div className="border-t p-3">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                router.push('/communications')
                setIsOpen(false)
              }}
              className="w-full"
            >
              <MessageSquare className="h-3 w-3 mr-1" />
              View All Messages
            </Button>
          </div>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
})