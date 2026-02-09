"use client"

import { useState, useEffect, useMemo, memo, useCallback } from "react"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import {
  Search,
  MessageSquare,
  Users,
  UserCheck,
  Clock,
  Check,
  CheckCheck
} from "lucide-react"
import { cn } from "@/lib/utils"
import { useCommunications } from "@/hooks/use-communications"
import { useUsers } from "@/hooks/use-users"
import { useSession } from "next-auth/react"
import { User } from "@/types"
import { formatDistanceToNow } from "date-fns"
import { HtmlTextRenderer } from "@/components/shared/html-text-renderer"
import { communicationLogger as logger } from "@/lib/logger"
import { useToast } from "@/hooks/use-toast"

interface UserDirectoryProps {
  onStartDM?: (userId: string) => void
  onChannelSelect?: (channelId: string) => void
  className?: string
}

export const UserDirectory = memo(function UserDirectory({ onStartDM, onChannelSelect, className }: UserDirectoryProps) {
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [pinLoading, setPinLoading] = useState<string | null>(null)
  const { channels, createChannel, loading: channelLoading, selectChannel, onlineUserIds, pinUser, pinChannel } = useCommunications()
  const { users, loading: usersLoading } = useUsers()
  const { data: session } = useSession()
  const { toast } = useToast()
  
  const currentUserId = (session?.user as any)?.id

  // Derive pinned users from pinned DM channels (Feature 30: Pin Sync)
  // This ensures pin status is always in sync between user_directory and chat_lists
  const pinnedUsers = useMemo(() => {
    if (!currentUserId) return new Set<string>()
    
    const pinnedUserIds = new Set<string>()
    channels.forEach(channel => {
      if (channel.type === 'dm' && channel.is_pinned) {
        // Find the other user in this DM channel
        const otherMember = channel.channel_members.find(
          m => m.mongo_member_id !== currentUserId
        )
        if (otherMember) {
          pinnedUserIds.add(otherMember.mongo_member_id)
        }
      }
    })
    return pinnedUserIds
  }, [channels, currentUserId])

  // Filter active users (exclude current user)
  const activeUsers = useMemo(() => {
    return users.filter(user =>
      user._id.toString() !== currentUserId
      //  &&
      // user.isClient === false
    )
  }, [users, currentUserId]);
  
  // Get DM channel for a user (if exists)
  const getUserDMChannel = (user: User) => {
    if (!currentUserId) return null
    
    return channels.find(channel => {
      if (channel.type !== 'dm') return false
      const memberIds = channel.channel_members.map(m => m.mongo_member_id)
      return memberIds.includes(currentUserId) && memberIds.includes(user._id.toString())
    }) || null
  }
  
  const getUserUnreadCount = (user: User) => {
    const dmChannel = getUserDMChannel(user)
    return dmChannel ? (dmChannel.unreadCount || 0) : 0
  }
  
  // Get last message info for a user
  const getUserLastMessage = (user: User) => {
    const dmChannel = getUserDMChannel(user)
    if (!dmChannel?.last_message) return null
    
    const lastMsg = dmChannel.last_message
    const isFromMe = lastMsg.mongo_sender_id === currentUserId
    
    return {
      content: lastMsg.content,
      isFromMe,
      time: lastMsg.created_at,
      hasRead: false // TODO: Track if message is read
    }
  }
  
  // Sort users by recent message activity
  // Users with recent DM messages appear first
  const sortedUsers = useMemo(() => {
    if (!currentUserId) return activeUsers
    
    // Create a map of userId -> last_message_at from DM channels
    const userLastMessageMap = new Map<string, string>()
    
    channels.forEach(channel => {
      if (channel.type === 'dm' && channel.last_message_at) {
        // Find the other user in this DM
        const otherMember = channel.channel_members.find(
          m => m.mongo_member_id !== currentUserId
        )
        if (otherMember) {
          const existingTime = userLastMessageMap.get(otherMember.mongo_member_id)
          // Keep the most recent message time
          if (!existingTime || new Date(channel.last_message_at) > new Date(existingTime)) {
            userLastMessageMap.set(otherMember.mongo_member_id, channel.last_message_at)
          }
        }
      }
    })
    
    // Sort users: pinned first, then those with unread messages, then those with recent messages, then by online status, then alphabetically
    return [...activeUsers].sort((a, b) => {
      const aPinned = pinnedUsers.has(a._id.toString())
      const bPinned = pinnedUsers.has(b._id.toString())
      
      // Pinned users come first
      if (aPinned && !bPinned) return -1
      if (!aPinned && bPinned) return 1
      
      const aHasUnread = getUserUnreadCount(a) > 0
      const bHasUnread = getUserUnreadCount(b) > 0
      
      // Users with unread messages come next
      if (aHasUnread && !bHasUnread) return -1
      if (!aHasUnread && bHasUnread) return 1
      
      const aTime = userLastMessageMap.get(a._id.toString())
      const bTime = userLastMessageMap.get(b._id.toString())
      
      // Both have messages - sort by most recent
      if (aTime && bTime) {
        return new Date(bTime).getTime() - new Date(aTime).getTime()
      }
      
      // Only one has messages - that one goes first
      if (aTime && !bTime) return -1
      if (!aTime && bTime) return 1
      
      // Neither has messages - sort by online status, then name
      const aOnline = onlineUserIds.includes(a._id.toString())
      const bOnline = onlineUserIds.includes(b._id.toString())
      
      if (aOnline && !bOnline) return -1
      if (!aOnline && bOnline) return 1
      
      // Both same status - sort alphabetically
      return (a.name || a.email || '').localeCompare(b.name || b.email || '')
    })
  }, [activeUsers, channels, onlineUserIds, pinnedUsers, (session?.user as any)?.id])

  // Filter users based on search (using sorted users)
  const filteredUsers = useMemo(() => {
    return sortedUsers.filter(user => {
      if (!searchQuery) return true
      const query = searchQuery.toLowerCase()
      return (
        user.name?.toLowerCase().includes(query) ||
        user.email?.toLowerCase().includes(query) ||
        (typeof user.role === 'string' && user.role.toLowerCase().includes(query))
      )
    })
  }, [sortedUsers, searchQuery])

  const handleStartDM = async (user: User) => {
    if (!(session?.user as any)?.id) {
      logger.error('No current user found or user id missing')
      return
    }

    try {
      // Check if DM channel already exists
      const existingChannel = channels.find(channel => {
        if (channel.type !== 'dm') return false
        const memberIds = channel.channel_members.map(m => m.mongo_member_id)
        return memberIds.includes((session?.user as any)?.id) && memberIds.includes(user._id.toString())
      })

      if (existingChannel) {
        // Open existing channel
        selectChannel(existingChannel.id)
        if (onChannelSelect) {
          onChannelSelect(existingChannel.id)
        }
      } else {
        // Create new DM channel
        const channel = await createChannel({
          type: 'dm',
          channel_members: [(session?.user as any)?.id, user._id as string],
          is_private: true
        })

        if (channel && onChannelSelect) {
          // Select the new channel
          selectChannel(channel.id)
          onChannelSelect(channel.id)
        }
      }
    } catch (error) {
      logger.error('Failed to create DM:', error)
      toast({
        title: "Failed to start conversation",
        description: "Something went wrong. Please try again.",
        variant: "destructive"
      })
    }
  }

  // Get the DM channel for a user (for pin sync)
  const getUserDMChannelId = useCallback((userId: string): string | null => {
    if (!currentUserId) return null
    
    const dmChannel = channels.find(channel => {
      if (channel.type !== 'dm') return false
      const memberIds = channel.channel_members.map(m => m.mongo_member_id)
      return memberIds.includes(currentUserId) && memberIds.includes(userId)
    })
    
    return dmChannel?.id || null
  }, [channels, currentUserId])

  const handlePinToggle = async (userId: string) => {
    const isPinned = pinnedUsers.has(userId)
    const channelId = getUserDMChannelId(userId)
    
    // If no DM channel exists, we need to create one first or use the old API
    if (!channelId) {
      // Use the legacy pinUser API for users without DM channels
      setPinLoading(userId)
      try {
        await pinUser(userId, isPinned)
      } catch (error) {
        logger.error('Failed to toggle pin:', error)
        toast({
          title: "Failed to pin user",
          description: "Something went wrong. Please try again.",
          variant: "destructive"
        })
      } finally {
        setPinLoading(null)
      }
      return
    }
    
    // Pin/unpin the DM channel - this syncs with channel list
    setPinLoading(userId)
    try {
      await pinChannel(channelId, isPinned)
      // The channel update will propagate through Redux and update pinnedUsers via useMemo
    } catch (error) {
      logger.error('Failed to toggle pin:', error)
      toast({
        title: "Failed to pin channel",
        description: "Something went wrong. Please try again.",
        variant: "destructive"
      })
    } finally {
      setPinLoading(null)
    }
  }

  const getUserStatus = (user: User) => {
    // Use real-time onlineUserIds from Supabase presence
    return onlineUserIds.includes(user._id.toString()) ? 'online' : 'offline'
  }

  const getRoleColor = (role?: string | any) => {
    const roleStr = typeof role === 'string' ? role : 'user'
    switch (roleStr?.toLowerCase()) {
      case 'admin':
        return 'bg-red-100 text-red-800'
      case 'manager':
        return 'bg-blue-100 text-blue-800'
      case 'employee':
        return 'bg-green-100 text-green-800'
      case 'client':
        return 'bg-yellow-100 text-yellow-800'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <div className={cn("flex flex-col h-full", className)}>
      {/* Header */}
      <div className="p-4 border-b">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search users..."   
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      {/* User List */}
      <div className="flex-1 overflow-auto">
        <div className="p-2">
          {filteredUsers.length === 0 ? (
            <div className="text-center py-8">
              <Users className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">
                {searchQuery ? 'No users found matching your search.' : 'No active users available.'}
              </p>
            </div>
          ) : (
            <div className="space-y-1 pb-4">
            {/* <div className="space-y-1"> */}
              {filteredUsers.map((user) => {
                const isPinned = pinnedUsers.has(user._id.toString())
                const unreadCount = getUserUnreadCount(user)
                const hasUnread = unreadCount > 0
                const isPinLoading = pinLoading === user._id.toString()
                const lastMessage = getUserLastMessage(user)
                
                return (
                  <div
                    key={user._id as string}
                    className={cn(
                      "flex items-center gap-3 py-2.5 px-2 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer group",
                      hasUnread && "bg-accent/30"
                    )}
                    onClick={() => !channelLoading && handleStartDM(user)}
                  >
                    {/* Avatar */}
                    <div className="relative shrink-0">
                      <Avatar className={cn(
                        "h-11 w-11",
                        // WhatsApp-style green ring for online users
                        getUserStatus(user) === 'online' && "ring-2 ring-emerald-500 ring-offset-2 ring-offset-background"
                      )}>
                        <AvatarImage src={user.avatar} alt={user.name || user.email} />
                        <AvatarFallback className="bg-gradient-to-br from-primary/20 to-accent/40 text-primary font-semibold">
                          {user.name
                            ? (() => {
                              const parts = user.name.trim().split(' ');
                              if (parts.length === 1) {
                                return parts[0][0].toUpperCase();
                              }
                              return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                            })()
                            : user.email?.[0]?.toUpperCase() || 'U'}
                        </AvatarFallback>
                      </Avatar>
                      {/* Online indicator dot */}
                      <div className={cn(
                        "absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full border-2 border-background",
                        getUserStatus(user) === 'online' ? 'bg-emerald-500 animate-pulse shadow-sm' : 'bg-gray-400'
                      )} />
                    </div>

                    {/* User Info with Last Message */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <p className={cn(
                          "font-medium text-sm truncate",
                          hasUnread && "font-semibold"
                        )}>
                          {user.name || user.email}
                        </p>
                        {/* Time of last message */}
                        {lastMessage && (
                          <span className={cn(
                            "text-[10px] font-medium shrink-0",
                            hasUnread ? "text-primary" : "text-muted-foreground"
                          )}>
                            {formatDistanceToNow(new Date(lastMessage.time), { addSuffix: false })}
                          </span>
                        )}
                      </div>
                      
                      {/* Last message preview */}
                      <div className="flex items-center justify-between gap-2 mt-0.5">
                        <div className="flex items-center gap-1 flex-1 min-w-0">
                          {/* Read status for sent messages */}
                          {lastMessage?.isFromMe && (
                            <CheckCheck className={cn(
                              "h-3.5 w-3.5 shrink-0",
                              lastMessage.hasRead ? "text-blue-500" : "text-muted-foreground"
                            )} />
                          )}
                          {lastMessage ? (
                            <HtmlTextRenderer
                              content={lastMessage.content}
                              fallbackText=""
                              showFallback={false}
                              renderAsHtml={true}
                              className={cn(
                                "line-clamp-1 text-xs",
                                hasUnread ? "text-foreground font-medium" : "text-muted-foreground"
                              )}
                              truncateHtml={true}
                            />
                          ) : (
                            <span className="text-xs text-muted-foreground/60">
                              Start a conversation
                            </span>
                          )}
                        </div>
                        
                        {/* Unread badge */}
                        {hasUnread && (
                          <Badge
                            variant="default"
                            className="ml-1 h-5 min-w-[20px] px-1.5 flex items-center justify-center text-[10px] font-bold bg-gradient-to-r from-primary to-primary/90 text-primary-foreground shadow-sm"
                          >
                            {unreadCount > 99 ? '99+' : unreadCount}
                          </Badge>
                        )}
                      </div>
                    </div>

                    {/* Pin Button */}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="opacity-0 group-hover:opacity-100 transition-opacity h-8 w-8 p-0 shrink-0"
                      onClick={(e) => {
                        e.stopPropagation()
                        handlePinToggle(user._id.toString())
                      }}
                      disabled={isPinLoading}
                    >
                      <UserCheck className={cn(
                        "h-4 w-4",
                        isPinned ? "text-yellow-500 fill-yellow-500" : "text-muted-foreground"
                      )} />
                    </Button>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 border-t bg-muted/30">
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>{filteredUsers.length} user{filteredUsers.length !== 1 ? 's' : ''}</span>
        </div>
      </div>
    </div>
  )
})