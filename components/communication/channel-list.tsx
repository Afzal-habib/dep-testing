"use client"

import { useState, memo, useCallback } from "react"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import {
  Search,
  Hash,
  MessageSquare,
  Users,
  Phone,
  Plus,
  Settings,
  Filter,
  Archive,
  Pin,
  PinOff,
  CheckCheck,
  BellOff
} from "lucide-react"
import { cn } from "@/lib/utils"
import { IChannel, IParticipant } from "@/types/communication"
import { formatDistanceToNow } from "date-fns"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import HtmlTextRenderer from "../shared/html-text-renderer"
import { useToast } from "@/hooks/use-toast"

interface ChannelListProps {
  channels: IChannel[]
  activeChannelId?: string | null
  onChannelSelect: (channelId: string) => void
  currentUserId: string
  onlineUserIds?: string[] // Real-time online user IDs from Supabase
  showSearch?: boolean
  showHeader?: boolean
  onCreateChannel?: () => void
  onPinChannel?: (channelId: string, isPinned: boolean) => Promise<void>
  className?: string
}

export const ChannelList = memo(function ChannelList({
  channels,
  activeChannelId,
  onChannelSelect,
  currentUserId,
  onlineUserIds = [],
  showSearch = true,
  showHeader = true,
  onCreateChannel,
  onPinChannel,
  className
}: ChannelListProps) {
  const [searchQuery, setSearchQuery] = useState("")
  const [pinLoading, setPinLoading] = useState<string | null>(null)
  const { toast } = useToast()

  const getChannelIcon = (channel: IChannel) => {
    switch (channel.type) {
      case 'dm':
        return <MessageSquare className="h-4 w-4" />
      case 'project':
        return <Hash className="h-4 w-4" />
      case 'client-support':
        return <Phone className="h-4 w-4" />
      case 'group':
        return <Users className="h-4 w-4" />
      default:
        return <MessageSquare className="h-4 w-4" />
    }
  }

  const getChannelDisplayName = (channel: IChannel) => {
    if (channel.type === 'dm') {
      // For DM, show the other participant's name
      const otherParticipant = channel.channel_members.find(p => p.mongo_member_id !== currentUserId)
      return otherParticipant?.name || 'Unknown User'
    }
    return channel.name || 'Unnamed Channel'
  }

  const getChannelSubtitle = (channel: IChannel) => {
    if (channel.type === 'dm') {
      const otherParticipant = channel.channel_members.find(p => p.mongo_member_id !== currentUserId)
      return otherParticipant?.userRole || otherParticipant?.userType || ''
    }

    if (channel.type === 'project') {
      return `${channel.channel_members.length} members`
    }

    if (channel.type === 'client-support') {
      return 'Client Support'
    }

    return `${channel.channel_members.length} members`
  }

  const getChannelAvatar = (channel: IChannel): IParticipant | null => {
    if (channel.type === 'dm') {
      return channel.channel_members.find(p => p.mongo_member_id !== currentUserId) as IParticipant || null
    }
    return null
  }

  const formatLastMessageTime = (date: string) => {
    return formatDistanceToNow(new Date(date), { addSuffix: true })
  }

  const filteredChannels = channels.filter(channel => {
    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      const channelName = getChannelDisplayName(channel).toLowerCase()
      const matchesName = channelName.includes(query)
      const matchesChannelMembers = channel.channel_members.some(p =>
        p.name.toLowerCase().includes(query)
      )
      const matchesLastMessage = channel.last_message?.content.toLowerCase().includes(query)

      if (!matchesName && !matchesChannelMembers && !matchesLastMessage) {
        return false
      }
    }

    return true
  })

  // Separate pinned and unpinned channels, then sort each group
  const pinnedChannels = filteredChannels.filter((ch: any) => ch.is_pinned)
  const unpinnedChannels = filteredChannels.filter((ch: any) => !ch.is_pinned)

  // Handle pin toggle
  const handlePinToggle = useCallback(async (e: React.MouseEvent, channel: IChannel) => {
    e.stopPropagation()
    if (!onPinChannel) return

    const isPinned = (channel as any).is_pinned || false
    setPinLoading(channel.id)

    try {
      await onPinChannel(channel.id, isPinned)
    } catch (error: any) {
      toast({
        title: "Failed to update pin",
        description: error.message || "Something went wrong",
        variant: "destructive"
      })
    } finally {
      setPinLoading(null)
    }
  }, [onPinChannel, toast])

  const ChannelItem = ({ channel }: { channel: IChannel }) => {
    const isActive = channel.id === activeChannelId
    const avatar = getChannelAvatar(channel)
    const displayName = getChannelDisplayName(channel)
    const subtitle = getChannelSubtitle(channel)
    const hasUnread = (channel.unreadCount || 0) > 0
    const isArchived = (channel as any).is_archived || false
    const isPinned = (channel as any).is_pinned || false
    const isPinLoading = pinLoading === channel.id

    // Check if notifications are muted for this channel (per-user setting)
    const currentMember = channel.channel_members.find(m => m.mongo_member_id === currentUserId)
    const isMuted = currentMember?.notifications_enabled === false

    // Check if user is online using real-time onlineUserIds from Supabase
    const isAvatarUserOnline = avatar ? (
      onlineUserIds.length > 0
        ? onlineUserIds.includes(avatar.mongo_member_id)
        : avatar.isOnline
    ) : false

    return (
      <div
        onClick={() => onChannelSelect(channel.id)}
        className={cn(
          "flex items-center gap-2.5 p-2 cursor-pointer transition-all duration-200 rounded-lg group relative",
          "hover:bg-primary/90 hover:shadow-sm hover:scale-[1.005] hover:text-white",
          "border border-transparent hover:border-accent/50",
          isActive && "bg-primary/10 shadow-sm border-primary/30",
          hasUnread && "bg-accent/20 border-accent/30",
          isArchived && "opacity-60 bg-muted/30",
          isPinned && "border-primary/20"
        )}
      >

        {/* {onPinChannel && (
          <Button
            variant="ghost"
            size="icon"
            className={cn(
              "absolute top-1 right-1 h-6 w-6 opacity-0 group-hover:opacity-100 transition-all",
              "hover:bg-white hover:text-primary",
              "group/button",
              isPinned && "opacity-100"
            )}
            onClick={(e) => handlePinToggle(e, channel)}
            disabled={isPinLoading}
          >
            {isPinLoading ? (
              <div className="h-3 w-3 animate-spin rounded-full border-2 border-primary border-t-transparent group-hover:border-white group-hover/button:border-primary" />
            ) : isPinned ? (
              <>
                <Pin
                  className={cn(
                    "h-3 w-3 text-white transition-opacity group-hover:opacity-0",
                    "group-hover/button:text-primary"
                  )}
                />
                <PinOff
                  className={cn(
                    "absolute inset-0 h-3 w-3 text-white opacity-0 group-hover:opacity-100 transition-opacity",
                    "group-hover/button:text-primary"
                  )}
                />
              </>
            ) : (
              <Pin
                className={cn(
                  "h-3 w-3 text-white opacity-0 group-hover:opacity-100 transition-opacity",
                  "group-hover/button:text-primary"
                )}
              />
            )}
          </Button>
        )} */}

        {/* Avatar or Icon */}
        <div className="relative shrink-0">
          {avatar ? (
            <>
              <Avatar className={cn(
                "h-7 w-7 transition-all duration-200 group-hover:scale-105 shadow-sm",
                // WhatsApp-style green ring for online users
                isAvatarUserOnline && "ring-2 ring-green-500 dark:ring-green-400 ring-offset-1 ring-offset-background"
              )}>
                <AvatarImage src={avatar.avatar} alt={avatar.name} />
                <AvatarFallback className="bg-gradient-to-br from-primary/20 to-accent/40 text-primary font-semibold group-hover:text-white group-hover:bg-gradient-to-br group-hover:from-white/30 group-hover:to-white/20">
                  {avatar.name ? (() => {
                    const parts = avatar.name.trim().split(' ');
                    if (parts.length === 1) {
                      return parts[0][0].toUpperCase();
                    }
                    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                  })()
                    : ''}
                </AvatarFallback>
              </Avatar>
              {/* Online indicator dot */}
              {isAvatarUserOnline && (
                <div className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-green-500 dark:bg-green-400 border-2 border-background animate-pulse shadow-sm transition-transform group-hover:scale-110" />
              )}
            </>
          ) : (
            <div className="h-9 w-9 rounded-full bg-gradient-to-br from-muted to-accent/30 flex items-center justify-center transition-all duration-200 group-hover:scale-105 group-hover:shadow-sm group-hover:from-white/30 group-hover:to-white/20 group-hover:text-white">
              {getChannelIcon(channel)}
            </div>
          )}
        </div>

        {/* Channel info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-1.5">
            <h3 className={cn(
              "font-semibold text-[13px] truncate transition-all group-hover:text-white group-hover:scale-[1.02]",
              hasUnread && "font-bold text-foreground",
              isActive && "text-primary"
            )}>
              {displayName}
            </h3>

            {channel.last_message && (
              <span className={cn(
                "text-[9px] font-medium shrink-0 transition-all group-hover:text-white group-hover:scale-105",
                hasUnread ? "text-primary" : "text-muted-foreground"
              )}>
                {formatLastMessageTime(channel.last_message.created_at)}
              </span>
            )}
          </div>

          <div className="flex items-center justify-between gap-1.5">
            {/* Subtitle or last message */}
            <div className="flex-1 min-w-0">
              {channel.last_message ? (
                <HtmlTextRenderer
                  content={channel.last_message.content}
                  fallbackText="No description"
                  showFallback={true}
                  renderAsHtml={true}
                  className="line-clamp-1 text-[11px]"
                  truncateHtml={true}
                />
              ) : (
                <p className="text-[11px] text-muted-foreground/60 font-medium group-hover:text-white transition-all group-hover:scale-[1.02]">
                  {subtitle}
                </p>
              )}
            </div>

            {/* Unread count */}
            {hasUnread && (
              <Badge
                variant="default"
                className="ml-1.5 h-4 min-w-[18px] px-1 flex items-center justify-center text-[9px] font-bold bg-gradient-to-r from-primary to-primary/90 text-primary-foreground shadow-sm transition-all group-hover:scale-110 group-hover:bg-white group-hover:text-accent group-hover:border-white"
              >
                {(channel.unreadCount || 0) > 99 ? '99+' : (channel.unreadCount || 0)}
              </Badge>
            )}
          </div>

          {/* Channel type indicator */}
          <div className="flex items-center gap-0.5 mt-0.5">
            {isArchived && (
              <Badge variant="secondary" className="text-[9px] h-3.5 gap-0.5 px-1 py-0 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400 group-hover:bg-white/20 group-hover:text-white group-hover:border-white/40 transition-all group-hover:scale-105">
                <Archive className="h-2 w-2" />
                Archived
              </Badge>
            )}

            {!channel.is_private && !isArchived && (
              <Badge variant="secondary" className="text-[10px] h-4 px-1.5 py-0 rounded-full group-hover:bg-white/20 group-hover:text-white group-hover:border-white/40 transition-all group-hover:scale-105">
                External
              </Badge>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className={cn("flex flex-col h-full w-full max-w-full bg-gradient-to-b from-card to-card/95 border-r border-border/50 shadow-sm overflow-hidden", className)}>
      {/* Header */}
      {showHeader && (
        <div className="p-3 pr-4 border-b border-border/30 bg-gradient-to-r from-background via-accent/5 to-primary/5 shadow-sm">
          {/* Search */}
          {showSearch && (
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground transition-colors" />
              <Input
                placeholder="Search conversations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 transition-all duration-200 focus:ring-2 focus:ring-primary/20 hover:border-primary/30"
              />
            </div>
          )}
        </div>
      )}

      {/* Channel list */}
      <div className="flex-1 w-full max-w-full overflow-auto">
        <div className="p-2 space-y-1 w-full max-w-full">
          {filteredChannels.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <MessageSquare className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No conversations found</p>
              {searchQuery && (
                <Button
                  variant="link"
                  size="sm"
                  onClick={() => setSearchQuery('')}
                  className="mt-2"
                >
                  Clear search
                </Button>
              )}
            </div>
          ) : (
            <>
              {/* Pinned Channels Section */}
              {pinnedChannels.length > 0 && (
                <>
                  <div className="py-2 px-2">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground font-medium">
                      <Pin className="h-3 w-3" />
                      <span>Pinned ({pinnedChannels.length}/5)</span>
                    </div>
                  </div>
                  {pinnedChannels.map((channel) => (
                    <ChannelItem key={channel.id} channel={channel} />
                  ))}
                  {/* Separator after pinned */}
                  <div className="py-2 px-2">
                    <div className="h-px bg-gradient-to-r from-transparent via-border to-transparent" />
                  </div>
                </>
              )}

              {/* Unpinned Channels - DM and Other */}
              {(() => {
                const dmChannels = unpinnedChannels.filter(channel => channel.type === 'dm')
                const otherChannels = unpinnedChannels.filter(channel => channel.type !== 'dm')

                return (
                  <>
                    {/* DM Unread */}
                    {dmChannels
                      .filter(channel => (channel.unreadCount || 0) > 0)
                      .map((channel) => (
                        <ChannelItem key={channel.id} channel={channel} />
                      ))
                    }

                    {/* DM Read */}
                    {dmChannels
                      .filter(channel => (channel.unreadCount || 0) === 0)
                      .map((channel) => (
                        <ChannelItem key={channel.id} channel={channel} />
                      ))
                    }

                    {/* Separator between DM and other channels */}
                    {dmChannels.length > 0 && otherChannels.length > 0 && (
                      <div className="py-2 px-2">
                        <div className="h-px bg-gradient-to-r from-transparent via-border to-transparent opacity-50" />
                      </div>
                    )}

                    {/* Other Channels Unread */}
                    {otherChannels
                      .filter(channel => (channel.unreadCount || 0) > 0)
                      .map((channel) => (
                        <ChannelItem key={channel.id} channel={channel} />
                      ))
                    }

                    {/* Other Channels Read */}
                    {otherChannels
                      .filter(channel => (channel.unreadCount || 0) === 0)
                      .map((channel) => (
                        <ChannelItem key={channel.id} channel={channel} />
                      ))
                    }
                  </>
                )
              })()}
            </>
          )}
        </div>
      </div>
    </div>
  )
})
