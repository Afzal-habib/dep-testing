"use client"

import { useState, useCallback, memo, useMemo } from "react"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Badge } from "@/components/ui/badge"
import {
  MessageSquare,
  Users,
  Hash,
  ChevronDown,
  ChevronRight,
  Trash2,
  FileText,
  Filter,
  Phone
} from "lucide-react"
import { cn } from "@/lib/utils"
import { UserDirectory } from "./user-directory"
import { IChannel } from "@/types/communication"
import { ChannelList } from "./channel-list"
import { TrashView } from "./trash-view"
import { AuditLogView } from "./audit-log-view"

interface CommunicationSidebarProps {
  channels: IChannel[]
  activeChannelId?: string | null
  currentUserId: string
  onlineUserIds?: string[] // Real-time online user IDs from Supabase
  onChannelSelect: (channelId: string) => void
  onCreateChannel?: () => void
  onPinChannel?: (channelId: string, isPinned: boolean) => Promise<void>
  loading?: boolean
  className?: string
}

export const CommunicationSidebar = memo(function CommunicationSidebar({
  channels,
  activeChannelId,
  currentUserId,
  onlineUserIds = [],
  onChannelSelect,
  onCreateChannel,
  onPinChannel,
  loading = false,
  className
}: CommunicationSidebarProps) {
  const [showUsers, setShowUsers] = useState(true)
  const [showChannels, setShowChannels] = useState(true)
  const [showTrash, setShowTrash] = useState(false)
  const [showAuditLog, setShowAuditLog] = useState(false)
  const [filterType, setFilterType] = useState<'all' | 'dm' | 'project' | 'client-support'>('all')

  const handleStartDM = useCallback(async (userId: string) => {
    // This will be handled by the parent component
    // The UserDirectory component will handle the DM creation
  }, [])

  // Determine if active channel is a DM or regular channel
  const activeChannel = channels.find(c => c.id === activeChannelId)
  const isActiveChannelDM = activeChannel?.type === 'dm'
  const isActiveChannelRegular = activeChannel && activeChannel.type !== 'dm'

  const content = useMemo(() => (
    loading ? (
      <div className="p-5 space-y-5">
        <div className="flex items-center justify-between mb-4">
          <Skeleton className="h-7 w-32 rounded-lg" />
          <Skeleton className="h-9 w-9 rounded-lg" />
        </div>
        <Skeleton className="h-11 w-full rounded-xl" />
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex gap-3 p-3 rounded-xl bg-muted/30 animate-in fade-in duration-300" style={{ animationDelay: `${i * 50}ms` }}>
            <Skeleton className="h-12 w-12 rounded-full shrink-0" />
            <div className="space-y-2.5 flex-1">
              <Skeleton className="h-4 w-3/4 rounded-md" />
              <Skeleton className="h-3 w-1/2 rounded-md" />
            </div>
          </div>
        ))}
      </div>
    ) : (
      <div className="pt-3 pr-0 pl-0 space-y-3">
        {/* Channels Section */}
        <div>
          <div className="px-3">
            <Button
              variant="ghost"
              className={cn(
                "w-full justify-start p-3 h-auto font-bold text-sm hover:bg-primary hover:text-primary-foreground transition-all duration-200 rounded-xl shadow-sm",
                isActiveChannelRegular && "bg-primary text-white shadow-md"
              )}
              onClick={() => setShowChannels(!showChannels)}
            >
              {showChannels ? (
                <ChevronDown className="h-4 w-4 mr-2 transition-transform" />
              ) : (
                <ChevronRight className="h-4 w-4 mr-2 transition-transform" />
              )}
              <Hash className="h-4 w-4 mr-2" />
              Channels
              <span className="ml-auto text-xs opacity-70 font-semibold bg-white/10 px-2 py-0.5 rounded-full">({channels.filter(c => c.type !== 'dm').length})</span>
            </Button>
          </div>

          {showChannels && (
            <div className="mt-2">
              <ChannelList
                channels={channels.filter(c => {
                  if (c.type === 'dm') return false
                  if (filterType === 'all') return true
                  return c.type === filterType
                })}
                activeChannelId={activeChannelId}
                onChannelSelect={onChannelSelect}
                currentUserId={currentUserId}
                onlineUserIds={onlineUserIds}
                onPinChannel={onPinChannel}
                showSearch={false}
                showHeader={false}
                className="border-0 shadow-none"
              />
            </div>
          )}
        </div>

        <Separator className="my-3" />
        {/* Direct Messages Section */}
        <div>
          <div className="px-3">
            <Button
              variant="ghost"
              className={cn(
                "w-full justify-start p-3 h-auto font-bold text-sm hover:bg-primary hover:text-primary-foreground transition-all duration-200 rounded-xl shadow-sm",
                isActiveChannelDM && "bg-primary text-white shadow-md"
              )}
              onClick={() => setShowUsers(!showUsers)}
            >
              {showUsers ? (
                <ChevronDown className="h-4 w-4 mr-2 transition-transform" />
              ) : (
                <ChevronRight className="h-4 w-4 mr-2 transition-transform" />
              )}
              <Users className="h-4 w-4 mr-2" />
              Direct Messages
            </Button>
          </div>

          <div className={cn("mt-2", !showUsers && "hidden")}>
            {/* All Users - handles both existing DMs and new conversations */}
            <UserDirectory
              onStartDM={handleStartDM}
              onChannelSelect={onChannelSelect}
              className="border-0 shadow-none"
            />
          </div>
        </div>
      </div>
    )
  ), [
    loading,
    showChannels,
    showUsers,
    channels,
    activeChannelId,
    onChannelSelect,
    currentUserId,
    onlineUserIds,
    onPinChannel,
    filterType,
    isActiveChannelDM,
    isActiveChannelRegular
  ])

  return (
    <div className={cn("flex flex-col h-full bg-gradient-to-b from-card via-card/98 to-card/95 border-r shadow-md", className)}>
      {/* Header */}
      <div className="pl-5 pr-4 pt-6 pb-5 border-b bg-gradient-to-br from-card/80 via-primary/5 to-transparent backdrop-blur-sm">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-extrabold text-2xl tracking-tight bg-gradient-to-r from-foreground via-foreground to-foreground/80 bg-clip-text">Messages</h2>
          <div className="flex items-center gap-1.5">
            {/* Filter dropdown */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-9 w-9 p-0 hover:bg-primary/10 hover:text-primary hover:scale-110 transition-all duration-200 rounded-lg"
                  title="Filter conversations"
                >
                  <Filter className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuLabel>Filter by type</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => setFilterType('all')} className={filterType === 'all' ? 'bg-accent' : ''}>
                  All Conversations
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setFilterType('dm')} className={filterType === 'dm' ? 'bg-accent' : ''}>
                  <MessageSquare className="h-4 w-4 mr-2" />
                  Direct Messages
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setFilterType('project')} className={filterType === 'project' ? 'bg-accent' : ''}>
                  <Hash className="h-4 w-4 mr-2" />
                  Project Channels
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setFilterType('client-support')} className={filterType === 'client-support' ? 'bg-accent' : ''}>
                  <Phone className="h-4 w-4 mr-2" />
                  Client Support
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            {/* Audit Log button (admin only - API will enforce) */}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowAuditLog(true)}
              title="View Audit Logs"
              className="h-9 w-9 p-0 hover:bg-primary/10 hover:text-primary hover:scale-110 transition-all duration-200 rounded-lg"
            >
              <FileText className="h-4 w-4" />
            </Button>
            {/* Trash button */}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowTrash(true)}
              title="View Trash"
              className="h-9 w-9 p-0 hover:bg-primary/10 hover:text-primary hover:scale-110 transition-all duration-200 rounded-lg"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
            {onCreateChannel && (
              <Button
                variant="default"
                size="sm"
                onClick={onCreateChannel}
                className="h-9 w-9 p-0 hover:scale-110 transition-all duration-200 shadow-md hover:shadow-lg rounded-lg"
                title="Create new channel"
              >
                <MessageSquare className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>

        {/* Active filter indicator */}
        {filterType !== 'all' && (
          <Badge variant="secondary" className="text-xs font-semibold px-3 py-1 rounded-full shadow-sm animate-in fade-in duration-300">
            {filterType === 'dm' ? 'Direct Messages' : filterType === 'client-support' ? 'Client Support' : filterType.replace('-', ' ')}
          </Badge>
        )}
      </div>

      <div className="flex-1 overflow-auto">
        {content}
      </div>

      {/* Trash View Dialog */}
      <TrashView
        isOpen={showTrash}
        onClose={() => setShowTrash(false)}
      />

      {/* Audit Log View Dialog */}
      <AuditLogView
        isOpen={showAuditLog}
        onClose={() => setShowAuditLog(false)}
      />
    </div>
  )
})