"use client"

import { useState, useMemo, useCallback, memo, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Checkbox } from "@/components/ui/checkbox"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Textarea } from "@/components/ui/textarea"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { cn } from "@/lib/utils"
import {
  Search,
  MessageSquare,
  Users,
  Hash,
  Phone,
  Pin,
  Clock,
  Forward,
  FileText,
  Image as ImageIcon,
  Loader2,
  X,
} from "lucide-react"
import { IChannel, IAttachment } from "@/types/communication"
import { useCommunications } from "@/hooks/use-communications"
import { useSession } from "next-auth/react"
import { formatDistanceToNow } from "date-fns"
import { getFileCategory, formatFileSize } from "@/lib/utils/file-preview"

interface ChatSelectorModalProps {
  isOpen: boolean
  onClose: () => void
  onSelect: (channelIds: string[], message?: string) => void
  multiSelect?: boolean
  attachments?: IAttachment[]
  title?: string
  description?: string
}

/**
 * Modal for selecting one or more chats to forward attachments to
 */
export const ChatSelectorModal = memo(function ChatSelectorModal({
  isOpen,
  onClose,
  onSelect,
  multiSelect = true,
  attachments = [],
  title = "Forward to...",
  description = "Select chats to forward the attachment(s)"
}: ChatSelectorModalProps) {
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedChannelIds, setSelectedChannelIds] = useState<Set<string>>(new Set())
  const [message, setMessage] = useState("")
  const [isForwarding, setIsForwarding] = useState(false)

  const { channels } = useCommunications()
  const { data: session } = useSession()
  const currentUserId = (session?.user as any)?.id

  // Reset state when modal opens
  useEffect(() => {
    if (isOpen) {
      setSelectedChannelIds(new Set())
      setMessage("")
      setSearchQuery("")
    }
  }, [isOpen])

  // Get channel icon
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

  // Get channel display name
  const getChannelDisplayName = (channel: IChannel) => {
    if (channel.type === 'dm') {
      const otherParticipant = channel.channel_members.find(p => p.mongo_member_id !== currentUserId)
      return otherParticipant?.name || 'Unknown User'
    }
    return channel.name || 'Unnamed Channel'
  }

  // Get channel avatar
  const getChannelAvatar = (channel: IChannel) => {
    if (channel.type === 'dm') {
      const other = channel.channel_members.find(p => p.mongo_member_id !== currentUserId)
      return other?.avatar
    }
    return channel.avatar_url
  }

  // Separate pinned and recent channels
  const { pinnedChannels, recentChannels, filteredChannels } = useMemo(() => {
    const query = searchQuery.toLowerCase()
    
    const filtered = channels.filter(channel => {
      if (!query) return true
      const name = getChannelDisplayName(channel).toLowerCase()
      return name.includes(query)
    })

    const pinned = filtered.filter((ch: any) => ch.is_pinned)
    const unpinned = filtered.filter((ch: any) => !ch.is_pinned)
    
    // Sort unpinned by last activity
    const sorted = unpinned.sort((a, b) => {
      const aTime = a.last_message_at ? new Date(a.last_message_at).getTime() : 0
      const bTime = b.last_message_at ? new Date(b.last_message_at).getTime() : 0
      return bTime - aTime
    })

    return {
      pinnedChannels: pinned,
      recentChannels: sorted.slice(0, 10),
      filteredChannels: filtered
    }
  }, [channels, searchQuery, currentUserId])

  // Toggle channel selection
  const toggleChannel = useCallback((channelId: string) => {
    setSelectedChannelIds(prev => {
      const newSet = new Set(prev)
      if (newSet.has(channelId)) {
        newSet.delete(channelId)
      } else {
        if (!multiSelect) {
          newSet.clear()
        }
        newSet.add(channelId)
      }
      return newSet
    })
  }, [multiSelect])

  // Handle forward
  const handleForward = useCallback(async () => {
    if (selectedChannelIds.size === 0) return
    
    setIsForwarding(true)
    try {
      onSelect(Array.from(selectedChannelIds), message.trim() || undefined)
    } finally {
      setIsForwarding(false)
    }
  }, [selectedChannelIds, message, onSelect])

  // Render channel item
  const renderChannelItem = (channel: IChannel) => {
    const isSelected = selectedChannelIds.has(channel.id)
    const name = getChannelDisplayName(channel)
    const avatar = getChannelAvatar(channel)

    return (
      <div
        key={channel.id}
        className={cn(
          "flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-colors",
          isSelected 
            ? "bg-primary/10 border border-primary/30" 
            : "hover:bg-muted/50 border border-transparent"
        )}
        onClick={() => toggleChannel(channel.id)}
      >
        {/* Checkbox */}
        <Checkbox 
          checked={isSelected}
          onCheckedChange={() => toggleChannel(channel.id)}
        />

        {/* Avatar */}
        <Avatar className="h-10 w-10">
          <AvatarImage src={avatar} alt={name} />
          <AvatarFallback className="bg-gradient-to-br from-primary/20 to-accent/40">
            {name.substring(0, 2).toUpperCase()}
          </AvatarFallback>
        </Avatar>

        {/* Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            {getChannelIcon(channel)}
            <span className="font-medium text-sm truncate">{name}</span>
          </div>
          {channel.last_message_at && (
            <span className="text-xs text-muted-foreground">
              {formatDistanceToNow(new Date(channel.last_message_at), { addSuffix: true })}
            </span>
          )}
        </div>

        {/* Type badge */}
        <Badge variant="outline" className="text-xs capitalize">
          {channel.type === 'dm' ? 'DM' : channel.type}
        </Badge>
      </div>
    )
  }

  // Get file preview icon
  const getFileIcon = (attachment: IAttachment) => {
    const category = getFileCategory(attachment.file_type, attachment.file_name)
    if (category === 'image') return <ImageIcon className="h-4 w-4" />
    return <FileText className="h-4 w-4" />
  }

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Forward className="h-5 w-5" />
            {title}
          </DialogTitle>
          <DialogDescription>
            {description}
          </DialogDescription>
        </DialogHeader>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search chats..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
          />
        </div>

        {/* Attachments preview */}
        {attachments.length > 0 && (
          <div className="flex flex-wrap gap-2 p-3 bg-muted/30 rounded-lg">
            {attachments.map((att) => (
              <div 
                key={att.id}
                className="flex items-center gap-2 px-2 py-1 bg-background rounded border text-xs"
              >
                {getFileIcon(att)}
                <span className="truncate max-w-[120px]">{att.file_name}</span>
                <span className="text-muted-foreground">
                  {formatFileSize(att.file_size)}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* Channel list */}
        <ScrollArea className="flex-1 max-h-[300px] -mx-6 px-6">
          <div className="space-y-4">
            {/* Pinned section */}
            {pinnedChannels.length > 0 && (
              <div>
                <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground mb-2">
                  <Pin className="h-3 w-3" />
                  PINNED
                </div>
                <div className="space-y-1">
                  {pinnedChannels.map(renderChannelItem)}
                </div>
              </div>
            )}

            {/* Recent section */}
            {recentChannels.length > 0 && (
              <div>
                <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground mb-2">
                  <Clock className="h-3 w-3" />
                  RECENT
                </div>
                <div className="space-y-1">
                  {recentChannels.map(renderChannelItem)}
                </div>
              </div>
            )}

            {/* All channels if searching */}
            {searchQuery && filteredChannels.length === 0 && (
              <div className="text-center py-8 text-muted-foreground">
                <Search className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>No chats found matching "{searchQuery}"</p>
              </div>
            )}
          </div>
        </ScrollArea>

        {/* Optional message */}
        {selectedChannelIds.size > 0 && (
          <div className="space-y-2">
            <Textarea
              placeholder="Add a message (optional)..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              className="resize-none"
              rows={2}
            />
          </div>
        )}

        {/* Selected summary */}
        {selectedChannelIds.size > 0 && (
          <div className="flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">
              Forwarding to {selectedChannelIds.size} chat{selectedChannelIds.size !== 1 ? 's' : ''}
            </span>
            <Button 
              variant="ghost" 
              size="sm" 
              onClick={() => setSelectedChannelIds(new Set())}
            >
              <X className="h-3 w-3 mr-1" />
              Clear
            </Button>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isForwarding}>
            Cancel
          </Button>
          <Button 
            onClick={handleForward}
            disabled={selectedChannelIds.size === 0 || isForwarding}
          >
            {isForwarding ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                Forwarding...
              </>
            ) : (
              <>
                <Forward className="h-4 w-4 mr-2" />
                Forward to {selectedChannelIds.size || ''} Chat{selectedChannelIds.size !== 1 ? 's' : ''}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
})

export default ChatSelectorModal
