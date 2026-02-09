"use client"

import { useState, useRef, useEffect, useLayoutEffect, useCallback } from "react"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Check,
  CheckCheck,
  Download,
  ExternalLink,
  Reply,
  MoreVertical,
  Trash2,
  Edit,
  Clock,
  CornerDownRight,
  Loader2,
  Smile,
  EyeOff,
  Forward,
  CheckSquare,
  X
} from "lucide-react"
import { cn } from "@/lib/utils"
import { ICommunication, ITypingIndicator, IParticipant, IAttachment, IGroupedReaction } from "@/types/communication"
import { AttachmentGrid } from "./attachment-preview"
import { WhatsAppAttachmentGrid } from "./whatsapp-attachment-grid"
import { AudioPlayer } from "./attachment-preview"
import { QuickReactionBar, MessageReactions } from "./reaction-picker"
import { formatDistanceToNow, format } from "date-fns"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"

import { IReadReceipt } from "@/types/communication"
import HtmlTextRenderer, { extractTextFromHtml } from "../shared/html-text-renderer"

interface MessageListProps {
  messages: ICommunication[]
  typingUsers: ITypingIndicator[]
  currentUserId: string
  onMessageRead?: (messageId: string) => void
  onReply?: (message: ICommunication) => void
  onEdit?: (message: ICommunication) => void
  onDelete?: (messageId: string) => void
  onMoveToTrash?: (messageId: string, channelId: string) => void
  onHideForSelf?: (messageId: string, channelId: string) => void
  onReaction?: (messageId: string, emoji: string) => void
  onScrollToMessage?: (messageId: string) => void
  onLoadMore?: () => Promise<{ messages: ICommunication[]; hasMore: boolean }>
  onForwardMessages?: (messageIds: string[]) => void
  hasMoreMessages?: boolean
  isLoadingMore?: boolean
  className?: string
  readReceipts?: IReadReceipt[] // Array of read receipts for all messages in this channel
  channel_members?: IParticipant[] // For showing who read
  selectMode?: boolean
  selectedMessageIds?: Set<string>
  onSelectionChange?: (selectedIds: Set<string>) => void
  onToggleSelectMode?: () => void
}

export function MessageList({
  messages,
  typingUsers,
  currentUserId,
  onMessageRead,
  onReply,
  onEdit,
  onDelete,
  onMoveToTrash,
  onHideForSelf,
  onReaction,
  onScrollToMessage,
  onLoadMore,
  onForwardMessages,
  hasMoreMessages = true,
  isLoadingMore = false,
  className,
  readReceipts = [],
  channel_members = [],
  selectMode = false,
  selectedMessageIds = new Set(),
  onSelectionChange,
  onToggleSelectMode
}: MessageListProps) {
  const [visibleMessages, setVisibleMessages] = useState(new Set<string>())
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const messagesContainerRef = useRef<HTMLDivElement>(null)
  const messageRefs = useRef<Map<string, HTMLDivElement>>(new Map())
  const observerRef = useRef<IntersectionObserver | null>(null)
  const loadMoreTriggerRef = useRef<HTMLDivElement>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const prevScrollHeightRef = useRef<number>(0)
  const prevFirstMessageIdRef = useRef<string | null>(null)
  const isInitialLoadRef = useRef(true)
  const isNearBottomRef = useRef(true)
  const shouldRestoreScrollRef = useRef(false)

  // Use useLayoutEffect to restore scroll position BEFORE browser paint
  // This prevents the visual "jump" when loading older messages
  useLayoutEffect(() => {
    const container = messagesContainerRef.current
    if (!container) return

    // Restore scroll position after loading older messages (prepended)
    if (shouldRestoreScrollRef.current && prevScrollHeightRef.current > 0) {
      const newScrollHeight = container.scrollHeight
      const scrollDiff = newScrollHeight - prevScrollHeightRef.current
      container.scrollTop = container.scrollTop + scrollDiff
      shouldRestoreScrollRef.current = false
      prevScrollHeightRef.current = 0
      return
    }

    // Update the first message id reference
    const currentFirstMessageId = messages.length > 0 ? messages[0].id : null
    const messagesWerePrepended = prevFirstMessageIdRef.current !== null &&
      currentFirstMessageId !== null &&
      prevFirstMessageIdRef.current !== currentFirstMessageId &&
      messages.some(m => m.id === prevFirstMessageIdRef.current)

    prevFirstMessageIdRef.current = currentFirstMessageId

    // Don't auto-scroll if messages were prepended (older messages loaded)
    if (messagesWerePrepended) {
      return
    }

    // Initial load - scroll to bottom immediately
    if (isInitialLoadRef.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'auto' })
      isInitialLoadRef.current = false
      return
    }

    // Only auto-scroll for new messages if user was near bottom
    if (isNearBottomRef.current && !loadingMore) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages, loadingMore])

  // Infinite scroll - load more when scrolling to top
  const handleScroll = useCallback(async () => {
    const container = messagesContainerRef.current
    if (!container) return

    // Track if user is near the bottom (within 150px)
    // This determines whether we should auto-scroll on new messages
    const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight
    isNearBottomRef.current = distanceFromBottom < 150

    // Don't trigger load more if already loading or no more messages
    if (loadingMore || !hasMoreMessages || !onLoadMore) return

    // Trigger load more when scrolled near top (within 100px)
    if (container.scrollTop < 100) {
      // Save scroll height BEFORE loading new messages
      prevScrollHeightRef.current = container.scrollHeight
      shouldRestoreScrollRef.current = true
      setLoadingMore(true)

      try {
        await onLoadMore()
        // hasMoreMessages will be updated by parent
      } finally {
        setLoadingMore(false)
      }
    }
  }, [loadingMore, hasMoreMessages, onLoadMore])

  // Intersection Observer for read receipts
  useEffect(() => {
    if (observerRef.current) {
      observerRef.current.disconnect()
    }

    observerRef.current = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const messageId = entry.target.getAttribute('data-message-id')
            if (messageId && !visibleMessages.has(messageId)) {
              setVisibleMessages(prev => new Set([...prev, messageId]))

              // Mark as read if not from current user
              const message = messages.find(m => m.id === messageId)
              if (message && message.mongo_sender_id !== currentUserId && !message.read_receipts?.length && onMessageRead) {
                onMessageRead(messageId)
              }
            }
          }
        })
      },
      { threshold: 0.5 }
    )

    // Observe all message elements
    const messageElements = document.querySelectorAll('[data-message-id]')
    messageElements.forEach(el => observerRef.current?.observe(el))

    return () => observerRef.current?.disconnect()
  }, [messages, currentUserId, onMessageRead, visibleMessages])

  // Scroll to a specific message (for reply navigation)
  const scrollToMessage = useCallback((messageId: string) => {
    const element = messageRefs.current.get(messageId)
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'center' })
      // Highlight briefly
      element.classList.add('bg-primary/10')
      setTimeout(() => {
        element.classList.remove('bg-primary/10')
      }, 2000)
    }
    onScrollToMessage?.(messageId)
  }, [onScrollToMessage])

  // Find parent message for reply preview
  const getParentMessage = useCallback((parentId?: string): ICommunication | undefined => {
    if (!parentId) return undefined
    return messages.find(m => m.id === parentId)
  }, [messages])

  // Helper to parse forwarded content for WhatsApp-style display
  const parseForwardedContent = useCallback((content: string): { isForwarded: boolean; cleanContent: string; forwardedFrom?: string } => {
    if (content.startsWith('[Forwarded]')) {
      const withoutForwarded = content.replace(/^\[Forwarded\]\n?/, '')
      return {
        isForwarded: true,
        cleanContent: withoutForwarded,
        forwardedFrom: undefined // Could add sender info if needed
      }
    }
    return {
      isForwarded: false,
      cleanContent: content
    }
  }, [])
  const formatMessageTime = (date: Date) => {
    const now = new Date()
    const messageDate = new Date(date)
    const diffInHours = Math.abs(now.getTime() - messageDate.getTime()) / (1000 * 60 * 60)

    if (diffInHours < 24) {
      return format(messageDate, 'HH:mm')
    } else if (diffInHours < 24 * 7) {
      return format(messageDate, 'EEE HH:mm')
    } else {
      return format(messageDate, 'MMM d, HH:mm')
    }
  }

  // file_name: string
  // file_url?: string
  // s3_key?: string
  // s3_bucket?: string
  // file_size?: number
  // file_type?: string
  const renderAttachments = (attachments: IAttachment[]) => {
    if (!attachments || attachments.length === 0) return null

    // Use WhatsApp-style grid for media-heavy attachments
    const hasMedia = attachments.some(a => {
      const type = a.file_type?.toLowerCase() || ''
      return type.startsWith('image/') || type.startsWith('video/')
    })

    if (hasMedia) {
      return (
        <div className="mt-1.5">
          <WhatsAppAttachmentGrid
            attachments={attachments}
            maxVisible={4}
            onForward={onForwardMessages ? (atts) => {
              // For attachments, we need to forward via messages
              // This opens the forward modal with the attachment IDs
              // The parent component handles the actual forwarding
            } : undefined}
          />
        </div>
      )
    }

    // Use regular grid for documents/files
    return (
      <div className="mt-1.5">
        <AttachmentGrid attachments={attachments} />
      </div>
    )
  }

  // Helper to group reactions by emoji for display - WhatsApp style
  const groupReactions = (reactions: ICommunication['reactions']): IGroupedReaction[] => {
    if (!reactions || reactions.length === 0) return []

    const grouped: Record<string, IGroupedReaction> = {}

    reactions.forEach((reaction) => {
      // Robust emoji validation - handle potential data corruption
      let emojiKey = reaction.emoji

      // Check if emoji field is corrupted (contains UUID or is too long)
      if (!emojiKey || emojiKey.length > 10 || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(emojiKey)) {
        emojiKey = '👍' // Fallback to default emoji
      }

      if (!grouped[emojiKey]) {
        grouped[emojiKey] = {
          emoji: emojiKey,
          count: 0,
          users: [],
          hasCurrentUserReacted: false
        }
      }
      grouped[emojiKey].count++

      // Ensure we have proper user name - use the stored user_name from reaction
      const userName = reaction.user_name || 'Someone'

      grouped[emojiKey].users.push({
        id: reaction.id,
        mongo_user_id: reaction.mongo_user_id,
        name: userName
      })

      if (reaction.mongo_user_id === currentUserId) {
        grouped[emojiKey].hasCurrentUserReacted = true
      }
    })

    return Object.values(grouped).sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count
      return a.emoji.localeCompare(b.emoji)
    })
  }

  const MessageItem = ({ message, isOwn }: { message: ICommunication; isOwn: boolean }) => {
    const sender = message.sender

    // Get read receipts from message's own read_receipts (for real-time updates) or from props (fallback)
    const messageReceipts = message.read_receipts || []
    const propReceipts = readReceipts.filter(r => r.message_id === message.id)
    // Merge both sources, preferring message's own receipts
    const allReceipts = [...messageReceipts]
    propReceipts.forEach(pr => {
      if (!allReceipts.some(r => r.mongo_user_id === pr.mongo_user_id)) {
        allReceipts.push(pr)
      }
    })

    // Find all read receipts for this message (excluding sender)
    const receipts = allReceipts.filter(r => r.mongo_user_id !== message.mongo_sender_id)

    // For current user, check if this message is read
    const isReadByCurrentUser = receipts.some(r => r.mongo_user_id === currentUserId)

    // For sender, show who has read
    const readers = channel_members.filter(p =>
      receipts.some(r => r.mongo_user_id === p.mongo_member_id)
    )

    // Get parent message for reply preview
    const parentMessage = getParentMessage(message.parent_message_id)

    // Message status
    const getStatusIcon = () => {
      if (message.isOptimistic) {
        // Message is being sent
        return <Clock className="h-3 w-3 text-muted-foreground animate-pulse" />
      }
      if (message.isFailed) {
        // Message failed to send
        return (
          <Tooltip>
            <TooltipTrigger>
              <span className="text-destructive text-xs">!</span>
            </TooltipTrigger>
            <TooltipContent>
              <p>Failed to send. Click to retry.</p>
            </TooltipContent>
          </Tooltip>
        )
      }
      if (readers.length > 0) {
        // Message has been read by at least one person
        return <CheckCheck className="h-3 w-3 text-primary" />
      }
      // Message sent but not read yet
      return <Check className="h-3 w-3 text-muted-foreground" />
    }

    const isSelected = selectedMessageIds.has(message.id)

    const handleMessageClick = () => {
      if (selectMode && onSelectionChange) {
        const newSelected = new Set(selectedMessageIds)
        if (isSelected) {
          newSelected.delete(message.id)
        } else {
          newSelected.add(message.id)
        }
        onSelectionChange(newSelected)
      }
    }

    return (
      <div
        data-message-id={message.id}
        ref={(el) => {
          if (el) messageRefs.current.set(message.id, el)
        }}
        className={cn(
          "flex gap-2 px-3 py-1 group transition-all duration-150 hover:bg-muted/20",
          isOwn && "flex-row-reverse",
          selectMode && "cursor-pointer",
          isSelected && "bg-primary/10"
        )}
        onClick={handleMessageClick}
      >
        {/* Selection checkbox in select mode */}
        {selectMode && (
          <div className="flex items-start pt-2 shrink-0">
            <Checkbox
              checked={isSelected}
              onCheckedChange={handleMessageClick}
              className="h-5 w-5"
            />
          </div>
        )}

        {/* Avatar */}
        <div className="shrink-0">
          {/* <Avatar className="h-8 w-8">
            <AvatarImage src={sender?.avatar} alt={sender?.name} />
            <AvatarFallback className="text-xs">
              {sender?.name?.split(' ').map(n => n[0]).join('').toUpperCase()}
            </AvatarFallback>
          </Avatar> */}
          <Avatar className="h-7 w-7 transition-transform duration-150 group-hover:scale-105">
            <AvatarImage src={sender?.avatar} alt={sender?.name} />
            <AvatarFallback className="bg-gradient-to-br from-primary/15 to-accent/30 text-primary font-medium text-xs">
              {sender?.name
                ? (() => {
                  const parts = sender.name.trim().split(' ');
                  if (parts.length === 1) {
                    return parts[0][0].toUpperCase();
                  }
                  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                })()
                : ''}
            </AvatarFallback>
          </Avatar>
        </div>

        {/* Message content */}
        <div className={cn("flex-1 space-y-0.5 flex flex-col", isOwn && "text-right")}>
          {/* Header */}
          <div className={cn("flex items-center gap-1.5", isOwn && "flex-row-reverse")}>
            <span className="font-medium text-[13px]">{sender?.name}</span>

            {sender?.role && (
              <Badge variant="outline" className="text-[9px] h-[14px] px-1 py-0 rounded-full border-primary/20 bg-primary/5 text-primary font-normal">
                {sender?.role}
              </Badge>
            )}

            <span className="text-[11px] text-muted-foreground">
              {formatMessageTime(new Date(message.created_at))}
            </span>

            {/* Message actions (visible on hover) */}
            <div className="opacity-0 group-hover:opacity-100 transition-all duration-150">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="sm" className="h-6 w-6 p-0 hover:bg-accent transition-all">
                    <MoreVertical className="h-3 w-3" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align={isOwn ? "end" : "start"} className="min-w-[140px]">
                  {onReply && (
                    <DropdownMenuItem onClick={() => onReply(message)} className="text-xs py-1.5">
                      <Reply className="h-3.5 w-3.5 mr-2" />
                      Reply
                    </DropdownMenuItem>
                  )}
                  {isOwn && onEdit && (
                    <DropdownMenuItem onClick={() => onEdit(message)} className="text-xs py-1.5">
                      <Edit className="h-3.5 w-3.5 mr-2" />
                      Edit
                    </DropdownMenuItem>
                  )}

                  {/* Forward message */}
                  {onForwardMessages && (
                    <DropdownMenuItem onClick={() => onForwardMessages([message.id])} className="text-xs py-1.5">
                      <Forward className="h-3.5 w-3.5 mr-2" />
                      Forward
                    </DropdownMenuItem>
                  )}

                  {/* Select for multi-forward */}
                  {onToggleSelectMode && (
                    <DropdownMenuItem onClick={() => {
                      onToggleSelectMode()
                      if (onSelectionChange) {
                        onSelectionChange(new Set([message.id]))
                      }
                    }} className="text-xs py-1.5">
                      <CheckSquare className="h-3.5 w-3.5 mr-2" />
                      Select
                    </DropdownMenuItem>
                  )}

                  {/* Delete options separator */}
                  {(onHideForSelf || (isOwn && onMoveToTrash) || (isOwn && onDelete)) && (
                    <DropdownMenuSeparator />
                  )}

                  {/* Hide for Me - available for all messages */}
                  {onHideForSelf && (
                    <DropdownMenuItem
                      onClick={() => onHideForSelf(message.id, message.channel_id)}
                      className="text-muted-foreground text-xs py-1.5"
                    >
                      <EyeOff className="h-3.5 w-3.5 mr-2" />
                      Delete for Me
                    </DropdownMenuItem>
                  )}

                  {/* Move to Trash - only for message owner */}
                  {isOwn && onMoveToTrash && (
                    <DropdownMenuItem
                      onClick={() => onMoveToTrash(message.id, message.channel_id)}
                      className="text-amber-600 text-xs py-1.5"
                    >
                      <Trash2 className="h-3.5 w-3.5 mr-2" />
                      Delete for everyone
                    </DropdownMenuItem>
                  )}

                  {/* Legacy delete (falls back to trash if no new handlers) */}
                  {isOwn && onDelete && !onMoveToTrash && (
                    <DropdownMenuItem
                      onClick={() => onDelete(message.id)}
                      className="text-destructive text-xs py-1.5"
                    >
                      <Trash2 className="h-3.5 w-3.5 mr-2" />
                      Delete
                    </DropdownMenuItem>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>

          {/* Message text */}
          <div className={cn(
            "relative rounded-xl px-3 py-2 shadow-sm border max-w-[65%] w-auto overflow-visible transition-all duration-150 group-hover:shadow-md",
            isOwn
              ? "bg-gradient-to-br from-primary to-primary/95 text-white ml-auto self-end border-primary/20"
              : "bg-card mr-auto self-start border-border/40 hover:border-border/60"
          )}>
            {/* Reply preview */}
            {parentMessage && (
              <button
                onClick={() => scrollToMessage(parentMessage.id)}
                className={cn(
                  "flex items-start gap-1.5 mb-2 px-2 py-1.5 rounded-md text-[11px] w-full text-left transition-colors border-l-2",
                  isOwn
                    ? "bg-primary-foreground/10 hover:bg-primary-foreground/15 border-primary-foreground/30"
                    : "bg-muted/40 hover:bg-muted/60 border-primary/40"
                )}
              >
                <CornerDownRight className="h-2.5 w-2.5 mt-0.5 shrink-0 opacity-60" />
                <div className="min-w-0 flex-1">
                  <p className={cn("font-medium truncate text-[11px]", isOwn ? "text-primary-foreground" : "text-foreground")}>
                    {parentMessage.sender?.name || parentMessage.sender_name}
                  </p>
                  <p className={cn("truncate opacity-70 text-[10px]", isOwn ? "text-primary-foreground" : "text-muted-foreground")}>
                    {extractTextFromHtml(parentMessage.content, 50)}
                  </p>
                </div>
              </button>
            )}

            {/* Render content based on type */}
            {message.content_type === 'audio' && message.attachments && message.attachments.length > 0 ? (
              <div className="space-y-2">
                {/* Voice message content */}
                {message.content && message.content !== '🎤 Voice message' && (
                  <HtmlTextRenderer
                    content={message.content}
                    fallbackText=""
                    showFallback={false}
                    renderAsHtml={true}
                    className={cn(
                      "text-[13px] leading-snug whitespace-pre-wrap [overflow-wrap:anywhere]",
                      isOwn && "text-white"
                    )}
                    truncateHtml={false}
                  />
                )}
                {/* Audio player for voice messages */}
                {message.attachments[0].file_url && (
                  <AudioPlayer
                    src={message.attachments[0].file_url}
                    duration={message.attachments[0].durationSeconds}
                    className="max-w-xs"
                    isVoiceMessage={true}
                  />
                )}
              </div>
            ) : (() => {
              const { isForwarded, cleanContent } = parseForwardedContent(message.content || '')
              const hasAttachments = message.attachments && message.attachments.length > 0

              return (
                <>
                  {/* WhatsApp-style forwarded message layout */}
                  {isForwarded && (
                    <div className={cn(
                      "text-[11px] font-medium mb-1.5 italic flex items-center gap-1",
                      isOwn ? "text-primary-foreground/70" : "text-muted-foreground"
                    )}>
                      <Forward className="h-3 w-3" />
                      Forwarded
                    </div>
                  )}

                  {/* For forwarded messages with attachments: show attachments first, then content */}
                  {isForwarded && hasAttachments ? (
                    <>
                      {/* Attachments first */}
                      {renderAttachments(message.attachments)}

                      {/* Then content (if any) */}
                      {cleanContent.trim() && (
                        <div className="mt-2">
                          <HtmlTextRenderer
                            content={cleanContent}
                            fallbackText=""
                            showFallback={false}
                            renderAsHtml={true}
                            className={cn(
                              "text-[13px] leading-snug whitespace-pre-wrap [overflow-wrap:anywhere]",
                              isOwn && "text-white"
                            )}
                            truncateHtml={false}
                          />
                        </div>
                      )}
                    </>
                  ) : (
                    <>
                      {/* Normal message or forwarded without attachments: content first */}
                      <HtmlTextRenderer
                        content={isForwarded ? cleanContent : message.content}
                        fallbackText="No description"
                        showFallback={true}
                        renderAsHtml={true}
                        className={cn(
                          "text-[13px] leading-snug whitespace-pre-wrap [overflow-wrap:anywhere]",
                          isOwn && "text-white"
                        )}
                        truncateHtml={false}
                      />

                      {/* Then attachments */}
                      {hasAttachments && renderAttachments(message.attachments)}
                    </>
                  )}
                </>
              )
            })()}

            {/* Quick reaction bar (visible on hover) */}
            {onReaction && (
              <div className={cn(
                "absolute -top-3 opacity-0 group-hover:opacity-100 transition-all duration-150 transform group-hover:scale-100 scale-90 z-10 shadow-md",
                isOwn ? "left-0" : "right-0"
              )}>
                <QuickReactionBar
                  onSelect={(emoji) => onReaction(message.id, emoji)}
                />
              </div>
            )}
          </div>

          {/* Message reactions */}
          {message.reactions && message.reactions.length > 0 && (
            <MessageReactions
              reactions={groupReactions(message.reactions)}
              onReactionClick={(emoji) => onReaction?.(message.id, emoji)}
              currentUserId={currentUserId}
              className={isOwn ? "justify-end" : "justify-start"}
            />
          )}

          {/* Status and read receipts UI */}
          <div className={cn("flex items-center gap-0.5 text-[10px] text-muted-foreground", isOwn && "justify-end")}>
            {isOwn && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger className="flex items-center">
                    {getStatusIcon()}
                  </TooltipTrigger>
                  <TooltipContent>
                    {message.isOptimistic ? (
                      <p>Sending...</p>
                    ) : message.isFailed ? (
                      <p>Failed to send</p>
                    ) : readers.length > 0 ? (
                      <div>
                        <p className="font-medium text-xs">Read by {readers.length}</p>
                        <div className="flex flex-col gap-0.5 mt-1 max-h-28 overflow-y-auto">
                          {readers.map(r => {
                            const receipt = receipts.find(rr => rr.mongo_user_id === r.mongo_member_id)
                            return (
                              <span key={`reader-${r.mongo_member_id}`} className="flex items-center gap-1 text-[10px]">
                                <span>{r.name}</span>
                                {receipt && (
                                  <span className="text-muted-foreground ml-1">
                                    {format(new Date(receipt.read_at), 'HH:mm')}
                                  </span>
                                )}
                              </span>
                            )
                          })}
                        </div>
                      </div>
                    ) : (
                      <p>Sent</p>
                    )}
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}

            {message.edited_at && message.edited_at !== message.created_at && (
              <span className="italic text-[10px]">(edited)</span>
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <TooltipProvider>
      <>
        {/* Multi-select action bar */}
        {selectMode && (
          <div className="sticky top-0 z-10 flex items-center justify-between p-3 bg-primary/10 border-b">
            <div className="flex items-center gap-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  onToggleSelectMode?.()
                  onSelectionChange?.(new Set())
                }}
              >
                <X className="h-4 w-4 mr-1" />
                Cancel
              </Button>
              <span className="text-sm font-medium">
                {selectedMessageIds.size} message{selectedMessageIds.size !== 1 ? 's' : ''} selected
              </span>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => onSelectionChange?.(new Set())}
                disabled={selectedMessageIds.size === 0}
              >
                Clear
              </Button>
              <Button
                variant="default"
                size="sm"
                onClick={() => onForwardMessages?.(Array.from(selectedMessageIds))}
                disabled={selectedMessageIds.size === 0}
              >
                <Forward className="h-4 w-4 mr-1" />
                Forward ({selectedMessageIds.size})
              </Button>
            </div>
          </div>
        )}

        {/* Messages */}
        <div
          ref={messagesContainerRef}
          onScroll={handleScroll}
          className={cn("flex-1 min-h-0 overflow-y-auto overflow-x-hidden space-y-1 p-3", className)}
        >
          {/* Load more indicator at top */}
          {hasMoreMessages && messages.length > 0 && (
            <div
              ref={loadMoreTriggerRef}
              className="flex justify-center py-2"
            >
              {loadingMore || isLoadingMore ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Loading older messages...</span>
                </div>
              ) : (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onLoadMore?.()}
                  className="text-xs text-muted-foreground hover:text-foreground"
                >
                  Load older messages
                </Button>
              )}
            </div>
          )}

          {messages.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-muted-foreground h-full">
              <div className="text-center">
                <p>No messages yet</p>
                <p className="text-sm mt-1">Start the conversation!</p>
              </div>
            </div>
          ) : (
            <>
              {messages.map((message) => (
                <MessageItem
                  key={message.id}
                  message={message}
                  isOwn={message.mongo_sender_id === currentUserId}
                />
              ))}

              {/* Typing indicators */}
              {typingUsers.length > 0 && (
                <div className="flex items-center gap-3 p-3 animate-pulse">
                  <div className="flex -space-x-1">
                    {typingUsers.slice(0, 3).map((typing) => {
                      const user = { name: typing.userName, avatar: '' }
                      return (
                        <Avatar key={`typing-${typing.userId}`} className="h-6 w-6 border-2 border-background">
                          <AvatarImage src={user.avatar} alt={user.name} />
                          <AvatarFallback className="text-xs">
                            {user.name ? (() => {
                              const parts = user.name.trim().split(' ');
                              if (parts.length === 1) {
                                return parts[0][0].toUpperCase();
                              }
                              return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                            })()
                              : ''}
                          </AvatarFallback>
                        </Avatar>
                      )
                    })}
                  </div>

                  <div className="text-sm text-muted-foreground italic">
                    {typingUsers.length === 1
                      ? `${typingUsers[0].userName} is typing...`
                      : `${typingUsers.length} people are typing...`
                    }
                  </div>

                  <div className="flex gap-1">
                    <div className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce [animation-delay:-0.3s]"></div>
                    <div className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce [animation-delay:-0.15s]"></div>
                    <div className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce"></div>
                  </div>
                </div>
              )}
            </>
          )}

          {/* Scroll anchor */}
          <div ref={messagesEndRef} />
        </div>
      </>
    </TooltipProvider>
  )
}
