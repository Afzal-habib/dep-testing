"use client"

import { useState, useEffect, useCallback } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Checkbox } from "@/components/ui/checkbox"
import {
  X,
  Users,
  Hash,
  FileText,
  ExternalLink,
  Settings,
  Bell,
  BellOff,
  Pin,
  Archive,
  Loader2,
  Download,
  Eye,
  UserMinus,
  LogOut,
  Forward,
  Share2,
  CheckSquare,
  Square,
  Grid3X3,
  PinOff
} from "lucide-react"
import { cn } from "@/lib/utils"
import { IChannel, IParticipant, IAttachment } from "@/types/communication"
import { format, formatDistanceToNow } from "date-fns"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { useChatAttachments } from "@/hooks/use-chat-attachments"
import { useCommunications } from "@/hooks/use-communications"
import { useSession } from "next-auth/react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import {
  getFileCategory,
  getFileIcon,
  getExtensionColor,
  formatFileSize
} from "@/components/communication/attachment-preview"
import { AttachmentShareMenu } from "@/components/communication/attachment-share-menu"
import { ChatSelectorModal } from "@/components/communication/chat-selector-modal"
import { AttachmentGallery } from "@/components/communication/attachment-gallery"
import { updateChannel } from "@/store/slices/communicationSlice"
import { useAppDispatch } from "@/hooks/redux"
import ChannelSettingsModal from "./channel-settings-modal"
import { useToast } from "@/hooks/use-toast"
import { communicationLogger as logger } from "@/lib/logger"

interface AttachmentWithUploader extends IAttachment {
  uploaded_by?: string
}

interface ContextPanelProps {
  channel?: IChannel
  isVisible: boolean
  onToggle: () => void
  onClose?: () => void
  onPinChannel?: (channelId: string, isPinned: boolean) => Promise<void>
  className?: string
}

export function ContextPanel({
  channel,
  isVisible,
  onToggle,
  onClose,
  onPinChannel,
  className
}: ContextPanelProps) {
  const [isNotificationEnabled, setIsNotificationEnabled] = useState(true)
  const [isMuteLoading, setIsMuteLoading] = useState(false)
  const [isPinned, setIsPinned] = useState(false)
  const [pinLoading, setPinLoading] = useState(false)
  const [attachments, setAttachments] = useState<AttachmentWithUploader[]>([])
  const [attachmentsLoading, setAttachmentsLoading] = useState(false)
  const [attachmentError, setAttachmentError] = useState<string | null>(null)
  const [showAllAttachments, setShowAllAttachments] = useState(false)

  // Multi-select state for attachments
  const [selectMode, setSelectMode] = useState(false)
  const [selectedAttachments, setSelectedAttachments] = useState<Set<string>>(new Set())
  const [showChatSelector, setShowChatSelector] = useState(false)
  const [showGallery, setShowGallery] = useState(false)

  // Remove member state
  const [showRemoveMemberConfirm, setShowRemoveMemberConfirm] = useState<string | null>(null)
  const [isRemovingMember, setIsRemovingMember] = useState(false)

  // Channel settings modal state
  const [showChannelSettings, setShowChannelSettings] = useState(false)

  const { fetchChannelAttachments, downloadAttachment, previewAttachment, forwardAttachment } = useChatAttachments()
  const { data: session } = useSession()
  const currentUserId = (session?.user as any)?.id
  const { actionLoading, leaveChannel, archiveChannel, muteChannel } = useCommunications()
  const dispatch = useAppDispatch()
  const { toast } = useToast()

  // Fetch attachments when channel changes
  useEffect(() => {
    if (!channel?.id || !isVisible) {
      setAttachments([])
      return
    }

    const loadAttachments = async () => {
      setAttachmentsLoading(true)
      setAttachmentError(null)

      try {
        const result = await fetchChannelAttachments({
          channelId: channel.id,
          limit: showAllAttachments ? 50 : 5
        })
        setAttachments(result.attachments)
      } catch (error) {
        logger.error('Failed to load attachments:', error)
        setAttachmentError('Failed to load files')
      } finally {
        setAttachmentsLoading(false)
      }
    }

    loadAttachments()
  }, [channel?.id, isVisible, showAllAttachments, fetchChannelAttachments])

  // Sync pinned state with channel
  useEffect(() => {
    if (channel) {
      setIsPinned((channel as any).is_pinned || false)
    }
  }, [channel])

  // Sync notification/mute state with channel member data
  useEffect(() => {
    if (channel && currentUserId) {
      const currentMember = channel.channel_members.find(
        m => m.mongo_member_id === currentUserId
      )
      // notifications_enabled defaults to true if not set
      setIsNotificationEnabled(currentMember?.notifications_enabled ?? true)
    }
  }, [channel, currentUserId])

  // Handle mute toggle
  const handleMuteToggle = useCallback(async () => {
    if (!channel) return

    setIsMuteLoading(true)
    try {
      const result = await muteChannel(channel.id, !isNotificationEnabled)
      setIsNotificationEnabled(result.notifications_enabled)
    } catch (error: any) {
      logger.error('Mute toggle error:', error)
      toast({
        title: "Failed to update notification settings",
        description: error.message || "Something went wrong",
        variant: "destructive"
      })
    } finally {
      setIsMuteLoading(false)
    }
  }, [channel, isNotificationEnabled, muteChannel, toast])

  const handleDownload = useCallback((attachment: IAttachment) => {
    downloadAttachment(attachment)
  }, [downloadAttachment])

  const handlePreview = useCallback((attachment: IAttachment) => {
    previewAttachment(attachment)
  }, [previewAttachment])

  // Get current user's membership and permissions
  const currentMembership = channel?.channel_members.find(
    m => m.mongo_member_id === currentUserId
  )

  const isOwner = currentMembership?.channelRole === 'owner' || channel?.mongo_creator_id === currentUserId
  const isAdmin = isOwner || currentMembership?.channelRole === 'admin'

  // Handle remove member
  const handleRemoveMember = useCallback(async (memberId: string) => {
    if (!channel) return

    setIsRemovingMember(true)
    try {
      const response = await fetch(`/api/communication/channels/${channel.id}?action=remove-member&mongo_member_id=${memberId}`, {
        method: 'DELETE'
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Failed to remove member')
      }

      const data = await response.json()
      if (data.success && data.channel) {
        // Update channel data immediately
        dispatch(updateChannel({ id: channel.id, ...data.channel }))
      }

      // Close confirmation dialog
      setShowRemoveMemberConfirm(null)

      // Note: Real-time updates will handle UI refresh for other users
      // The channel data has been updated immediately for current user
    } catch (error: any) {
      logger.error('Remove member error:', error)
      toast({
        title: "Failed to remove member",
        description: error.message || "Something went wrong",
        variant: "destructive"
      })
    } finally {
      setIsRemovingMember(false)
    }
  }, [channel])

  // Handle pin toggle
  const handlePinToggle = useCallback(async () => {
    if (!channel || !onPinChannel) return

    const currentPinned = (channel as any).is_pinned || false
    setPinLoading(true)

    try {
      await onPinChannel(channel.id, currentPinned)
      setIsPinned(!currentPinned)
    } catch (error: any) {
      logger.error('Pin toggle error:', error)
      toast({
        title: "Failed to pin channel",
        description: error.message || "Something went wrong",
        variant: "destructive"
      })
    } finally {
      setPinLoading(false)
    }
  }, [channel, onPinChannel])

  // Toggle attachment selection
  const toggleAttachmentSelection = useCallback((attachmentId: string) => {
    setSelectedAttachments(prev => {
      const newSet = new Set(prev)
      if (newSet.has(attachmentId)) {
        newSet.delete(attachmentId)
      } else {
        newSet.add(attachmentId)
      }
      return newSet
    })
  }, [])

  // Handle forward selected attachments
  const handleForwardSelected = useCallback(async (channelIds: string[], message?: string) => {
    if (selectedAttachments.size === 0) return

    const selectedAtts = attachments.filter(a => selectedAttachments.has(a.id))
    let successCount = 0

    for (const att of selectedAtts) {
      const success = await forwardAttachment(att.id, channelIds, message)
      if (success) successCount++
    }

    if (successCount > 0) {
      toast({
        title: 'Attachments Forwarded',
        description: `${successCount} file(s) sent to ${channelIds.length} chat(s)`,
      })
      setSelectedAttachments(new Set())
      setSelectMode(false)
    }

    setShowChatSelector(false)
  }, [selectedAttachments, attachments, forwardAttachment, toast])

  if (!isVisible || !channel) {
    return null
  }

  const getChannelTypeLabel = (type: string) => {
    switch (type) {
      case 'dm': return 'Direct Message'
      case 'project': return 'Project Channel'
      case 'client-support': return 'Client Support'
      case 'group': return 'Group Channel'
      default: return 'Channel'
    }
  }

  const mockProjectInfo = channel.mongo_project_id ? {
    name: 'Digi Era Pro CRM Development',
    description: 'Complete CRM system with advanced features',
    status: 'In Progress',
    deadline: '2025-12-31'
  } : null

  // Render file item with selection support
  const renderFileItem = (attachment: AttachmentWithUploader) => {
    const category = getFileCategory(attachment.file_type, attachment.file_name)
    const Icon = getFileIcon(category)
    const colorClass = getExtensionColor(category)
    const isSelected = selectedAttachments.has(attachment.id)

    return (
      <div
        key={attachment.id}
        className={cn(
          "flex items-center gap-3 p-2 rounded-lg hover:bg-muted/50 cursor-pointer group transition-colors",
          isSelected && "bg-primary/10 ring-1 ring-primary"
        )}
        onClick={() => selectMode && toggleAttachmentSelection(attachment.id)}
      >
        {/* Selection checkbox in select mode */}
        {selectMode && (
          <Checkbox
            checked={isSelected}
            onCheckedChange={() => toggleAttachmentSelection(attachment.id)}
            className="shrink-0"
          />
        )}

        <div className={cn("h-8 w-8 rounded flex items-center justify-center shrink-0", colorClass)}>
          <Icon className="h-4 w-4" />
        </div>

        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate">{attachment.file_name}</p>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span>{formatFileSize(attachment.file_size)}</span>
            {attachment.uploaded_by && (
              <>
                <span>•</span>
                <span>{attachment.uploaded_by}</span>
              </>
            )}
            {attachment.created_at && (
              <>
                <span>•</span>
                <span>{format(new Date(attachment.created_at), 'MMM d')}</span>
              </>
            )}
          </div>
        </div>

        {/* Actions - show share menu and download */}
        {!selectMode && (
          <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
            <AttachmentShareMenu
              attachment={attachment}
              onForward={(att) => {
                setSelectedAttachments(new Set([att.id]))
                setShowChatSelector(true)
              }}
              variant="icon"
              size="sm"
              className="h-6 w-6 p-0"
            />
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 w-6 p-0"
                  onClick={(e) => {
                    e.stopPropagation()
                    handlePreview(attachment)
                  }}
                >
                  <Eye className="h-3 w-3" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                <p>Preview</p>
              </TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 w-6 p-0"
                  onClick={(e) => {
                    e.stopPropagation()
                    handleDownload(attachment)
                  }}
                >
                  <Download className="h-3 w-3" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                <p>Download</p>
              </TooltipContent>
            </Tooltip>
          </div>
        )
        }
      </div>
    )
  }

  return (
    <TooltipProvider>
      <div className={cn(
        "bg-card flex flex-col h-full",
        className
      )}>
        {/* Header */}
        <div className="p-4 border-b flex items-center justify-between">
          <h3 className="font-semibold">Channel Info</h3>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose || onToggle}
            className="h-8 w-8 p-0"
          >
            <X className="h-4 w-4" />
          </Button>
        </div>

        <ScrollArea className="flex-1 pb-4">
          <div className="pl-2 pr-6 space-y-4">
            {/* Channel Overview */}
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Hash className="h-5 w-5 text-muted-foreground" />
                <h4 className="font-medium">{channel.name}</h4>
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Type:</span>
                  <Badge variant="outline">{getChannelTypeLabel(channel.type)}</Badge>
                </div>

                <div className="flex justify-between">
                  <span className="text-muted-foreground">Created:</span>
                  <span>{format(new Date(channel.created_at), 'MMM d, yyyy')}</span>
                </div>

                <div className="flex justify-between">
                  <span className="text-muted-foreground">Members:</span>
                  <span>{channel.channel_members.length}</span>
                </div>

                {!channel.is_private && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Visibility:</span>
                    <Badge variant="secondary">External</Badge>
                  </div>
                )}
              </div>

              {/* Quick Actions */}
              <div className="flex gap-2 pt-2">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleMuteToggle}
                      disabled={isMuteLoading}
                    >
                      {isMuteLoading ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : isNotificationEnabled ? (
                        <Bell className="h-4 w-4" />
                      ) : (
                        <BellOff className="h-4 w-4 text-muted-foreground" />
                      )}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{isNotificationEnabled ? 'Mute' : 'Unmute'} notifications</p>
                  </TooltipContent>
                </Tooltip>

                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handlePinToggle}
                      disabled={pinLoading || !onPinChannel}
                    >
                      {pinLoading ? (
                        <div className="h-3 w-3 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                      ) : (
                        isPinned ? (
                          <PinOff className="h-4 w-4" />
                        ) : (
                          <Pin className={cn("h-4 w-4")} />
                        )
                      )}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{isPinned ? 'Unpin' : 'Pin'} channel</p>
                  </TooltipContent>
                </Tooltip>
                {channel.type !== 'dm' && (
                  <>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button variant="outline" size="sm" onClick={() => setShowChannelSettings(true)}>
                          <Settings className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>Channel settings</p>
                      </TooltipContent>
                    </Tooltip>


                    {/* <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => leaveChannel(channel.id)}
                          className="text-orange-600"
                        >
                          <LogOut className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>Leave channel</p>
                      </TooltipContent>
                    </Tooltip> */}

                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => archiveChannel(channel.id, (channel as any).is_archived ? 'unarchive' : 'archive')}
                          className="text-destructive"
                        >
                          <Archive className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>{(channel as any).is_archived ? 'Unarchive' : 'Archive'} channel</p>
                      </TooltipContent>
                    </Tooltip>
                  </>
                )}
              </div>
            </div>

            <Separator />

            {/* Project Info (if applicable) */}
            {mockProjectInfo && (
              <>
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <FileText className="h-5 w-5 text-muted-foreground" />
                    <h4 className="font-medium">Project Details</h4>
                  </div>

                  <div className="space-y-2 text-sm">
                    <div>
                      <span className="text-muted-foreground">Name:</span>
                      <p className="font-medium">{mockProjectInfo.name}</p>
                    </div>

                    <div>
                      <span className="text-muted-foreground">Description:</span>
                      <p>{mockProjectInfo.description}</p>
                    </div>

                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Status:</span>
                      <Badge variant="default">{mockProjectInfo.status}</Badge>
                    </div>

                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Deadline:</span>
                      <span>{format(new Date(mockProjectInfo.deadline), 'MMM d, yyyy')}</span>
                    </div>
                  </div>

                  <Button variant="outline" size="sm" className="w-full">
                    <ExternalLink className="h-4 w-4 mr-2" />
                    View Project
                  </Button>
                </div>

                <Separator />
              </>
            )}

            {/* Members */}
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Users className="h-5 w-5 text-muted-foreground" />
                <h4 className="font-medium">Members ({channel.channel_members.length})</h4>
              </div>

              <div className="space-y-2">
                {channel.channel_members.map((participant) => {
                  const isCurrentUser = participant.mongo_member_id === currentUserId
                  const isMemberOwner = participant.channelRole === 'owner' || participant.mongo_member_id === channel.mongo_creator_id
                  const canRemoveMember = isAdmin && !isMemberOwner && !isCurrentUser

                  return (
                    <div key={participant.mongo_member_id} className="flex items-center gap-3 p-2 rounded-lg hover:bg-muted/50 group">
                      <div className="relative">
                        <Avatar className="h-8 w-8">
                          <AvatarImage src={participant.avatar} alt={participant.name} />
                          <AvatarFallback className="text-xs">
                            {participant.name
                              ? participant.name.split(' ').map(n => n[0]).join('').toUpperCase()
                              : ''}
                          </AvatarFallback>
                        </Avatar>
                        {participant.isOnline && (
                          <div className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-emerald-500 border-2 border-background" />
                        )}
                      </div>

                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{participant.name}</p>
                        <div className="flex items-center gap-2">
                          {participant.channelRole && (
                            <Badge variant="outline" className="text-xs">
                              {participant.channelRole}
                            </Badge>
                          )}
                          <Badge variant="secondary" className="text-xs">
                            {participant.userType}
                          </Badge>
                        </div>
                      </div>

                      {/* Remove member button for admins */}
                      {canRemoveMember && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity text-destructive hover:text-destructive hover:bg-destructive/10"
                          onClick={() => setShowRemoveMemberConfirm(participant.mongo_member_id)}
                          disabled={isRemovingMember}
                        >
                          <UserMinus className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

            <Separator />

            {/* Shared Files */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="h-5 w-5 text-muted-foreground" />
                  <h4 className="font-medium">
                    Shared Files
                    {attachments.length > 0 && (
                      <span className="text-muted-foreground font-normal ml-1">
                        ({attachments.length})
                      </span>
                    )}
                  </h4>
                </div>
                <div className="flex items-center gap-1">
                  {/* Gallery view button */}
                  {attachments.length > 0 && (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 w-7 p-0"
                          onClick={() => setShowGallery(true)}
                        >
                          <Grid3X3 className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>View Gallery</p>
                      </TooltipContent>
                    </Tooltip>
                  )}

                  {/* Multi-select toggle */}
                  {attachments.length > 1 && (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant={selectMode ? "secondary" : "ghost"}
                          size="sm"
                          className="h-7 w-7 p-0"
                          onClick={() => {
                            setSelectMode(!selectMode)
                            if (selectMode) {
                              setSelectedAttachments(new Set())
                            }
                          }}
                        >
                          <CheckSquare className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>{selectMode ? 'Cancel selection' : 'Select multiple'}</p>
                      </TooltipContent>
                    </Tooltip>
                  )}

                  {!selectMode && attachments.length > 3 && !showAllAttachments && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setShowAllAttachments(true)}
                    >
                      View all
                    </Button>
                  )}
                  {!selectMode && showAllAttachments && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setShowAllAttachments(false)}
                    >
                      Show less
                    </Button>
                  )}
                </div>
              </div>

              {/* Multi-select action bar */}
              {selectMode && selectedAttachments.size > 0 && (
                <div className="flex items-center justify-between p-2 bg-primary/10 rounded-lg">
                  <span className="text-sm font-medium">
                    {selectedAttachments.size} selected
                  </span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setSelectedAttachments(new Set())}
                    >
                      Clear
                    </Button>
                    <Button
                      variant="default"
                      size="sm"
                      onClick={() => setShowChatSelector(true)}
                    >
                      <Forward className="h-4 w-4 mr-1" />
                      Forward
                    </Button>
                  </div>
                </div>
              )}

              <div className="space-y-1">
                {attachmentsLoading ? (
                  <div className="flex items-center justify-center py-4">
                    <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                    <span className="ml-2 text-sm text-muted-foreground">Loading files...</span>
                  </div>
                ) : attachmentError ? (
                  <div className="text-sm text-muted-foreground text-center py-4">
                    {attachmentError}
                  </div>
                ) : attachments.length === 0 ? (
                  <div className="text-sm text-muted-foreground text-center py-4">
                    No files shared yet
                  </div>
                ) : (
                  <>
                    {(showAllAttachments ? attachments : attachments.slice(0, 3)).map(renderFileItem)}
                  </>
                )}
              </div>
            </div>
          </div>
        </ScrollArea>
      </div>

      {/* Remove Member Confirmation Dialog */}
      <AlertDialog open={!!showRemoveMemberConfirm} onOpenChange={() => setShowRemoveMemberConfirm(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove Member?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove this member from the channel?
              They will no longer be able to see messages or participate in this channel.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isRemovingMember}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => showRemoveMemberConfirm && handleRemoveMember(showRemoveMemberConfirm)}
              disabled={isRemovingMember}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isRemovingMember && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Remove Member
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Channel Settings Modal */}
      {channel && (
        <ChannelSettingsModal
          isOpen={showChannelSettings}
          onClose={() => setShowChannelSettings(false)}
          channel={channel}
        />
      )}

      {/* Chat Selector for forwarding */}
      <ChatSelectorModal
        isOpen={showChatSelector}
        onClose={() => {
          setShowChatSelector(false)
          setSelectedAttachments(new Set())
          setSelectMode(false)
        }}
        onSelect={handleForwardSelected}
        title="Forward Attachments"
        description={`Forward ${selectedAttachments.size} file(s) to selected chats`}
        multiSelect={true}
      />

      {/* Attachment Gallery */}
      {channel && (
        <AttachmentGallery
          channelId={channel.id}
          isOpen={showGallery}
          onClose={() => setShowGallery(false)}
          onForward={(atts) => {
            setSelectedAttachments(new Set(atts.map(a => a.id)))
            setShowChatSelector(true)
            setShowGallery(false)
          }}
        />
      )}
    </TooltipProvider>
  )
}
