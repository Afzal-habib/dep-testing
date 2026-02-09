"use client"

import { useState, useEffect, useCallback } from "react"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Trash2,
  RotateCcw,
  AlertTriangle,
  Clock,
  Loader2,
  ChevronDown,
  MessageSquare
} from "lucide-react"
import { cn } from "@/lib/utils"
import { formatDistanceToNow } from "date-fns"
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
import { ScrollArea } from "@/components/ui/scroll-area"
import CustomModal from "@/components/shared/custom-modal"
import { useCommunications } from "@/hooks/use-communications"
import HtmlTextRenderer from "../shared/html-text-renderer"
import { AttachmentGrid } from "./attachment-preview"

interface TrashViewProps {
  isOpen: boolean
  onClose: () => void
  className?: string
}

export function TrashView({
  isOpen,
  onClose,
  className
}: TrashViewProps) {
  const {
    trashedMessages,
    trashedMessagesLoading,
    trashedMessagesPagination,
    fetchTrashedMessages,
    restoreFromTrash,
    permanentlyDelete,
    actionLoading
  } = useCommunications()

  const [selectedMessage, setSelectedMessage] = useState<string | null>(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [showRestoreConfirm, setShowRestoreConfirm] = useState(false)
  const [messageToAction, setMessageToAction] = useState<string | null>(null)
  const [loadingMessageId, setLoadingMessageId] = useState<string | null>(null)

  // Fetch trashed messages when dialog opens
  useEffect(() => {
    if (isOpen) {
      fetchTrashedMessages()
    }
  }, [isOpen, fetchTrashedMessages])

  // Load more handler
  const handleLoadMore = useCallback(async () => {
    if (trashedMessagesPagination.hasMore && !trashedMessagesLoading) {
      const nextOffset = trashedMessages.length
      await fetchTrashedMessages({ 
        limit: trashedMessagesPagination.limit,
        offset: nextOffset 
      })
    }
  }, [trashedMessagesPagination, trashedMessagesLoading, trashedMessages.length, fetchTrashedMessages])

  // Restore handler
  const handleRestore = useCallback(async () => {
    if (!messageToAction) return
    
    setLoadingMessageId(messageToAction)
    const result = await restoreFromTrash(messageToAction)
    setLoadingMessageId(null)
    
    if (result.success) {
      setShowRestoreConfirm(false)
      setMessageToAction(null)
    }
  }, [messageToAction, restoreFromTrash])

  // Permanent delete handler
  const handlePermanentDelete = useCallback(async () => {
    if (!messageToAction) return
    
    setLoadingMessageId(messageToAction)
    const result = await permanentlyDelete(messageToAction)
    setLoadingMessageId(null)
    
    if (result.success) {
      setShowDeleteConfirm(false)
      setMessageToAction(null)
    }
  }, [messageToAction, permanentlyDelete])

  // Get avatar initials
  const getInitials = (name: string | undefined) => {
    if (!name) return "?"
    return name
      .split(" ")
      .map(n => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2)
  }

  // Get expiry status color
  const getExpiryStatusColor = (daysRemaining: number) => {
    if (daysRemaining <= 3) return "text-red-500 bg-red-500/10"
    if (daysRemaining <= 7) return "text-amber-500 bg-amber-500/10"
    return "text-muted-foreground bg-muted"
  }

  // Get expiry badge variant
  const getExpiryBadgeVariant = (daysRemaining: number): "destructive" | "default" | "secondary" => {
    if (daysRemaining <= 3) return "destructive"
    if (daysRemaining <= 7) return "default"
    return "secondary"
  }

  return (
    <>
      <CustomModal
        isOpen={isOpen}
        onClose={onClose}
        title="Message Trash"
        modalSize="lg"
        className={className}
        headerActions={
          <div className="flex items-center gap-2 text-muted-foreground">
            <Trash2 className="h-4 w-4" />
            <span className="text-xs">
              {trashedMessages.length} message{trashedMessages.length !== 1 ? "s" : ""}
            </span>
          </div>
        }
        actions={
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        }
      >
        <div className="mb-2 text-sm text-muted-foreground">
          Messages are kept for 30 days before being permanently deleted.
        </div>

        <ScrollArea className="h-[50vh] pr-4">
          {trashedMessagesLoading && trashedMessages.length === 0 ? (
            <div className="flex items-center justify-center h-full py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : trashedMessages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full py-12 text-center">
              <MessageSquare className="h-12 w-12 text-muted-foreground/40 mb-4" />
              <p className="text-muted-foreground font-medium">No messages in trash</p>
              <p className="text-sm text-muted-foreground/60 mt-1">
                Deleted messages will appear here
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {trashedMessages.map((message) => (
                <div
                  key={message.id}
                  className={cn(
                    "p-4 rounded-lg border transition-colors cursor-pointer",
                    selectedMessage === message.id 
                      ? "border-primary bg-accent/50" 
                      : "border-border hover:border-primary/50 hover:bg-accent/30",
                    message.is_expiring_soon && "border-amber-500/30"
                  )}
                  onClick={() => setSelectedMessage(
                    selectedMessage === message.id ? null : message.id
                  )}
                >
                  {/* Message Header */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <Avatar className="h-9 w-9 shrink-0">
                        <AvatarImage 
                          src={message.sender_avatar || message.sender?.avatar} 
                          alt={message.sender_name || message.sender?.name || "User"} 
                        />
                        <AvatarFallback>
                          {getInitials(message.sender_name || message.sender?.name)}
                        </AvatarFallback>
                      </Avatar>
                      <div className="min-w-0 flex-1">
                        <p className="font-medium text-sm truncate">
                          {message.sender_name || message.sender?.name || "Unknown"}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Deleted {formatDistanceToNow(new Date(message.trashed_at), { addSuffix: true })}
                        </p>
                      </div>
                    </div>
                    
                    {/* Expiry Badge */}
                    <Badge 
                      variant={getExpiryBadgeVariant(message.days_remaining)}
                      className={cn(
                        "shrink-0 text-xs",
                        message.days_remaining <= 7 && "animate-pulse"
                      )}
                    >
                      <Clock className="h-3 w-3 mr-1" />
                      {message.days_remaining} days left
                    </Badge>
                  </div>

                  {/* Message Content Preview */}
                  <div className="mt-3 pl-12">
                    <div className="text-sm text-muted-foreground line-clamp-2">
                      <HtmlTextRenderer 
                        content={message.content} 
                        className="prose-sm" 
                      />
                    </div>
                    
                    {/* Attachments Preview */}
                    {message.attachments && message.attachments.length > 0 && (
                      <div className="mt-2">
                        <AttachmentGrid
                          attachments={message.attachments}
                          maxVisible={3}
                          className="gap-1"
                        />
                      </div>
                    )}
                    
                    {/* Trash reason if provided */}
                    {message.trash_reason && (
                      <p className="text-xs text-muted-foreground/60 mt-1 italic">
                        Reason: {message.trash_reason}
                      </p>
                    )}
                  </div>

                  {/* Expiry Warning */}
                  {message.is_expiring_soon && (
                    <div className={cn(
                      "mt-3 pl-12 flex items-center gap-2 text-xs rounded-md py-1 px-2 w-fit",
                      getExpiryStatusColor(message.days_remaining)
                    )}>
                      <AlertTriangle className="h-3 w-3" />
                      {message.days_remaining <= 1 
                        ? "Expires tomorrow!" 
                        : `Expires in ${message.days_remaining} days`
                      }
                    </div>
                  )}

                  {/* Action Buttons - Show when selected */}
                  {selectedMessage === message.id && (
                    <div className="mt-4 pl-12 flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-green-600 hover:text-green-700 hover:bg-green-50 dark:hover:bg-green-950"
                        disabled={loadingMessageId === message.id}
                        onClick={(e) => {
                          e.stopPropagation()
                          setMessageToAction(message.id)
                          setShowRestoreConfirm(true)
                        }}
                      >
                        {loadingMessageId === message.id ? (
                          <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                        ) : (
                          <RotateCcw className="h-4 w-4 mr-1" />
                        )}
                        Restore
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-950"
                        disabled={loadingMessageId === message.id}
                        onClick={(e) => {
                          e.stopPropagation()
                          setMessageToAction(message.id)
                          setShowDeleteConfirm(true)
                        }}
                      >
                        {loadingMessageId === message.id ? (
                          <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                        ) : (
                          <Trash2 className="h-4 w-4 mr-1" />
                        )}
                        Delete Forever
                      </Button>
                    </div>
                  )}
                </div>
              ))}

              {/* Load More Button */}
              {trashedMessagesPagination.hasMore && (
                <div className="flex justify-center pt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleLoadMore}
                    disabled={trashedMessagesLoading}
                  >
                    {trashedMessagesLoading ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Loading...
                      </>
                    ) : (
                      <>
                        <ChevronDown className="h-4 w-4 mr-2" />
                        Load More
                      </>
                    )}
                  </Button>
                </div>
              )}
            </div>
          )}
        </ScrollArea>
      </CustomModal>

      {/* Restore Confirmation Dialog */}
      <AlertDialog open={showRestoreConfirm} onOpenChange={setShowRestoreConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Restore Message</AlertDialogTitle>
            <AlertDialogDescription>
              This message will be restored to its original conversation. 
              Do you want to continue?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={loadingMessageId !== null}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleRestore}
              disabled={loadingMessageId !== null}
              className="bg-green-600 hover:bg-green-700"
            >
              {loadingMessageId ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Restoring...
                </>
              ) : (
                <>
                  <RotateCcw className="h-4 w-4 mr-2" />
                  Restore
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Permanent Delete Confirmation Dialog */}
      <AlertDialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="text-red-600 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Permanently Delete Message
            </AlertDialogTitle>
            <AlertDialogDescription>
              <span className="font-semibold text-foreground">This action cannot be undone.</span>
              {" "}The message will be permanently deleted and cannot be recovered.
              Are you sure you want to continue?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={loadingMessageId !== null}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handlePermanentDelete}
              disabled={loadingMessageId !== null}
              className="bg-red-600 hover:bg-red-700"
            >
              {loadingMessageId ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Deleting...
                </>
              ) : (
                <>
                  <Trash2 className="h-4 w-4 mr-2" />
                  Delete Forever
                </>
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

export default TrashView
