"use client"

import { useState, useCallback, memo } from "react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
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
  Share2,
  Download,
  Link2,
  Forward,
  Mail,
  Copy,
  Check,
  ExternalLink,
  MoreVertical,
  Loader2,
} from "lucide-react"
import { IAttachment } from "@/types/communication"
import { useChatAttachments } from "@/hooks/use-chat-attachments"
import { useToast } from "@/hooks/use-toast"

export type ShareMethod = 'copy-link' | 'download' | 'forward' | 'email' | 'native-share' | 'open'

interface AttachmentShareMenuProps {
  attachment: IAttachment
  onForward?: (attachment: IAttachment) => void
  variant?: 'button' | 'icon' | 'dropdown'
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

/**
 * Share menu for attachments with multiple sharing options
 */
export const AttachmentShareMenu = memo(function AttachmentShareMenu({
  attachment,
  onForward,
  variant = 'icon',
  size = 'md',
  className
}: AttachmentShareMenuProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const [showEmailDialog, setShowEmailDialog] = useState(false)
  
  const { downloadAttachment } = useChatAttachments()
  const { toast } = useToast()

  // Size classes
  const sizeClasses = {
    sm: "h-6 w-6",
    md: "h-8 w-8", 
    lg: "h-10 w-10"
  }

  const iconSizes = {
    sm: "h-3 w-3",
    md: "h-4 w-4",
    lg: "h-5 w-5"
  }

  // Check if native share is supported
  const isNativeShareSupported = typeof navigator !== 'undefined' && !!navigator.share

  // Copy link to clipboard
  const handleCopyLink = useCallback(async () => {
    if (!attachment.file_url) {
      toast({
        title: "Error",
        description: "File URL not available",
        variant: "destructive"
      })
      return
    }

    try {
      setIsLoading(true)
      
      // Get a fresh presigned URL from the API
      const response = await fetch(`/api/communication/attachments?download=${attachment.id}`)
      const data = await response.json()
      
      if (data.success && data.downloadUrl) {
        await navigator.clipboard.writeText(data.downloadUrl)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        
        toast({
          title: "Link Copied",
          description: "The download link has been copied to your clipboard (valid for 1 hour)",
        })
      } else {
        // Fallback to file_url
        await navigator.clipboard.writeText(attachment.file_url)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        
        toast({
          title: "Link Copied",
          description: "The file link has been copied to your clipboard",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to copy link",
        variant: "destructive"
      })
    } finally {
      setIsLoading(false)
    }
  }, [attachment, toast])

  // Download file
  const handleDownload = useCallback(async () => {
    try {
      setIsLoading(true)
      await downloadAttachment(attachment)
    } finally {
      setIsLoading(false)
    }
  }, [attachment, downloadAttachment])

  // Forward to chat
  const handleForward = useCallback(() => {
    if (onForward) {
      onForward(attachment)
    }
    setIsOpen(false)
  }, [attachment, onForward])

  // Open in new tab
  const handleOpenExternal = useCallback(() => {
    if (attachment.file_url) {
      window.open(attachment.file_url, '_blank')
    }
  }, [attachment])

  // Native share (mobile)
  const handleNativeShare = useCallback(async () => {
    if (!isNativeShareSupported) return

    try {
      await navigator.share({
        title: attachment.file_name,
        url: attachment.file_url || undefined,
      })
    } catch (error) {
      // User cancelled or share failed
      if ((error as Error).name !== 'AbortError') {
        toast({
          title: "Share Failed",
          description: "Could not share the file",
          variant: "destructive"
        })
      }
    }
  }, [attachment, isNativeShareSupported, toast])

  // Send via email
  const handleEmailShare = useCallback(() => {
    const subject = encodeURIComponent(`Sharing: ${attachment.file_name}`)
    const body = encodeURIComponent(
      `I'm sharing a file with you:\n\n` +
      `File: ${attachment.file_name}\n` +
      `Link: ${attachment.file_url || 'Link not available'}\n\n` +
      `This link will expire in 1 hour.`
    )
    window.open(`mailto:?subject=${subject}&body=${body}`, '_blank')
    setShowEmailDialog(false)
  }, [attachment])

  // Render trigger based on variant
  const renderTrigger = () => {
    switch (variant) {
      case 'button':
        return (
          <Button variant="outline" size="sm" className={className}>
            <Share2 className={cn(iconSizes[size], "mr-2")} />
            Share
          </Button>
        )
      case 'dropdown':
        return (
          <Button variant="ghost" size="icon" className={cn(sizeClasses[size], className)}>
            <MoreVertical className={iconSizes[size]} />
          </Button>
        )
      case 'icon':
      default:
        return (
          <Button 
            variant="ghost" 
            size="icon" 
            className={cn(sizeClasses[size], className)}
          >
            <Share2 className={iconSizes[size]} />
          </Button>
        )
    }
  }

  return (
    <>
      <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
        <DropdownMenuTrigger asChild>
          {renderTrigger()}
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-48">
          {/* Copy Link */}
          <DropdownMenuItem 
            onClick={handleCopyLink}
            disabled={isLoading}
            className="gap-2"
          >
            {copied ? (
              <Check className="h-4 w-4 text-green-500" />
            ) : isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Link2 className="h-4 w-4" />
            )}
            {copied ? "Copied!" : "Copy Link"}
          </DropdownMenuItem>

          {/* Download */}
          <DropdownMenuItem 
            onClick={handleDownload}
            disabled={isLoading}
            className="gap-2"
          >
            <Download className="h-4 w-4" />
            Download
          </DropdownMenuItem>

          {/* Open in new tab */}
          {attachment.file_url && (
            <DropdownMenuItem 
              onClick={handleOpenExternal}
              className="gap-2"
            >
              <ExternalLink className="h-4 w-4" />
              Open in New Tab
            </DropdownMenuItem>
          )}

          <DropdownMenuSeparator />

          {/* Forward to Chat */}
          {onForward && (
            <DropdownMenuItem 
              onClick={handleForward}
              className="gap-2"
            >
              <Forward className="h-4 w-4" />
              Forward to Chat
            </DropdownMenuItem>
          )}

          {/* Email */}
          <DropdownMenuItem 
            onClick={() => setShowEmailDialog(true)}
            className="gap-2"
          >
            <Mail className="h-4 w-4" />
            Send via Email
          </DropdownMenuItem>

          {/* Native Share (mobile only) */}
          {isNativeShareSupported && (
            <DropdownMenuItem 
              onClick={handleNativeShare}
              className="gap-2"
            >
              <Share2 className="h-4 w-4" />
              Share...
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Email Share Dialog */}
      <Dialog open={showEmailDialog} onOpenChange={setShowEmailDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Share via Email</DialogTitle>
            <DialogDescription>
              This will open your email client with a pre-filled message containing the file link.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <div className="rounded-lg border p-3 bg-muted/30">
              <p className="text-sm font-medium">{attachment.file_name}</p>
              <p className="text-xs text-muted-foreground mt-1">
                Link will be valid for 1 hour
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowEmailDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleEmailShare}>
              <Mail className="h-4 w-4 mr-2" />
              Open Email Client
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
})

interface AttachmentBatchActionsProps {
  selectedAttachments: IAttachment[]
  onDownloadAll?: () => void
  onForwardAll?: () => void
  onCopyLinks?: () => void
  onDeselectAll?: () => void
  className?: string
}

/**
 * Batch actions bar for selected attachments
 */
export const AttachmentBatchActions = memo(function AttachmentBatchActions({
  selectedAttachments,
  onDownloadAll,
  onForwardAll,
  onCopyLinks,
  onDeselectAll,
  className
}: AttachmentBatchActionsProps) {
  const count = selectedAttachments.length

  if (count === 0) return null

  return (
    <div className={cn(
      "flex items-center justify-between gap-4 p-3 bg-primary/10 border rounded-lg",
      className
    )}>
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium">
          {count} file{count !== 1 ? 's' : ''} selected
        </span>
        {onDeselectAll && (
          <Button variant="ghost" size="sm" onClick={onDeselectAll}>
            Clear
          </Button>
        )}
      </div>

      <div className="flex items-center gap-2">
        {onCopyLinks && (
          <Button variant="outline" size="sm" onClick={onCopyLinks}>
            <Copy className="h-4 w-4 mr-2" />
            Copy Links
          </Button>
        )}
        {onDownloadAll && (
          <Button variant="outline" size="sm" onClick={onDownloadAll}>
            <Download className="h-4 w-4 mr-2" />
            Download All
          </Button>
        )}
        {onForwardAll && (
          <Button size="sm" onClick={onForwardAll}>
            <Forward className="h-4 w-4 mr-2" />
            Forward All
          </Button>
        )}
      </div>
    </div>
  )
})

export default AttachmentShareMenu
