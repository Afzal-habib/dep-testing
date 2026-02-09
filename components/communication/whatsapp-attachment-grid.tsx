"use client"

import { useState, useCallback, memo } from "react"
import Image from "next/image"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogTitle,
} from "@/components/ui/dialog"
import { Checkbox } from "@/components/ui/checkbox"
import { cn } from "@/lib/utils"
import {
  Play,
  Download,
  X,
  ChevronLeft,
  ChevronRight,
  FileText,
  FileAudio,
  FileArchive,
  FileCode,
  File,
  Share2,
  Forward,
  Check,
} from "lucide-react"
import { IAttachment } from "@/types/communication"
import { formatFileSize, formatDuration } from "@/lib/utils/file-preview"
import { AttachmentShareMenu } from "./attachment-share-menu"
import { communicationLogger as logger } from "@/lib/logger"
import { useToast } from "@/hooks/use-toast"

interface WhatsAppAttachmentGridProps {
  attachments: IAttachment[]
  className?: string
  maxVisible?: number
  onViewAll?: () => void
  onForward?: (attachments: IAttachment[]) => void
  selectable?: boolean
  selectedIds?: Set<string>
  onSelectionChange?: (selectedIds: Set<string>) => void
}

interface MediaViewerProps {
  attachments: IAttachment[]
  initialIndex: number
  isOpen: boolean
  onClose: () => void
  onDownload?: (attachment: IAttachment) => void
  onForward?: (attachments: IAttachment[]) => void
}

// Get file category
const getFileCategory = (mimeType?: string | null, fileName?: string): string => {
  if (!mimeType && !fileName) return 'file'

  const type = mimeType?.toLowerCase() || ''
  const name = fileName?.toLowerCase() || ''

  if (type.startsWith('image/')) return 'image'
  if (type.startsWith('video/')) return 'video'
  if (type.startsWith('audio/')) return 'audio'
  if (type === 'application/pdf' || name.endsWith('.pdf')) return 'pdf'
  if (type.includes('zip') || type.includes('rar') || type.includes('7z') || type.includes('tar')) return 'archive'
  if (type.includes('javascript') || type.includes('typescript') || type.includes('json') ||
    name.endsWith('.js') || name.endsWith('.ts') || name.endsWith('.jsx') || name.endsWith('.tsx')) return 'code'

  return 'document'
}

// Get file icon component
const getFileIcon = (category: string) => {
  switch (category) {
    case 'pdf': return FileText
    case 'audio': return FileAudio
    case 'archive': return FileArchive
    case 'code': return FileCode
    default: return File
  }
}

/**
 * WhatsApp-style Media Viewer with gallery navigation
 */
export const MediaViewer = memo(function MediaViewer({
  attachments,
  initialIndex,
  isOpen,
  onClose,
  onDownload,
  onForward
}: MediaViewerProps) {
  const [currentIndex, setCurrentIndex] = useState(initialIndex)

  const currentAttachment = attachments[currentIndex]
  const category = getFileCategory(currentAttachment?.file_type, currentAttachment?.file_name)

  const goToPrevious = useCallback(() => {
    setCurrentIndex(prev => prev > 0 ? prev - 1 : attachments.length - 1)
  }, [attachments.length])

  const goToNext = useCallback(() => {
    setCurrentIndex(prev => prev < attachments.length - 1 ? prev + 1 : 0)
  }, [attachments.length])

  // Reset index when opening
  const handleOpenChange = useCallback((open: boolean) => {
    if (open) {
      setCurrentIndex(initialIndex)
    } else {
      onClose()
    }
  }, [initialIndex, onClose])

  if (!currentAttachment) return null

  return (
    <Dialog open={isOpen} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-5xl max-h-[95vh] p-0 overflow-hidden bg-black/95">
        <DialogTitle className="sr-only">{currentAttachment.file_name}</DialogTitle>

        {/* Close button */}
        <Button
          variant="ghost"
          size="sm"
          className="absolute top-4 right-4 z-50 h-10 w-10 p-0 bg-black/50 hover:bg-black/70 text-white rounded-full"
          onClick={onClose}
        >
          <X className="h-5 w-5" />
        </Button>

        {/* Navigation arrows */}
        {attachments.length > 1 && (
          <>
            <Button
              variant="ghost"
              size="sm"
              className="absolute left-4 top-1/2 -translate-y-1/2 z-50 h-12 w-12 p-0 bg-black/50 hover:bg-black/70 text-white rounded-full"
              onClick={goToPrevious}
            >
              <ChevronLeft className="h-6 w-6" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="absolute right-4 top-1/2 -translate-y-1/2 z-50 h-12 w-12 p-0 bg-black/50 hover:bg-black/70 text-white rounded-full"
              onClick={goToNext}
            >
              <ChevronRight className="h-6 w-6" />
            </Button>
          </>
        )}

        {/* Media content */}
        <div className="flex items-center justify-center min-h-[60vh] max-h-[80vh] p-4">
          {category === 'image' && currentAttachment.file_url && (
            <Image
              src={currentAttachment.file_url}
              alt={currentAttachment.file_name}
              width={1200}
              height={800}
              className="max-w-full max-h-[75vh] object-contain"
              priority
            />
          )}
          {category === 'video' && currentAttachment.file_url && (
            <video
              src={currentAttachment.file_url}
              controls
              className="max-w-full max-h-[75vh]"
              autoPlay
            />
          )}
        </div>

        {/* Bottom bar */}
        <div className="absolute bottom-0 left-0 right-0 p-4 bg-gradient-to-t from-black/90 to-transparent">
          <div className="flex items-center justify-between text-white">
            <div className="flex-1 min-w-0">
              <p className="font-medium truncate">{currentAttachment.file_name}</p>
              <p className="text-sm opacity-70">
                {formatFileSize(currentAttachment.file_size)}
                {attachments.length > 1 && ` • ${currentIndex + 1} of ${attachments.length}`}
              </p>
            </div>
            <div className="flex items-center gap-2">
              {onForward && (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => onForward([currentAttachment])}
                >
                  <Forward className="h-4 w-4 mr-2" />
                  Forward
                </Button>
              )}
              {onDownload && (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => onDownload(currentAttachment)}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Download
                </Button>
              )}
            </div>
          </div>

          {/* Thumbnail strip for multiple attachments */}
          {attachments.length > 1 && (
            <div className="flex gap-2 mt-4 overflow-x-auto pb-2">
              {attachments.map((att, index) => {
                const attCategory = getFileCategory(att.file_type, att.file_name)
                const isMedia = attCategory === 'image' || attCategory === 'video'

                return (
                  <button
                    key={att.id}
                    onClick={() => setCurrentIndex(index)}
                    className={cn(
                      "relative shrink-0 w-16 h-16 rounded-lg overflow-hidden border-2 transition-all",
                      currentIndex === index
                        ? "border-white scale-105"
                        : "border-transparent opacity-60 hover:opacity-100"
                    )}
                  >
                    {isMedia && att.file_url ? (
                      <Image
                        src={att.file_url}
                        alt={att.file_name}
                        fill
                        className="object-cover"
                      />
                    ) : (
                      <div className="w-full h-full bg-muted flex items-center justify-center">
                        {(() => {
                          const Icon = getFileIcon(attCategory)
                          return <Icon className="h-6 w-6 text-muted-foreground" />
                        })()}
                      </div>
                    )}
                    {attCategory === 'video' && (
                      <div className="absolute inset-0 flex items-center justify-center bg-black/30">
                        <Play className="h-4 w-4 text-white" fill="white" />
                      </div>
                    )}
                  </button>
                )
              })}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
})

/**
 * WhatsApp-style attachment grid with 2x2 layout and +N overlay
 * Supports up to 30 attachments with smart grouping
 */
export const WhatsAppAttachmentGrid = memo(function WhatsAppAttachmentGrid({
  attachments,
  className,
  maxVisible = 4,
  onViewAll,
  onForward,
  selectable = false,
  selectedIds = new Set(),
  onSelectionChange
}: WhatsAppAttachmentGridProps) {
  const [viewerOpen, setViewerOpen] = useState(false)
  const [viewerIndex, setViewerIndex] = useState(0)
  const { toast } = useToast()

  if (!attachments.length) return null

  const visibleAttachments = attachments.slice(0, maxVisible)
  const hiddenCount = attachments.length - maxVisible

  // Filter media attachments for viewer
  const mediaAttachments = attachments.filter(a => {
    const cat = getFileCategory(a.file_type, a.file_name)
    return cat === 'image' || cat === 'video'
  })

  const handleMediaClick = (attachment: IAttachment, index: number) => {
    if (selectable) {
      // Toggle selection in select mode
      const newSelected = new Set(selectedIds)
      if (newSelected.has(attachment.id)) {
        newSelected.delete(attachment.id)
      } else {
        newSelected.add(attachment.id)
      }
      onSelectionChange?.(newSelected)
      return
    }

    // Find index in media attachments
    const mediaIndex = mediaAttachments.findIndex(a => a.id === attachment.id)
    if (mediaIndex !== -1) {
      setViewerIndex(mediaIndex)
      setViewerOpen(true)
    }
  }

  const handleDownload = useCallback(async (attachment: IAttachment) => {
    if (!attachment.file_url) return

    try {
      const response = await fetch(`/api/communication/attachments?download=${attachment.id}`)
      const data = await response.json()

      if (data.success && data.downloadUrl) {
        const a = document.createElement('a')
        a.href = data.downloadUrl
        a.download = attachment.file_name
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
      }
    } catch (error) {
      logger.error('Download failed:', error)
      toast({
        title: "Download Failed",
        description: "Could not download the file. Please try again.",
        variant: "destructive"
      })
    }
  }, [toast])

  // Render a single grid item
  const renderGridItem = (attachment: IAttachment, index: number, totalVisible: number) => {
    const category = getFileCategory(attachment.file_type, attachment.file_name)
    const isMedia = category === 'image' || category === 'video'
    const isSelected = selectedIds.has(attachment.id)
    const isLastVisible = index === totalVisible - 1
    const showOverlay = isLastVisible && hiddenCount > 0

    // Determine grid span based on total count and position
    let spanClass = ""
    if (totalVisible === 1) {
      spanClass = "col-span-2 row-span-2"
    } else if (totalVisible === 2) {
      spanClass = "row-span-2"
    } else if (totalVisible === 3 && index === 0) {
      spanClass = "row-span-2"
    }

    return (
      <div
        key={attachment.id}
        className={cn(
          "relative overflow-hidden rounded-lg cursor-pointer group",
          spanClass,
          isSelected && "ring-2 ring-primary ring-offset-2"
        )}
        onClick={() => handleMediaClick(attachment, index)}
      >
        {/* Selection checkbox */}
        {selectable && (
          <div className="absolute top-2 left-2 z-20">
            <div className={cn(
              "h-6 w-6 rounded-full border-2 flex items-center justify-center transition-colors",
              isSelected
                ? "bg-primary border-primary"
                : "bg-black/30 border-white"
            )}>
              {isSelected && <Check className="h-4 w-4 text-white" />}
            </div>
          </div>
        )}

        {isMedia && attachment.file_url ? (
          <>
            <div className="relative aspect-square">
              <Image
                src={attachment.file_url}
                alt={attachment.file_name}
                fill
                className="object-cover transition-transform group-hover:scale-105"
              />
            </div>

            {/* Video duration badge */}
            {category === 'video' && (
              <>
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="h-10 w-10 rounded-full bg-black/50 flex items-center justify-center">
                    <Play className="h-5 w-5 text-white ml-0.5" fill="white" />
                  </div>
                </div>
                <div className="absolute bottom-1.5 left-1.5 px-1 py-0.5 bg-black/70 rounded text-[10px] text-white flex items-center gap-0.5">
                  <Play className="h-2.5 w-2.5" fill="white" />
                  {attachment.durationSeconds
                    ? formatDuration(attachment.durationSeconds)
                    : '0:00'
                  }
                </div>
              </>
            )}
          </>
        ) : (
          // Non-media file card
          <div className="aspect-square bg-muted flex flex-col items-center justify-center p-2">
            {(() => {
              const Icon = getFileIcon(category)
              return <Icon className="h-8 w-8 text-muted-foreground mb-1" />
            })()}
            <p className="text-[10px] text-center text-muted-foreground truncate max-w-full px-1">
              {attachment.file_name}
            </p>
            <p className="text-[10px] text-muted-foreground">
              {formatFileSize(attachment.file_size)}
            </p>
          </div>
        )}

        {/* +N overlay for hidden items */}
        {showOverlay && (
          <div
            className="absolute inset-0 bg-black/60 flex items-center justify-center"
            onClick={(e) => {
              e.stopPropagation()
              onViewAll?.()
            }}
          >
            <span className="text-white text-2xl font-bold">+{hiddenCount}</span>
          </div>
        )}

        {/* Hover actions (when not in select mode) */}
        {!selectable && !showOverlay && (
          <div className="absolute top-1.5 right-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
            <AttachmentShareMenu
              attachment={attachment}
              onForward={onForward ? (att) => onForward([att]) : undefined}
              variant="icon"
              size="sm"
              className="h-7 w-7 bg-black/50 hover:bg-black/70 text-white"
            />
          </div>
        )}
      </div>
    )
  }

  // Determine grid layout based on visible count
  const getGridClass = () => {
    const count = visibleAttachments.length
    if (count === 1) return "grid-cols-1"
    return "grid-cols-2"
  }

  return (
    <>
      <div className={cn(
        "grid gap-0.5 rounded-lg overflow-hidden max-w-[280px]",
        getGridClass(),
        className
      )}>
        {visibleAttachments.map((attachment, index) =>
          renderGridItem(attachment, index, visibleAttachments.length)
        )}
      </div>

      {/* Media viewer */}
      <MediaViewer
        attachments={mediaAttachments}
        initialIndex={viewerIndex}
        isOpen={viewerOpen}
        onClose={() => setViewerOpen(false)}
        onDownload={handleDownload}
        onForward={onForward}
      />
    </>
  )
})

export default WhatsAppAttachmentGrid
