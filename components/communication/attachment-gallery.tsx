"use client"

import { useState, useCallback, useMemo, memo, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { cn } from "@/lib/utils"
import {
  X,
  Search,
  Image as ImageIcon,
  FileText,
  Link2,
  Download,
  Forward,
  Share2,
  ChevronLeft,
  ChevronRight,
  Play,
  Loader2,
  Music,
  Film,
  File,
} from "lucide-react"
import { IAttachment } from "@/types/communication"
import { useChatAttachments } from "@/hooks/use-chat-attachments"
import {
  getFileCategory,
  formatFileSize,
  formatDuration,
  getCategoryColorClass,
  type FileCategory
} from "@/lib/utils/file-preview"
import { format, isToday, isYesterday, isThisWeek, isThisMonth } from "date-fns"
import Image from "next/image"
import { AttachmentShareMenu } from "./attachment-share-menu"
import { communicationLogger as logger } from "@/lib/logger"
import { useToast } from "@/hooks/use-toast"

type GalleryFilter = 'all' | 'media' | 'documents' | 'links'

interface AttachmentGroup {
  label: string
  date: string
  attachments: IAttachment[]
}

interface AttachmentGalleryProps {
  channelId: string
  isOpen: boolean
  onClose: () => void
  onForward?: (attachments: IAttachment[]) => void
  initialFilter?: GalleryFilter
}

/**
 * Group attachments by date
 */
function groupAttachmentsByDate(attachments: IAttachment[]): AttachmentGroup[] {
  const groups: Map<string, IAttachment[]> = new Map()

  attachments.forEach(att => {
    const date = new Date(att.created_at)
    let label: string
    let key: string

    if (isToday(date)) {
      label = 'Today'
      key = 'today'
    } else if (isYesterday(date)) {
      label = 'Yesterday'
      key = 'yesterday'
    } else if (isThisWeek(date)) {
      label = 'This Week'
      key = 'thisweek'
    } else if (isThisMonth(date)) {
      label = 'This Month'
      key = 'thismonth'
    } else {
      label = format(date, 'MMMM yyyy')
      key = format(date, 'yyyy-MM')
    }

    if (!groups.has(key)) {
      groups.set(key, [])
    }
    groups.get(key)!.push(att)
  })

  // Convert to array and sort
  return Array.from(groups.entries())
    .map(([key, atts]) => ({
      date: key,
      label: key === 'today' ? 'Today' 
           : key === 'yesterday' ? 'Yesterday'
           : key === 'thisweek' ? 'This Week'
           : key === 'thismonth' ? 'This Month'
           : atts[0] ? format(new Date(atts[0].created_at), 'MMMM yyyy') : key,
      attachments: atts.sort((a, b) => 
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      )
    }))
    .sort((a, b) => {
      const order = ['today', 'yesterday', 'thisweek', 'thismonth']
      const aIdx = order.indexOf(a.date)
      const bIdx = order.indexOf(b.date)
      if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx
      if (aIdx !== -1) return -1
      if (bIdx !== -1) return 1
      return b.date.localeCompare(a.date)
    })
}

/**
 * Filter attachments by type
 */
function filterAttachments(attachments: IAttachment[], filter: GalleryFilter): IAttachment[] {
  switch (filter) {
    case 'media':
      return attachments.filter(att => {
        const cat = getFileCategory(att.file_type, att.file_name)
        return cat === 'image' || cat === 'video' || cat === 'audio'
      })
    case 'documents':
      return attachments.filter(att => {
        const cat = getFileCategory(att.file_type, att.file_name)
        return cat === 'pdf' || cat === 'document' || cat === 'spreadsheet' || cat === 'archive'
      })
    case 'links':
      // Links would need special handling - for now return empty
      return []
    default:
      return attachments
  }
}

/**
 * Media Viewer - Full screen image/video viewer
 */
const MediaViewer = memo(function MediaViewer({
  attachments,
  initialIndex,
  isOpen,
  onClose,
  onDownload,
  onForward,
}: {
  attachments: IAttachment[]
  initialIndex: number
  isOpen: boolean
  onClose: () => void
  onDownload?: (attachment: IAttachment) => void
  onForward?: (attachment: IAttachment) => void
}) {
  const [currentIndex, setCurrentIndex] = useState(initialIndex)
  const current = attachments[currentIndex]
  const category = current ? getFileCategory(current.file_type, current.file_name) : 'other'

  useEffect(() => {
    setCurrentIndex(initialIndex)
  }, [initialIndex])

  // Keyboard navigation
  useEffect(() => {
    if (!isOpen) return

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowLeft') {
        setCurrentIndex(i => Math.max(0, i - 1))
      } else if (e.key === 'ArrowRight') {
        setCurrentIndex(i => Math.min(attachments.length - 1, i + 1))
      } else if (e.key === 'Escape') {
        onClose()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, attachments.length, onClose])

  if (!current) return null

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-[95vw] max-h-[95vh] p-0 bg-black/95 border-none">
        {/* Close button */}
        <Button
          variant="ghost"
          size="icon"
          className="absolute top-4 right-4 z-50 text-white hover:bg-white/20"
          onClick={onClose}
        >
          <X className="h-6 w-6" />
        </Button>

        {/* Navigation arrows */}
        {currentIndex > 0 && (
          <Button
            variant="ghost"
            size="icon"
            className="absolute left-4 top-1/2 -translate-y-1/2 z-50 text-white hover:bg-white/20 h-12 w-12"
            onClick={() => setCurrentIndex(i => i - 1)}
          >
            <ChevronLeft className="h-8 w-8" />
          </Button>
        )}
        {currentIndex < attachments.length - 1 && (
          <Button
            variant="ghost"
            size="icon"
            className="absolute right-4 top-1/2 -translate-y-1/2 z-50 text-white hover:bg-white/20 h-12 w-12"
            onClick={() => setCurrentIndex(i => i + 1)}
          >
            <ChevronRight className="h-8 w-8" />
          </Button>
        )}

        {/* Media content */}
        <div className="flex items-center justify-center w-full h-[80vh]">
          {category === 'image' && current.file_url && (
            <Image
              src={current.file_url}
              alt={current.file_name}
              fill
              className="object-contain"
              sizes="95vw"
            />
          )}
          {category === 'video' && current.file_url && (
            <video
              src={current.file_url}
              controls
              autoPlay
              className="max-w-full max-h-full"
            />
          )}
          {category === 'audio' && current.file_url && (
            <div className="flex flex-col items-center gap-4">
              <Music className="h-24 w-24 text-white/50" />
              <audio src={current.file_url} controls autoPlay />
            </div>
          )}
        </div>

        {/* Bottom bar */}
        <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent p-6">
          <div className="flex items-center justify-between text-white">
            <div>
              <p className="font-medium">{current.file_name}</p>
              <p className="text-sm text-white/70">
                {formatFileSize(current.file_size)} • {currentIndex + 1} of {attachments.length}
              </p>
            </div>
            <div className="flex items-center gap-2">
              {onForward && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="text-white hover:bg-white/20"
                  onClick={() => onForward(current)}
                >
                  <Forward className="h-5 w-5" />
                </Button>
              )}
              {onDownload && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="text-white hover:bg-white/20"
                  onClick={() => onDownload(current)}
                >
                  <Download className="h-5 w-5" />
                </Button>
              )}
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
})

/**
 * Gallery Grid Item
 */
const GalleryGridItem = memo(function GalleryGridItem({
  attachment,
  onClick,
  onForward,
}: {
  attachment: IAttachment
  onClick: () => void
  onForward?: (attachment: IAttachment) => void
}) {
  const category = getFileCategory(attachment.file_type, attachment.file_name)
  const colors = getCategoryColorClass(category)

  return (
    <div 
      className="relative aspect-square rounded-lg overflow-hidden cursor-pointer group"
      onClick={onClick}
    >
      {/* Image/Video thumbnail */}
      {(category === 'image' || category === 'video') && attachment.file_url ? (
        <>
          <Image
            src={attachment.file_url}
            alt={attachment.file_name}
            fill
            className="object-cover transition-transform group-hover:scale-105"
            sizes="150px"
          />
          {category === 'video' && (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-12 h-12 rounded-full bg-black/50 flex items-center justify-center">
                <Play className="h-6 w-6 text-white ml-1" />
              </div>
            </div>
          )}
        </>
      ) : (
        /* Document/Other file icon */
        <div className={cn("w-full h-full flex flex-col items-center justify-center gap-2", colors.bg)}>
          {category === 'audio' ? (
            <Music className={cn("h-8 w-8", colors.text)} />
          ) : category === 'pdf' ? (
            <FileText className={cn("h-8 w-8", colors.text)} />
          ) : (
            <File className={cn("h-8 w-8", colors.text)} />
          )}
          <span className={cn("text-xs font-medium uppercase", colors.text)}>
            {attachment.file_name.split('.').pop()?.slice(0, 4)}
          </span>
        </div>
      )}

      {/* Hover overlay */}
      <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors flex items-center justify-center opacity-0 group-hover:opacity-100">
        <div className="flex gap-2">
          <AttachmentShareMenu 
            attachment={attachment}
            onForward={onForward ? () => onForward(attachment) : undefined}
            variant="icon"
            size="sm"
          />
        </div>
      </div>

      {/* File size badge */}
      <div className="absolute bottom-1 right-1 px-1.5 py-0.5 bg-black/60 rounded text-[10px] text-white">
        {formatFileSize(attachment.file_size)}
      </div>
    </div>
  )
})

/**
 * Gallery List Item (for documents)
 */
const GalleryListItem = memo(function GalleryListItem({
  attachment,
  onClick,
  onForward,
}: {
  attachment: IAttachment
  onClick: () => void
  onForward?: (attachment: IAttachment) => void
}) {
  const category = getFileCategory(attachment.file_type, attachment.file_name)
  const colors = getCategoryColorClass(category)
  const { downloadAttachment } = useChatAttachments()

  const IconComponent = category === 'pdf' ? FileText 
    : category === 'audio' ? Music 
    : category === 'video' ? Film
    : File

  return (
    <div 
      className="flex items-center gap-3 p-3 rounded-lg hover:bg-muted/50 cursor-pointer group transition-colors"
      onClick={onClick}
    >
      {/* Icon */}
      <div className={cn("h-10 w-10 rounded-lg flex items-center justify-center shrink-0", colors.bg)}>
        <IconComponent className={cn("h-5 w-5", colors.text)} />
      </div>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">{attachment.file_name}</p>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>{formatFileSize(attachment.file_size)}</span>
          <span>•</span>
          <span>{format(new Date(attachment.created_at), 'MMM d, yyyy')}</span>
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={(e) => {
            e.stopPropagation()
            downloadAttachment(attachment)
          }}
        >
          <Download className="h-4 w-4" />
        </Button>
        <AttachmentShareMenu 
          attachment={attachment}
          onForward={onForward ? () => onForward(attachment) : undefined}
          variant="icon"
          size="sm"
        />
      </div>
    </div>
  )
})

/**
 * Main Attachment Gallery Component
 */
export const AttachmentGallery = memo(function AttachmentGallery({
  channelId,
  isOpen,
  onClose,
  onForward,
  initialFilter = 'all'
}: AttachmentGalleryProps) {
  const [filter, setFilter] = useState<GalleryFilter>(initialFilter)
  const [searchQuery, setSearchQuery] = useState("")
  const [attachments, setAttachments] = useState<IAttachment[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [viewerOpen, setViewerOpen] = useState(false)
  const [viewerIndex, setViewerIndex] = useState(0)
  const { toast } = useToast()

  const { fetchChannelAttachments, downloadAttachment } = useChatAttachments()

  // Fetch attachments when modal opens
  useEffect(() => {
    if (!isOpen || !channelId) return

    const loadAttachments = async () => {
      setIsLoading(true)
      try {
        const result = await fetchChannelAttachments({
          channelId,
          limit: 100
        })
        setAttachments(result.attachments)
      } catch (error) {
        logger.error('Failed to load gallery:', error)
        toast({
          title: "Failed to Load",
          description: "Could not load attachments. Please try again.",
          variant: "destructive"
        })
      } finally {
        setIsLoading(false)
      }
    }

    loadAttachments()
  }, [isOpen, channelId, fetchChannelAttachments])

  // Filter and search attachments
  const filteredAttachments = useMemo(() => {
    let result = filterAttachments(attachments, filter)
    
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      result = result.filter(att => 
        att.file_name.toLowerCase().includes(query)
      )
    }

    return result
  }, [attachments, filter, searchQuery])

  // Group by date
  const groupedAttachments = useMemo(() => {
    return groupAttachmentsByDate(filteredAttachments)
  }, [filteredAttachments])

  // Separate media and documents
  const { mediaAttachments, documentAttachments } = useMemo(() => {
    const media = filteredAttachments.filter(att => {
      const cat = getFileCategory(att.file_type, att.file_name)
      return cat === 'image' || cat === 'video'
    })
    const docs = filteredAttachments.filter(att => {
      const cat = getFileCategory(att.file_type, att.file_name)
      return cat !== 'image' && cat !== 'video'
    })
    return { mediaAttachments: media, documentAttachments: docs }
  }, [filteredAttachments])

  // Open viewer
  const openViewer = useCallback((index: number) => {
    setViewerIndex(index)
    setViewerOpen(true)
  }, [])

  // Calculate total size
  const totalSize = useMemo(() => {
    return filteredAttachments.reduce((acc, att) => acc + (att.file_size || 0), 0)
  }, [filteredAttachments])

  return (
    <>
      <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
        <DialogContent className="sm:max-w-2xl max-h-[85vh] flex flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ImageIcon className="h-5 w-5" />
              Media & Files
            </DialogTitle>
          </DialogHeader>

          {/* Filter tabs */}
          <Tabs value={filter} onValueChange={(v) => setFilter(v as GalleryFilter)}>
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="all" className="gap-2">
                <File className="h-4 w-4" />
                All
              </TabsTrigger>
              <TabsTrigger value="media" className="gap-2">
                <ImageIcon className="h-4 w-4" />
                Media
              </TabsTrigger>
              <TabsTrigger value="documents" className="gap-2">
                <FileText className="h-4 w-4" />
                Docs
              </TabsTrigger>
            </TabsList>
          </Tabs>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search files..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9"
            />
          </div>

          {/* Content */}
          <ScrollArea className="flex-1 -mx-6 px-6">
            {isLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : filteredAttachments.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <FileText className="h-12 w-12 mb-4 opacity-50" />
                <p>No files found</p>
              </div>
            ) : (
              <div className="space-y-6 pb-4">
                {groupedAttachments.map(group => {
                  const groupMedia = group.attachments.filter(att => {
                    const cat = getFileCategory(att.file_type, att.file_name)
                    return cat === 'image' || cat === 'video'
                  })
                  const groupDocs = group.attachments.filter(att => {
                    const cat = getFileCategory(att.file_type, att.file_name)
                    return cat !== 'image' && cat !== 'video'
                  })

                  return (
                    <div key={group.date}>
                      <h3 className="text-sm font-medium text-muted-foreground mb-3">
                        {group.label}
                      </h3>

                      {/* Media grid */}
                      {groupMedia.length > 0 && (
                        <div className="grid grid-cols-3 sm:grid-cols-4 gap-2 mb-4">
                          {groupMedia.map((att, idx) => (
                            <GalleryGridItem
                              key={att.id}
                              attachment={att}
                              onClick={() => {
                                const mediaIdx = mediaAttachments.findIndex(m => m.id === att.id)
                                openViewer(mediaIdx)
                              }}
                              onForward={onForward ? (a) => onForward([a]) : undefined}
                            />
                          ))}
                        </div>
                      )}

                      {/* Documents list */}
                      {groupDocs.length > 0 && (
                        <div className="space-y-1">
                          {groupDocs.map(att => (
                            <GalleryListItem
                              key={att.id}
                              attachment={att}
                              onClick={() => {
                                if (att.file_url) {
                                  window.open(att.file_url, '_blank')
                                }
                              }}
                              onForward={onForward ? (a) => onForward([a]) : undefined}
                            />
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </ScrollArea>

          {/* Footer with stats */}
          <div className="flex items-center justify-between pt-2 border-t text-sm text-muted-foreground">
            <span>
              {filteredAttachments.length} file{filteredAttachments.length !== 1 ? 's' : ''} • {formatFileSize(totalSize)}
            </span>
          </div>
        </DialogContent>
      </Dialog>

      {/* Media Viewer */}
      <MediaViewer
        attachments={mediaAttachments}
        initialIndex={viewerIndex}
        isOpen={viewerOpen}
        onClose={() => setViewerOpen(false)}
        onDownload={downloadAttachment}
        onForward={onForward ? (a) => onForward([a]) : undefined}
      />
    </>
  )
})

export default AttachmentGallery
