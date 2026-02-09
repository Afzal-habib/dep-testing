"use client"

import { useState, useCallback, memo, useRef, useEffect } from "react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog"
import {
  FileText,
  FileSpreadsheet,
  FileType,
  FileImage,
  FileArchive,
  File,
  Download,
  ExternalLink,
  X,
  Play,
  Pause,
  Maximize2,
  Eye,
  Mic,
  FileAudio,
  Forward,
  Share2
} from "lucide-react"
import { IAttachment } from "@/types/communication"
import { useChatAttachments } from "@/hooks/use-chat-attachments"
import { formatDistanceToNow } from "date-fns"
import Image from "next/image"
import { AttachmentShareMenu } from "./attachment-share-menu"
import { communicationLogger as logger } from "@/lib/logger"
import { useToast } from "@/hooks/use-toast"

interface AttachmentPreviewProps {
  attachment: IAttachment
  className?: string
  size?: "sm" | "md" | "lg"
  showDownload?: boolean
  showPreview?: boolean
  showShare?: boolean
  onForward?: (attachment: IAttachment) => void
}

interface AttachmentGridProps {
  attachments: IAttachment[]
  className?: string
  maxVisible?: number
  onViewAll?: () => void
}

interface AttachmentListItemProps {
  attachment: IAttachment
  uploaderName?: string
  showUploader?: boolean
  className?: string
  onDownload?: (attachment: IAttachment) => void
  onPreview?: (attachment: IAttachment) => void
}

// Helper to determine file category
export function getFileCategory(fileType: string | undefined, fileName: string): 'image' | 'video' | 'audio' | 'pdf' | 'document' | 'spreadsheet' | 'archive' | 'other' {
  const type = fileType?.toLowerCase() || ''
  const ext = fileName.split('.').pop()?.toLowerCase() || ''

  if (type.startsWith('image/') || ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'].includes(ext)) {
    return 'image'
  }
  if (type.startsWith('video/') || ['mp4', 'webm', 'mov', 'avi', 'mkv'].includes(ext)) {
    return 'video'
  }
  if (type.startsWith('audio/') || ['mp3', 'wav', 'ogg', 'aac', 'm4a'].includes(ext)) {
    return 'audio'
  }
  if (type === 'application/pdf' || ext === 'pdf') {
    return 'pdf'
  }
  if (
    type.includes('word') ||
    type.includes('document') ||
    ['doc', 'docx', 'txt', 'rtf', 'odt'].includes(ext)
  ) {
    return 'document'
  }
  if (
    type.includes('spreadsheet') ||
    type.includes('excel') ||
    ['xls', 'xlsx', 'csv', 'ods'].includes(ext)
  ) {
    return 'spreadsheet'
  }
  if (
    type.includes('zip') ||
    type.includes('rar') ||
    type.includes('archive') ||
    ['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)
  ) {
    return 'archive'
  }
  return 'other'
}

// Get icon for file type
export function getFileIcon(category: ReturnType<typeof getFileCategory>) {
  switch (category) {
    case 'image':
      return FileImage
    case 'video':
      return Play
    case 'audio':
      return Play
    case 'pdf':
      return FileText
    case 'document':
      return FileType
    case 'spreadsheet':
      return FileSpreadsheet
    case 'archive':
      return FileArchive
    default:
      return File
  }
}

// Get file extension color
export function getExtensionColor(category: ReturnType<typeof getFileCategory>): string {
  switch (category) {
    case 'image':
      return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
    case 'video':
      return 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400'
    case 'audio':
      return 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-400'
    case 'pdf':
      return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
    case 'document':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
    case 'spreadsheet':
      return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'
    case 'archive':
      return 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400'
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400'
  }
}

// Format file size
export function formatFileSize(bytes: number | undefined): string {
  if (!bytes) return 'Unknown size'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// Image preview with lightbox
export const ImagePreview = memo(function ImagePreview({
  src,
  alt,
  className,
  onExpand
}: {
  src: string
  alt: string
  className?: string
  onExpand?: () => void
}) {
  const [isLoading, setIsLoading] = useState(true)
  const [hasError, setHasError] = useState(false)

  if (hasError) {
    return (
      <div className={cn("bg-muted flex items-center justify-center rounded-lg", className)}>
        <FileImage className="h-8 w-8 text-muted-foreground" />
      </div>
    )
  }

  return (
    <div
      className={cn(
        "relative rounded-lg overflow-hidden cursor-pointer group",
        className
      )}
      onClick={onExpand}
    >
      {isLoading && (
        <div className="absolute inset-0 bg-muted animate-pulse" />
      )}
      <Image
        src={src}
        alt={alt}
        fill
        className={cn(
          "object-cover transition-opacity duration-200",
          isLoading ? "opacity-0" : "opacity-100"
        )}
        onLoad={() => setIsLoading(false)}
        onError={() => setHasError(true)}
        sizes="(max-width: 768px) 100vw, 300px"
      />
      {/* Hover overlay */}
      <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors flex items-center justify-center">
        <Maximize2 className="h-6 w-6 text-white opacity-0 group-hover:opacity-100 transition-opacity" />
      </div>
    </div>
  )
})

// WhatsApp-style Voice Message / Audio Player
export const AudioPlayer = memo(function AudioPlayer({
  src,
  duration: initialDuration,
  className,
  isVoiceMessage = false,
  onDownload
}: {
  src: string
  duration?: number
  className?: string
  isVoiceMessage?: boolean
  onDownload?: () => void
}) {
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const [isPlaying, setIsPlaying] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [duration, setDuration] = useState(initialDuration || 0)
  const [isLoading, setIsLoading] = useState(true)

  // Format time as mm:ss - handle edge cases
  const formatTime = (seconds: number) => {
    if (!isFinite(seconds) || isNaN(seconds) || seconds < 0) return '0:00'
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  // Handle audio events
  useEffect(() => {
    const audio = audioRef.current
    if (!audio) return

    const handleLoadedMetadata = () => {
      // Handle cases where audio.duration is Infinity or NaN (streaming/live audio)
      const audioDuration = audio.duration
      if (isFinite(audioDuration) && !isNaN(audioDuration) && audioDuration > 0) {
        setDuration(audioDuration)
      } else if (initialDuration && initialDuration > 0) {
        setDuration(initialDuration)
      }
      setIsLoading(false)
    }

    const handleDurationChange = () => {
      // Fallback for when duration becomes available later
      const audioDuration = audio.duration
      if (isFinite(audioDuration) && !isNaN(audioDuration) && audioDuration > 0) {
        setDuration(audioDuration)
      }
    }

    const handleCanPlayThrough = () => {
      // Another fallback when audio is fully buffered
      const audioDuration = audio.duration
      if (duration === 0 && isFinite(audioDuration) && !isNaN(audioDuration) && audioDuration > 0) {
        setDuration(audioDuration)
      }
      setIsLoading(false)
    }

    const handleTimeUpdate = () => setCurrentTime(audio.currentTime)
    const handleEnded = () => {
      setIsPlaying(false)
      setCurrentTime(0)
    }
    const handleError = () => setIsLoading(false)

    audio.addEventListener('loadedmetadata', handleLoadedMetadata)
    audio.addEventListener('durationchange', handleDurationChange)
    audio.addEventListener('canplaythrough', handleCanPlayThrough)
    audio.addEventListener('timeupdate', handleTimeUpdate)
    audio.addEventListener('ended', handleEnded)
    audio.addEventListener('error', handleError)

    // If we have initial duration, use it immediately
    if (initialDuration && initialDuration > 0) {
      setDuration(initialDuration)
      setIsLoading(false)
    }

    return () => {
      audio.removeEventListener('loadedmetadata', handleLoadedMetadata)
      audio.removeEventListener('durationchange', handleDurationChange)
      audio.removeEventListener('canplaythrough', handleCanPlayThrough)
      audio.removeEventListener('timeupdate', handleTimeUpdate)
      audio.removeEventListener('ended', handleEnded)
      audio.removeEventListener('error', handleError)
    }
  }, [initialDuration, duration])

  const togglePlayback = () => {
    if (!audioRef.current) return

    if (isPlaying) {
      audioRef.current.pause()
      setIsPlaying(false)
    } else {
      audioRef.current.play()
      setIsPlaying(true)
    }
  }

  const handleSeek = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!audioRef.current || !duration) return

    const rect = e.currentTarget.getBoundingClientRect()
    const x = e.clientX - rect.left
    const percent = x / rect.width
    const newTime = percent * duration

    audioRef.current.currentTime = newTime
    setCurrentTime(newTime)
  }

  const progressPercent = duration > 0 ? (currentTime / duration) * 100 : 0

  return (
    <div className={cn(
      "flex items-center gap-2 p-2 rounded-xl min-w-[180px] max-w-[240px]",
      isVoiceMessage
        // ? "bg-emerald-500/10 border border-emerald-500/20"
        ? "bg-white border border-emerald-500/20"
        : "bg-muted/40 border",
      className
    )}>
      {/* Hidden audio element */}
      <audio ref={audioRef} src={src} preload="metadata" />

      {/* Play/Pause button */}
      <Button
        variant="ghost"
        size="icon"
        className={cn(
          "h-8 w-8 rounded-full shrink-0",
          isVoiceMessage
            ? "bg-emerald-500 hover:bg-emerald-600 text-white"
            : "bg-primary hover:bg-primary/90 text-primary-foreground"
        )}
        onClick={togglePlayback}
        disabled={isLoading}
      >
        {isLoading ? (
          <div className="h-3 w-3 animate-spin rounded-full border-2 border-white border-t-transparent" />
        ) : isPlaying ? (
          <Pause className="h-4 w-4" />
        ) : (
          <Play className="h-4 w-4 ml-0.5" />
        )}
      </Button>

      {/* Waveform / Progress */}
      <div className="flex-1 space-y-0.5">
        {/* Progress bar with waveform-like appearance */}
        <div
          className="h-5 relative cursor-pointer flex items-center"
          onClick={handleSeek}
        >
          {/* Waveform visualization (simulated) */}
          <div className="absolute inset-0 flex items-center gap-[2px]">
            {Array.from({ length: 25 }).map((_, i) => {
              const height = 20 + Math.sin(i * 0.5) * 15 + Math.random() * 10
              const isPast = (i / 25) * 100 <= progressPercent
              return (
                <div
                  key={i}
                  className={cn(
                    "flex-1 rounded-full transition-colors",
                    isPast
                      ? isVoiceMessage ? "bg-emerald-500" : "bg-primary"
                      : "bg-muted-foreground/30"
                  )}
                  style={{ height: `${height}%` }}
                />
              )
            })}
          </div>
        </div>

        {/* Time display */}
        <div className="flex items-center justify-between text-[10px] text-muted-foreground">
          <span className="tabular-nums">{formatTime(currentTime)}</span>
          <span className="tabular-nums">{formatTime(duration)}</span>
        </div>
      </div>

      {/* Voice message icon or download */}
      {isVoiceMessage ? (
        <div className="shrink-0">
          <Mic className="h-3.5 w-3.5 text-emerald-500" />
        </div>
      ) : onDownload && (
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 shrink-0"
          onClick={onDownload}
        >
          <Download className="h-3.5 w-3.5" />
        </Button>
      )}
    </div>
  )
})

// Single attachment preview (WhatsApp style)
export const AttachmentPreview = memo(function AttachmentPreview({
  attachment,
  className,
  size = "md",
  showDownload = true,
  showPreview = true,
  showShare = false,
  onForward
}: AttachmentPreviewProps) {
  const [isLightboxOpen, setIsLightboxOpen] = useState(false)
  const [isDownloading, setIsDownloading] = useState(false)
  const { toast } = useToast()

  const { downloadAttachment } = useChatAttachments()

  const category = getFileCategory(attachment.file_type, attachment.file_name)
  const Icon = getFileIcon(category)
  const colorClass = getExtensionColor(category)

  const sizeClasses = {
    sm: "max-w-[120px]",
    md: "max-w-[200px]",
    lg: "max-w-[280px]"
  }

  const imageSizes = {
    sm: "h-[80px]",
    md: "h-[140px]",
    lg: "h-[200px]"
  }

  const handleDownload = useCallback(async () => {
    setIsDownloading(true)
    try {
      await downloadAttachment(attachment)
    } catch (error) {
      logger.error('Download failed:', error)
      toast({
        title: "Download Failed",
        description: "Could not download the file. Please try again.",
        variant: "destructive"
      })
    } finally {
      setIsDownloading(false)
    }
  }, [downloadAttachment, attachment, toast])

  // Image attachment
  if (category === 'image' && attachment.file_url) {
    return (
      <>
        <div className={cn("relative rounded-lg overflow-hidden", sizeClasses[size], className)}>
          <ImagePreview
            src={attachment.file_url}
            alt={attachment.file_name}
            className={cn("w-full", imageSizes[size])}
            onExpand={() => setIsLightboxOpen(true)}
          />
          {/* Actions overlay */}
          <div className="absolute bottom-0 left-0 right-0 p-2 bg-gradient-to-t from-black/60 to-transparent opacity-0 hover:opacity-100 transition-opacity">
            <div className="flex items-center justify-between">
              <span className="text-white text-xs truncate flex-1 mr-2">
                {attachment.file_name}
              </span>
              <div className="flex items-center gap-1">
                {showShare && (
                  <AttachmentShareMenu
                    attachment={attachment}
                    onForward={onForward}
                    variant="icon"
                    size="sm"
                    className="h-6 w-6 p-0 text-white hover:bg-white/20"
                  />
                )}
                {showDownload && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0 text-white hover:bg-white/20"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleDownload()
                    }}
                    disabled={isDownloading}
                  >
                    <Download className="h-3 w-3" />
                  </Button>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Lightbox */}
        <Dialog open={isLightboxOpen} onOpenChange={setIsLightboxOpen}>
          <DialogContent className="max-w-4xl max-h-[90vh] p-0 overflow-hidden">
            <DialogTitle className="sr-only">{attachment.file_name}</DialogTitle>
            <div className="relative">
              <Button
                variant="ghost"
                size="sm"
                className="absolute top-2 right-2 z-10 h-8 w-8 p-0 bg-black/50 hover:bg-black/70 text-white"
                onClick={() => setIsLightboxOpen(false)}
              >
                <X className="h-4 w-4" />
              </Button>
              <Image
                src={attachment.file_url}
                alt={attachment.file_name}
                width={1200}
                height={800}
                className="w-full h-auto max-h-[85vh] object-contain"
              />
              <div className="absolute bottom-0 left-0 right-0 p-4 bg-gradient-to-t from-black/80 to-transparent">
                <div className="flex items-center justify-between text-white">
                  <div>
                    <p className="font-medium">{attachment.file_name}</p>
                    <p className="text-sm opacity-80">{formatFileSize(attachment.file_size)}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {showShare && (
                      <AttachmentShareMenu
                        attachment={attachment}
                        onForward={onForward}
                        variant="button"
                        size="sm"
                      />
                    )}
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={handleDownload}
                      disabled={isDownloading}
                    >
                      <Download className="h-4 w-4 mr-2" />
                      Download
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </>
    )
  }

  // Audio / Voice message attachment
  if (category === 'audio' && attachment.file_url) {
    // Check if it's a voice message based on filename or type
    const isVoice = attachment.file_name.toLowerCase().includes('voice') ||
      attachment.file_type?.includes('webm') ||
      (attachment as any).isVoiceMessage

    return (
      attachment.file_url ? (
        <AudioPlayer
          src={attachment.file_url}
          duration={attachment.durationSeconds}
          isVoiceMessage={isVoice}
          onDownload={showDownload ? handleDownload : undefined}
          className={className}
        />
      ) : (
        <div className={cn("flex items-center gap-2 p-3 text-muted-foreground", className)}>
          <FileAudio className="h-4 w-4" />
          <span className="text-sm">Audio file unavailable</span>
        </div>
      )
    )
  }

  // PDF attachment with preview
  if (category === 'pdf' && attachment.file_url) {
    return (
      <div className={cn(
        "rounded-lg border bg-card overflow-hidden",
        sizeClasses[size],
        className
      )}>
        {/* PDF preview placeholder */}
        <div className="bg-red-50 dark:bg-red-900/20 flex items-center justify-center h-[80px]">
          <div className="text-center">
            <FileText className="h-8 w-8 text-red-500 mx-auto" />
            <span className="text-[10px] text-red-600 dark:text-red-400 font-medium">PDF</span>
          </div>
        </div>
        <div className="px-2 py-1.5">
          <p className="text-xs font-medium truncate">{attachment.file_name}</p>
          <p className="text-[10px] text-muted-foreground">{formatFileSize(attachment.file_size)}</p>
          <div className="flex gap-1 mt-1.5">
            {showShare && (
              <AttachmentShareMenu
                attachment={attachment}
                onForward={onForward}
                variant="button"
                size="sm"
                className="flex-1 h-6 text-[10px]"
              />
            )}
            {showPreview && (
              <Button
                variant="outline"
                size="sm"
                className="flex-1 h-6 text-[10px] px-2"
                onClick={() => window.open(attachment.file_url, '_blank')}
              >
                <Eye className="h-3 w-3 mr-1" />
                View
              </Button>
            )}
            {showDownload && (
              <Button
                variant="outline"
                size="sm"
                className="flex-1 h-6 text-[10px] px-2"
                onClick={handleDownload}
                disabled={isDownloading}
              >
                <Download className="h-3 w-3 mr-1" />
                Save
              </Button>
            )}
          </div>
        </div>
      </div>
    )
  }

  // Generic file attachment
  return (
    <div className={cn(
      "rounded-lg border bg-card p-2 flex items-center gap-2",
      sizeClasses[size],
      className
    )}>
      <div className={cn("h-8 w-8 rounded-md flex items-center justify-center shrink-0", colorClass)}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium truncate">{attachment.file_name}</p>
        <p className="text-[10px] text-muted-foreground">{formatFileSize(attachment.file_size)}</p>
      </div>
      <div className="flex gap-0.5 shrink-0">
        {showShare && (
          <AttachmentShareMenu
            attachment={attachment}
            onForward={onForward}
            variant="icon"
            size="sm"
            className="h-7 w-7 p-0"
          />
        )}
        {showPreview && attachment.file_url && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0"
            onClick={() => window.open(attachment.file_url, '_blank')}
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </Button>
        )}
        {showDownload && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0"
            onClick={handleDownload}
            disabled={isDownloading}
          >
            <Download className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>
    </div>
  )
})

// Grid of attachments (for messages with multiple files)
export const AttachmentGrid = memo(function AttachmentGrid({
  attachments,
  className,
  maxVisible = 4,
  onViewAll
}: AttachmentGridProps) {
  const [selectedAttachment, setSelectedAttachment] = useState<IAttachment | null>(null)

  if (!attachments.length) return null

  const visibleAttachments = attachments.slice(0, maxVisible)
  const hiddenCount = attachments.length - maxVisible

  // Single image - full width
  if (attachments.length === 1 && getFileCategory(attachments[0].file_type, attachments[0].file_name) === 'image') {
    return (
      <div className={cn("mt-1.5", className)}>
        <AttachmentPreview attachment={attachments[0]} size="md" />
      </div>
    )
  }

  // Multiple images - grid layout
  const allImages = attachments.every(a => getFileCategory(a.file_type, a.file_name) === 'image')

  if (allImages) {
    const gridClass = attachments.length === 2
      ? "grid-cols-2"
      : attachments.length === 3
        ? "grid-cols-2"
        : "grid-cols-2"

    return (
      <div className={cn("mt-1.5 grid gap-0.5", gridClass, className)}>
        {visibleAttachments.map((attachment, index) => (
          <div
            key={attachment.id}
            className={cn(
              "relative",
              attachments.length === 3 && index === 0 && "col-span-2"
            )}
          >
            <AttachmentPreview
              attachment={attachment}
              size={attachments.length === 3 && index === 0 ? "md" : "sm"}
              className="w-full"
            />
            {/* Show +N overlay on last visible if more hidden */}
            {index === maxVisible - 1 && hiddenCount > 0 && (
              <div
                className="absolute inset-0 bg-black/60 flex items-center justify-center rounded-lg cursor-pointer"
                onClick={onViewAll}
              >
                <span className="text-white text-xl font-semibold">+{hiddenCount}</span>
              </div>
            )}
          </div>
        ))}
      </div>
    )
  }

  // Mixed file types - list layout
  return (
    <div className={cn("mt-1.5 space-y-1", className)}>
      {visibleAttachments.map((attachment) => (
        <AttachmentPreview
          key={attachment.id}
          attachment={attachment}
          size="sm"
        />
      ))}
      {hiddenCount > 0 && (
        <Button
          variant="outline"
          size="sm"
          className="w-full h-7 text-xs"
          onClick={onViewAll}
        >
          View {hiddenCount} more file{hiddenCount > 1 ? 's' : ''}
        </Button>
      )}
    </div>
  )
})

// List item for context panel
export const AttachmentListItem = memo(function AttachmentListItem({
  attachment,
  uploaderName,
  showUploader = true,
  className,
  onDownload,
  onPreview
}: AttachmentListItemProps) {
  const category = getFileCategory(attachment.file_type, attachment.file_name)
  const Icon = getFileIcon(category)
  const colorClass = getExtensionColor(category)

  return (
    <div className={cn(
      "flex items-center gap-2 p-1.5 rounded-md hover:bg-muted/40 cursor-pointer transition-colors",
      className
    )}>
      <div className={cn("h-8 w-8 rounded-md flex items-center justify-center shrink-0", colorClass)}>
        <Icon className="h-4 w-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium truncate">{attachment.file_name}</p>
        <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
          <span>{formatFileSize(attachment.file_size)}</span>
          {showUploader && uploaderName && (
            <>
              <span>•</span>
              <span>{uploaderName}</span>
            </>
          )}
          {attachment.created_at && (
            <>
              <span>•</span>
              <span>{formatDistanceToNow(new Date(attachment.created_at), { addSuffix: true })}</span>
            </>
          )}
        </div>
      </div>
      <div className="flex gap-0.5 shrink-0">
        {onPreview && (
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0"
            onClick={() => onPreview(attachment)}
          >
            <Eye className="h-3.5 w-3.5" />
          </Button>
        )}
        {onDownload && (
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0"
            onClick={() => onDownload(attachment)}
          >
            <Download className="h-3.5 w-3.5" />
          </Button>
        )}
      </div>
    </div>
  )
})

export default AttachmentPreview
