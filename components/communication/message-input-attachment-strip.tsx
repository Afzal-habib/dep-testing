"use client"

import { useState, useEffect, useCallback, memo } from "react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { 
  X, 
  FileText, 
  FileSpreadsheet, 
  FileArchive, 
  File,
  Image as ImageIcon,
  Video,
  Music,
  Plus,
  Loader2,
  AlertCircle
} from "lucide-react"
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { IAttachment } from "@/types/communication"
import {
  getFileCategory,
  generateThumbnail,
  formatFileSize,
  formatDuration,
  getVideoDuration,
  getCategoryColorClass,
  type FileCategory
} from "@/lib/utils/file-preview"
import Image from "next/image"

// File icon mapping
const FILE_ICONS: Record<FileCategory, React.ElementType> = {
  image: ImageIcon,
  video: Video,
  audio: Music,
  pdf: FileText,
  document: FileText,
  spreadsheet: FileSpreadsheet,
  archive: FileArchive,
  other: File
}

interface FilePreviewCardProps {
  file: File
  index: number
  onRemove: (index: number) => void
  isUploading?: boolean
  uploadProgress?: number
  error?: string
}

/**
 * Individual file preview card with thumbnail support
 */
export const FilePreviewCard = memo(function FilePreviewCard({
  file,
  index,
  onRemove,
  isUploading = false,
  uploadProgress = 0,
  error
}: FilePreviewCardProps) {
  const [thumbnail, setThumbnail] = useState<string | null>(null)
  const [duration, setDuration] = useState<number | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const category = getFileCategory(file.type, file.name)
  const Icon = FILE_ICONS[category]
  const colorClass = getCategoryColorClass(category)

  // Generate thumbnail on mount
  useEffect(() => {
    let mounted = true
    setIsLoading(true)

    const loadPreview = async () => {
      try {
        const thumb = await generateThumbnail(file)
        if (mounted) {
          setThumbnail(thumb)
        }

        // Get video duration if applicable
        if (category === 'video') {
          try {
            const dur = await getVideoDuration(file)
            if (mounted) {
              setDuration(dur)
            }
          } catch {
            // Ignore duration errors
          }
        }
      } catch {
        // Thumbnail generation failed, will show icon instead
      } finally {
        if (mounted) {
          setIsLoading(false)
        }
      }
    }

    loadPreview()

    return () => {
      mounted = false
    }
  }, [file, category])

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            className={cn(
              "relative group flex flex-col items-center justify-center",
              "w-[88px] h-[88px] rounded-xl border-2 transition-all duration-200",
              "hover:border-primary/50 hover:shadow-md",
              error 
                ? "border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20" 
                : colorClass.border,
              !error && (thumbnail ? "bg-muted/30" : colorClass.bg)
            )}
          >
            {/* Thumbnail or Icon */}
            <div className="relative w-full h-full flex items-center justify-center overflow-hidden rounded-lg">
              {isLoading && (category === 'image' || category === 'video') ? (
                <div className="animate-pulse bg-muted rounded-lg w-full h-full" />
              ) : thumbnail ? (
                <>
                  <Image
                    src={thumbnail}
                    alt={file.name}
                    fill
                    className="object-cover rounded-lg"
                    sizes="88px"
                  />
                  {/* Video duration badge */}
                  {category === 'video' && duration !== null && (
                    <div className="absolute bottom-1 right-1 px-1.5 py-0.5 bg-black/70 rounded text-[10px] text-white font-medium">
                      {formatDuration(duration)}
                    </div>
                  )}
                </>
              ) : (
                <div className="flex flex-col items-center gap-1">
                  <Icon className={cn("h-6 w-6", colorClass.text)} />
                  <span className={cn("text-[10px] font-medium uppercase", colorClass.text)}>
                    {file.name.split('.').pop()?.slice(0, 4)}
                  </span>
                </div>
              )}

              {/* Upload progress overlay */}
              {isUploading && (
                <div className="absolute inset-0 bg-black/50 flex items-center justify-center rounded-lg">
                  <div className="relative w-10 h-10">
                    <svg className="w-10 h-10 transform -rotate-90">
                      <circle
                        cx="20"
                        cy="20"
                        r="16"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="3"
                        className="text-white/30"
                      />
                      <circle
                        cx="20"
                        cy="20"
                        r="16"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="3"
                        strokeLinecap="round"
                        className="text-white"
                        strokeDasharray={100}
                        strokeDashoffset={100 - uploadProgress}
                      />
                    </svg>
                    <span className="absolute inset-0 flex items-center justify-center text-[10px] text-white font-bold">
                      {uploadProgress}%
                    </span>
                  </div>
                </div>
              )}

              {/* Error indicator */}
              {error && (
                <div className="absolute inset-0 bg-red-500/20 flex items-center justify-center rounded-lg">
                  <AlertCircle className="h-6 w-6 text-red-500" />
                </div>
              )}
            </div>

            {/* Remove button */}
            <Button
              variant="destructive"
              size="icon"
              className={cn(
                "absolute -top-2 -right-2 h-5 w-5 rounded-full p-0",
                "opacity-0 group-hover:opacity-100 transition-opacity",
                "shadow-md"
              )}
              onClick={(e) => {
                e.stopPropagation()
                onRemove(index)
              }}
              disabled={isUploading}
            >
              <X className="h-3 w-3" />
            </Button>

            {/* File size badge */}
            <div className="absolute bottom-1 left-1 px-1.5 py-0.5 bg-black/60 rounded text-[9px] text-white">
              {formatFileSize(file.size)}
            </div>
          </div>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-[200px]">
          <p className="text-xs truncate">{file.name}</p>
          {error && <p className="text-xs text-red-400 mt-1">{error}</p>}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
})

interface ExistingAttachmentCardProps {
  attachment: IAttachment
  onRemove: (attachmentId: string) => void
  isMarkedForRemoval?: boolean
}

/**
 * Card for existing attachments (in edit mode)
 */
export const ExistingAttachmentCard = memo(function ExistingAttachmentCard({
  attachment,
  onRemove,
  isMarkedForRemoval = false
}: ExistingAttachmentCardProps) {
  const category = getFileCategory(attachment.file_type, attachment.file_name)
  const Icon = FILE_ICONS[category]
  const colorClass = getCategoryColorClass(category)

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            className={cn(
              "relative group flex flex-col items-center justify-center",
              "w-[88px] h-[88px] rounded-xl border-2 transition-all duration-200",
              isMarkedForRemoval 
                ? "opacity-50 border-dashed border-red-300 dark:border-red-700" 
                : "hover:border-primary/50 hover:shadow-md",
              colorClass.border,
              colorClass.bg
            )}
          >
            {/* Thumbnail or Icon */}
            <div className="relative w-full h-full flex items-center justify-center overflow-hidden rounded-lg">
              {(category === 'image' || category === 'video') && attachment.file_url ? (
                <>
                  <Image
                    src={attachment.file_url}
                    alt={attachment.file_name}
                    fill
                    className={cn(
                      "object-cover rounded-lg",
                      isMarkedForRemoval && "grayscale"
                    )}
                    sizes="88px"
                  />
                  {isMarkedForRemoval && (
                    <div className="absolute inset-0 bg-red-500/30 flex items-center justify-center rounded-lg">
                      <X className="h-8 w-8 text-red-500" />
                    </div>
                  )}
                </>
              ) : (
                <div className="flex flex-col items-center gap-1">
                  <Icon className={cn(
                    "h-6 w-6",
                    isMarkedForRemoval ? "text-red-400" : colorClass.text
                  )} />
                  <span className={cn(
                    "text-[10px] font-medium uppercase",
                    isMarkedForRemoval ? "text-red-400 line-through" : colorClass.text
                  )}>
                    {attachment.file_name.split('.').pop()?.slice(0, 4)}
                  </span>
                </div>
              )}
            </div>

            {/* Remove/Restore button */}
            <Button
              variant={isMarkedForRemoval ? "secondary" : "destructive"}
              size="icon"
              className={cn(
                "absolute -top-2 -right-2 h-5 w-5 rounded-full p-0",
                "opacity-0 group-hover:opacity-100 transition-opacity",
                "shadow-md"
              )}
              onClick={(e) => {
                e.stopPropagation()
                onRemove(attachment.id)
              }}
            >
              <X className="h-3 w-3" />
            </Button>

            {/* File size badge */}
            {attachment.file_size && (
              <div className={cn(
                "absolute bottom-1 left-1 px-1.5 py-0.5 rounded text-[9px]",
                isMarkedForRemoval 
                  ? "bg-red-500/60 text-white" 
                  : "bg-black/60 text-white"
              )}>
                {formatFileSize(attachment.file_size)}
              </div>
            )}

            {/* "Will be removed" indicator */}
            {isMarkedForRemoval && (
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2">
                <span className="text-[9px] text-red-500 font-medium bg-white/90 dark:bg-black/90 px-1 py-0.5 rounded">
                  Removing
                </span>
              </div>
            )}
          </div>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-[200px]">
          <p className="text-xs truncate">{attachment.file_name}</p>
          {isMarkedForRemoval && <p className="text-xs text-red-400 mt-1">Will be removed on save</p>}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
})

interface MessageInputAttachmentStripProps {
  files: File[]
  existingAttachments?: IAttachment[]
  attachmentsToRemove?: Set<string>
  onRemoveFile: (index: number) => void
  onRemoveExisting: (attachmentId: string) => void
  onAddMore?: () => void
  isUploading?: boolean
  uploadProgress?: number
  maxFiles?: number
  className?: string
}

/**
 * Horizontal strip of attachment previews for message input
 */
export const MessageInputAttachmentStrip = memo(function MessageInputAttachmentStrip({
  files,
  existingAttachments = [],
  attachmentsToRemove = new Set(),
  onRemoveFile,
  onRemoveExisting,
  onAddMore,
  isUploading = false,
  uploadProgress = 0,
  maxFiles = 5,
  className
}: MessageInputAttachmentStripProps) {
  // Filter out attachments marked for removal when counting
  const activeExisting = existingAttachments.filter(a => !attachmentsToRemove.has(a.id))
  const totalCount = files.length + activeExisting.length
  const canAddMore = totalCount < maxFiles

  if (files.length === 0 && existingAttachments.length === 0) {
    return null
  }

  return (
    <div className={cn(
      "flex flex-col gap-2 p-3 border-b bg-muted/20",
      className
    )}>
      {/* Header */}
      <div className="flex items-center justify-between px-1">
        <span className="text-xs font-medium text-muted-foreground">
          {totalCount} attachment{totalCount !== 1 ? 's' : ''}
          {attachmentsToRemove.size > 0 && (
            <span className="text-red-500 ml-1">
              ({attachmentsToRemove.size} will be removed)
            </span>
          )}
        </span>
        {isUploading && (
          <div className="flex items-center gap-1.5 text-xs text-primary">
            <Loader2 className="h-3 w-3 animate-spin" />
            <span>Uploading... {uploadProgress}%</span>
          </div>
        )}
      </div>

      {/* Attachment cards */}
      <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-thin scrollbar-thumb-muted scrollbar-track-transparent">
        {/* Existing attachments (for edit mode) */}
        {existingAttachments.map((attachment) => (
          <ExistingAttachmentCard
            key={attachment.id}
            attachment={attachment}
            onRemove={onRemoveExisting}
            isMarkedForRemoval={attachmentsToRemove.has(attachment.id)}
          />
        ))}

        {/* New files */}
        {files.map((file, index) => (
          <FilePreviewCard
            key={`${file.name}-${index}`}
            file={file}
            index={index}
            onRemove={onRemoveFile}
            isUploading={isUploading}
            uploadProgress={uploadProgress}
          />
        ))}

        {/* Add more button */}
        {canAddMore && onAddMore && (
          <button
            onClick={onAddMore}
            className={cn(
              "flex flex-col items-center justify-center",
              "w-[88px] h-[88px] rounded-xl border-2 border-dashed",
              "border-muted-foreground/30 hover:border-primary/50",
              "bg-muted/10 hover:bg-muted/30 transition-all duration-200",
              "group"
            )}
          >
            <Plus className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
            <span className="text-[10px] text-muted-foreground group-hover:text-primary mt-1 transition-colors">
              Add more
            </span>
          </button>
        )}
      </div>

      {/* Progress bar for upload */}
      {isUploading && (
        <div className="h-1 bg-muted rounded-full overflow-hidden">
          <div 
            className="h-full bg-primary transition-all duration-300 ease-out"
            style={{ width: `${uploadProgress}%` }}
          />
        </div>
      )}
    </div>
  )
})

export default MessageInputAttachmentStrip
