/**
 * File Preview Utilities
 * 
 * Provides thumbnail generation, file type detection, and preview utilities
 * for the communication module attachment handling.
 */

// File category types
export type FileCategory = 'image' | 'video' | 'audio' | 'pdf' | 'document' | 'spreadsheet' | 'archive' | 'other'

// File extension to category mapping
const EXTENSION_CATEGORIES: Record<string, FileCategory> = {
  // Images
  jpg: 'image', jpeg: 'image', png: 'image', gif: 'image', webp: 'image', svg: 'image', bmp: 'image', ico: 'image',
  // Videos
  mp4: 'video', webm: 'video', mov: 'video', avi: 'video', mkv: 'video', m4v: 'video', wmv: 'video',
  // Audio
  mp3: 'audio', wav: 'audio', ogg: 'audio', aac: 'audio', m4a: 'audio', flac: 'audio', wma: 'audio',
  // PDF
  pdf: 'pdf',
  // Documents
  doc: 'document', docx: 'document', txt: 'document', rtf: 'document', odt: 'document', md: 'document',
  // Spreadsheets
  xls: 'spreadsheet', xlsx: 'spreadsheet', csv: 'spreadsheet', ods: 'spreadsheet',
  // Archives
  zip: 'archive', rar: 'archive', '7z': 'archive', tar: 'archive', gz: 'archive',
}

// MIME type to category mapping
const MIME_CATEGORIES: Record<string, FileCategory> = {
  'image/': 'image',
  'video/': 'video',
  'audio/': 'audio',
  'application/pdf': 'pdf',
  'application/msword': 'document',
  'application/vnd.openxmlformats-officedocument.wordprocessingml': 'document',
  'application/vnd.ms-excel': 'spreadsheet',
  'application/vnd.openxmlformats-officedocument.spreadsheetml': 'spreadsheet',
  'text/': 'document',
  'application/zip': 'archive',
  'application/x-rar': 'archive',
  'application/x-7z': 'archive',
}

/**
 * Get the file category from file type or extension
 */
export function getFileCategory(fileType?: string, fileName?: string): FileCategory {
  // Try MIME type first
  if (fileType) {
    const lowerType = fileType.toLowerCase()
    for (const [prefix, category] of Object.entries(MIME_CATEGORIES)) {
      if (lowerType.startsWith(prefix) || lowerType === prefix) {
        return category
      }
    }
  }
  
  // Try extension
  if (fileName) {
    const ext = fileName.split('.').pop()?.toLowerCase()
    if (ext && EXTENSION_CATEGORIES[ext]) {
      return EXTENSION_CATEGORIES[ext]
    }
  }
  
  return 'other'
}

/**
 * Generate a local thumbnail URL from a File object (for images)
 */
export function generateImageThumbnail(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!file.type.startsWith('image/')) {
      reject(new Error('File is not an image'))
      return
    }

    const reader = new FileReader()
    reader.onload = (e) => {
      const result = e.target?.result as string
      if (result) {
        resolve(result)
      } else {
        reject(new Error('Failed to read file'))
      }
    }
    reader.onerror = () => reject(new Error('Failed to read file'))
    reader.readAsDataURL(file)
  })
}

/**
 * Generate a video thumbnail from first frame
 */
export function generateVideoThumbnail(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!file.type.startsWith('video/')) {
      reject(new Error('File is not a video'))
      return
    }

    const video = document.createElement('video')
    video.preload = 'metadata'
    video.muted = true
    video.playsInline = true

    const url = URL.createObjectURL(file)
    video.src = url

    video.onloadedmetadata = () => {
      // Seek to 1 second or 10% of duration, whichever is smaller
      video.currentTime = Math.min(1, video.duration * 0.1)
    }

    video.onseeked = () => {
      try {
        const canvas = document.createElement('canvas')
        canvas.width = video.videoWidth
        canvas.height = video.videoHeight
        
        const ctx = canvas.getContext('2d')
        if (ctx) {
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height)
          const thumbnail = canvas.toDataURL('image/jpeg', 0.7)
          URL.revokeObjectURL(url)
          resolve(thumbnail)
        } else {
          URL.revokeObjectURL(url)
          reject(new Error('Failed to get canvas context'))
        }
      } catch (err) {
        URL.revokeObjectURL(url)
        reject(err)
      }
    }

    video.onerror = () => {
      URL.revokeObjectURL(url)
      reject(new Error('Failed to load video'))
    }
  })
}

/**
 * Get video duration from file
 */
export function getVideoDuration(file: File): Promise<number> {
  return new Promise((resolve, reject) => {
    if (!file.type.startsWith('video/')) {
      reject(new Error('File is not a video'))
      return
    }

    const video = document.createElement('video')
    video.preload = 'metadata'
    
    const url = URL.createObjectURL(file)
    video.src = url

    video.onloadedmetadata = () => {
      URL.revokeObjectURL(url)
      resolve(video.duration)
    }

    video.onerror = () => {
      URL.revokeObjectURL(url)
      reject(new Error('Failed to load video'))
    }
  })
}

/**
 * Get audio duration from file
 */
export function getAudioDuration(file: File): Promise<number> {
  return new Promise((resolve, reject) => {
    if (!file.type.startsWith('audio/')) {
      reject(new Error('File is not audio'))
      return
    }

    const audio = document.createElement('audio')
    audio.preload = 'metadata'
    
    const url = URL.createObjectURL(file)
    audio.src = url

    audio.onloadedmetadata = () => {
      URL.revokeObjectURL(url)
      resolve(audio.duration)
    }

    audio.onerror = () => {
      URL.revokeObjectURL(url)
      reject(new Error('Failed to load audio'))
    }
  })
}

/**
 * Generate thumbnail for any supported file type
 */
export async function generateThumbnail(file: File): Promise<string | null> {
  const category = getFileCategory(file.type, file.name)
  
  try {
    switch (category) {
      case 'image':
        return await generateImageThumbnail(file)
      case 'video':
        return await generateVideoThumbnail(file)
      default:
        return null
    }
  } catch {
    return null
  }
}

/**
 * Format file size to human readable string
 */
export function formatFileSize(bytes?: number): string {
  if (!bytes || bytes === 0) return '0 B'
  
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const k = 1024
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${units[i]}`
}

/**
 * Format duration in seconds to mm:ss or hh:mm:ss
 */
export function formatDuration(seconds: number): string {
  if (!seconds || isNaN(seconds)) return '0:00'
  
  const hrs = Math.floor(seconds / 3600)
  const mins = Math.floor((seconds % 3600) / 60)
  const secs = Math.floor(seconds % 60)
  
  if (hrs > 0) {
    return `${hrs}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`
  }
  return `${mins}:${secs.toString().padStart(2, '0')}`
}

/**
 * Get file extension from filename
 */
export function getFileExtension(filename: string): string {
  const parts = filename.split('.')
  return parts.length > 1 ? parts.pop()?.toUpperCase() || '' : ''
}

/**
 * Check if file is previewable (can generate thumbnail)
 */
export function isPreviewable(file: File): boolean {
  const category = getFileCategory(file.type, file.name)
  return category === 'image' || category === 'video'
}

/**
 * Get color class for file category (for badges/icons)
 */
export function getCategoryColorClass(category: FileCategory): {
  bg: string
  text: string
  border: string
} {
  const colors: Record<FileCategory, { bg: string; text: string; border: string }> = {
    image: {
      bg: 'bg-green-100 dark:bg-green-900/30',
      text: 'text-green-700 dark:text-green-400',
      border: 'border-green-200 dark:border-green-800'
    },
    video: {
      bg: 'bg-purple-100 dark:bg-purple-900/30',
      text: 'text-purple-700 dark:text-purple-400',
      border: 'border-purple-200 dark:border-purple-800'
    },
    audio: {
      bg: 'bg-pink-100 dark:bg-pink-900/30',
      text: 'text-pink-700 dark:text-pink-400',
      border: 'border-pink-200 dark:border-pink-800'
    },
    pdf: {
      bg: 'bg-red-100 dark:bg-red-900/30',
      text: 'text-red-700 dark:text-red-400',
      border: 'border-red-200 dark:border-red-800'
    },
    document: {
      bg: 'bg-blue-100 dark:bg-blue-900/30',
      text: 'text-blue-700 dark:text-blue-400',
      border: 'border-blue-200 dark:border-blue-800'
    },
    spreadsheet: {
      bg: 'bg-emerald-100 dark:bg-emerald-900/30',
      text: 'text-emerald-700 dark:text-emerald-400',
      border: 'border-emerald-200 dark:border-emerald-800'
    },
    archive: {
      bg: 'bg-amber-100 dark:bg-amber-900/30',
      text: 'text-amber-700 dark:text-amber-400',
      border: 'border-amber-200 dark:border-amber-800'
    },
    other: {
      bg: 'bg-gray-100 dark:bg-gray-800',
      text: 'text-gray-700 dark:text-gray-400',
      border: 'border-gray-200 dark:border-gray-700'
    }
  }
  
  return colors[category]
}

/**
 * Validate file for upload
 */
export interface FileValidationResult {
  valid: boolean
  error?: string
}

export function validateFile(
  file: File,
  options: {
    maxSize?: number // in bytes
    allowedTypes?: FileCategory[]
    allowedExtensions?: string[]
  } = {}
): FileValidationResult {
  const { maxSize = 10 * 1024 * 1024, allowedTypes, allowedExtensions } = options
  
  // Check file size
  if (file.size > maxSize) {
    return {
      valid: false,
      error: `File size exceeds ${formatFileSize(maxSize)}`
    }
  }
  
  // Check file type
  if (allowedTypes && allowedTypes.length > 0) {
    const category = getFileCategory(file.type, file.name)
    if (!allowedTypes.includes(category)) {
      return {
        valid: false,
        error: `File type not allowed. Allowed: ${allowedTypes.join(', ')}`
      }
    }
  }
  
  // Check extension
  if (allowedExtensions && allowedExtensions.length > 0) {
    const ext = file.name.split('.').pop()?.toLowerCase()
    if (!ext || !allowedExtensions.includes(ext)) {
      return {
        valid: false,
        error: `File extension not allowed. Allowed: ${allowedExtensions.join(', ')}`
      }
    }
  }
  
  return { valid: true }
}
