import { useState, useCallback } from 'react'
import { useToast } from '@/hooks/use-toast'
import type { IAttachment } from '@/types/communication'

interface UploadedAttachment {
  id: string
  file_name: string
  file_url: string | null
  s3_key: string | null
  file_size: number | null
  file_type: string | null
  created_at: string
}

interface UploadAttachmentOptions {
  channelId: string
  messageId: string
  onProgress?: (progress: number) => void
  onSuccess?: (attachments: UploadedAttachment[]) => void
  onError?: (error: string) => void
}

interface FetchAttachmentsOptions {
  channelId: string
  limit?: number
  offset?: number
}

interface AttachmentWithUploader extends IAttachment {
  uploaded_by?: string
}

export function useChatAttachments() {
  const [isUploading, setIsUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { toast } = useToast()

  // Upload files for a message
  const uploadAttachments = useCallback(async (
    files: File[],
    options: UploadAttachmentOptions
  ): Promise<UploadedAttachment[]> => {
    if (!files.length) return []

    setIsUploading(true)
    setUploadProgress(0)
    setError(null)

    try {
      const formData = new FormData()
      formData.append('channel_id', options.channelId)
      formData.append('message_id', options.messageId)
      
      files.forEach(file => {
        formData.append('files', file)
      })

      // Use XMLHttpRequest for progress tracking
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest()

        xhr.upload.addEventListener('progress', (event) => {
          if (event.lengthComputable) {
            const progress = Math.round((event.loaded / event.total) * 100)
            setUploadProgress(progress)
            options.onProgress?.(progress)
          }
        })

        xhr.addEventListener('load', () => {
          setIsUploading(false)
          setUploadProgress(0)

          if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText)
            if (response.success) {
              const attachments = response.data.attachments as UploadedAttachment[]
              options.onSuccess?.(attachments)
              
              if (response.data.errors?.length > 0) {
                toast({
                  title: 'Partial Upload',
                  description: `${attachments.length} files uploaded, ${response.data.errors.length} failed`,
                  variant: 'default'
                })
              }
              
              resolve(attachments)
            } else {
              const errorMsg = response.error || 'Upload failed'
              setError(errorMsg)
              options.onError?.(errorMsg)
              reject(new Error(errorMsg))
            }
          } else {
            const errorMsg = `Upload failed with status ${xhr.status}`
            setError(errorMsg)
            options.onError?.(errorMsg)
            reject(new Error(errorMsg))
          }
        })

        xhr.addEventListener('error', () => {
          setIsUploading(false)
          setUploadProgress(0)
          const errorMsg = 'Network error during upload'
          setError(errorMsg)
          options.onError?.(errorMsg)
          reject(new Error(errorMsg))
        })

        xhr.open('POST', '/api/communication/attachments')
        xhr.send(formData)
      })
    } catch (error: unknown) {
      setIsUploading(false)
      setUploadProgress(0)
      const errorMsg = error instanceof Error ? error.message : 'Upload failed'
      setError(errorMsg)
      options.onError?.(errorMsg)
      
      toast({
        title: 'Upload Failed',
        description: errorMsg,
        variant: 'destructive'
      })
      
      return []
    }
  }, [toast])

  // Fetch attachments for a channel
  const fetchChannelAttachments = useCallback(async (
    options: FetchAttachmentsOptions
  ): Promise<{ attachments: AttachmentWithUploader[], total: number, hasMore: boolean }> => {
    setIsLoading(true)
    setError(null)

    try {
      const params = new URLSearchParams({
        channel_id: options.channelId,
        limit: String(options.limit || 50),
        offset: String(options.offset || 0)
      })

      const response = await fetch(`/api/communication/attachments?${params}`)
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch attachments')
      }

      return {
        attachments: data.data as AttachmentWithUploader[],
        total: data.meta?.total || 0,
        hasMore: data.meta?.hasMore || false
      }
    } catch (error: unknown) {
      const errorMsg = error instanceof Error ? error.message : 'Failed to fetch attachments'
      setError(errorMsg)
      throw error
    } finally {
      setIsLoading(false)
    }
  }, [])

  // Download an attachment
  const downloadAttachment = useCallback(async (attachment: IAttachment): Promise<void> => {
    if (!attachment.id) {
      toast({
        title: 'Download Failed',
        description: 'Attachment ID not available',
        variant: 'destructive'
      })
      return
    }

    try {
      // Get a fresh download URL from the consolidated API with Content-Disposition header
      const response = await fetch(`/api/communication/attachments?download=${attachment.id}`)
      
      if (!response.ok) {
        throw new Error('Failed to get download URL')
      }
      
      const data = await response.json()
      
      if (!data.success || !data.downloadUrl) {
        throw new Error(data.error || 'Download URL not available')
      }

      // Create download link with the signed URL
      const a = document.createElement('a')
      a.href = data.downloadUrl
      a.download = attachment.file_name
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)

      toast({
        title: 'Download Started',
        description: `Downloading ${attachment.file_name}`,
        variant: 'default'
      })
    } catch (error) {
      console.error('Download failed:', error)
      toast({
        title: 'Download Failed',
        description: 'Could not download the file',
        variant: 'destructive'
      })
    }
  }, [toast])

  // Preview attachment (open in new tab)
  const previewAttachment = useCallback((attachment: IAttachment): void => {
    if (!attachment.file_url) {
      toast({
        title: 'Preview Failed',
        description: 'File URL not available',
        variant: 'destructive'
      })
      return
    }
    window.open(attachment.file_url, '_blank')
  }, [toast])

  // Forward attachment to multiple channels
  const forwardAttachment = useCallback(async (
    attachmentId: string,
    targetChannelIds: string[],
    message?: string
  ): Promise<boolean> => {
    try {
      const response = await fetch('/api/communication/attachments', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          attachmentId,
          targetChannelIds,
          message
        })
      })

      const data = await response.json()

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Forward failed')
      }

      toast({
        title: 'Attachment Forwarded',
        description: `Sent to ${targetChannelIds.length} chat${targetChannelIds.length > 1 ? 's' : ''}`,
        variant: 'default'
      })

      return true
    } catch (error) {
      console.error('Forward failed:', error)
      toast({
        title: 'Forward Failed',
        description: error instanceof Error ? error.message : 'Could not forward the attachment',
        variant: 'destructive'
      })
      return false
    }
  }, [toast])

  // Copy attachment link to clipboard
  const copyAttachmentLink = useCallback(async (attachment: IAttachment): Promise<boolean> => {
    if (!attachment.file_url) {
      toast({
        title: 'Copy Failed',
        description: 'File URL not available',
        variant: 'destructive'
      })
      return false
    }

    try {
      await navigator.clipboard.writeText(attachment.file_url)
      toast({
        title: 'Link Copied',
        description: 'Attachment link copied to clipboard',
        variant: 'default'
      })
      return true
    } catch (error) {
      toast({
        title: 'Copy Failed',
        description: 'Could not copy link to clipboard',
        variant: 'destructive'
      })
      return false
    }
  }, [toast])

  return {
    // Upload
    uploadAttachments,
    isUploading,
    uploadProgress,
    
    // Fetch
    fetchChannelAttachments,
    isLoading,
    
    // Actions
    downloadAttachment,
    previewAttachment,
    forwardAttachment,
    copyAttachmentLink,
    
    // State
    error
  }
}
