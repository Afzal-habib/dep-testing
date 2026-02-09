import { useState, useCallback } from 'react'
import { useToast } from '@/hooks/use-toast'
import type { FileType } from '@/lib/validations/s3'

interface UploadedFile {
    key: string
    url: string
    size: number
    contentType: string
    originalName: string
}

interface UploadOptions {
    fileType: FileType
    clientId?: string
    onProgress?: (progress: number) => void
    onSuccess?: (file: UploadedFile) => void
    onError?: (error: string) => void
}

interface PresignedUploadData {
    uploadUrl: string
    key: string
    fields: Record<string, string>
}

export function useFileUpload() {
    const [isUploading, setIsUploading] = useState(false)
    const [uploadProgress, setUploadProgress] = useState(0)
    const [error, setError] = useState<string | null>(null)
    const { toast } = useToast()

    const uploadFile = useCallback(async (file: File, options: UploadOptions): Promise<UploadedFile | null> => {
        setIsUploading(true)
        setUploadProgress(0)
        setError(null)

        try {
            // Method 1: Direct upload via API route (for smaller files)
            if (file.size <= 5 * 1024 * 1024) { // 5MB threshold
                return await uploadViaAPI(file, options)
            } else {
                // Method 2: Presigned URL upload (for larger files)
                return await uploadViaPresignedUrl(file, options)
            }
        } catch (error: any) {
            const errorMessage = error.message || 'Failed to upload file'
            setError(errorMessage)
            options.onError?.(errorMessage)

            toast({
                title: "Upload Failed",
                description: errorMessage,
                variant: "destructive"
            })

            return null
        } finally {
            setIsUploading(false)
            setUploadProgress(0)
        }
    }, [toast])

    const uploadViaAPI = async (file: File, options: UploadOptions): Promise<UploadedFile> => {
        const formData = new FormData()
        formData.append('file', file)
        formData.append('fileType', options.fileType)
        if (options.clientId) {
            formData.append('clientId', options.clientId)
        }

        // Create XMLHttpRequest for progress tracking
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
                if (xhr.status === 201) {
                    const response = JSON.parse(xhr.responseText)
                    if (response.success) {
                        const uploadedFile: UploadedFile = {
                            key: response.data.key,
                            url: response.data.url,
                            size: response.data.size,
                            contentType: response.data.contentType,
                            originalName: file.name
                        }
                        options.onSuccess?.(uploadedFile)
                        toast({
                            title: "Upload Successful",
                            description: `${file.name} has been uploaded successfully.`,
                            variant: "default"
                        })
                        resolve(uploadedFile)
                    } else {
                        reject(new Error(response.error || 'Upload failed'))
                    }
                } else {
                    reject(new Error(`Upload failed with status ${xhr.status}`))
                }
            })

            xhr.addEventListener('error', () => {
                reject(new Error('Network error during upload'))
            })

            xhr.open('POST', '/api/files')
            xhr.send(formData)
        })
    }

    const uploadViaPresignedUrl = async (file: File, options: UploadOptions): Promise<UploadedFile> => {
        // Step 1: Get presigned URL
        const presignedResponse = await fetch('/api/files/presigned-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                fileName: file.name,
                contentType: file.type,
                fileType: options.fileType,
                clientId: options.clientId
            })
        })

        if (!presignedResponse.ok) {
            const errorData = await presignedResponse.json()
            throw new Error(errorData.error || 'Failed to get upload URL')
        }

        const { data: presignedData }: { data: PresignedUploadData } = await presignedResponse.json()

        // Step 2: Upload to S3 using presigned URL
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest()

            xhr.upload.addEventListener('progress', (event) => {
                if (event.lengthComputable) {
                    const progress = Math.round((event.loaded / event.total) * 100)
                    setUploadProgress(progress)
                    options.onProgress?.(progress)
                }
            })

            xhr.addEventListener('load', async () => {
                if (xhr.status === 200) {
                    try {
                        // Get the file URL after successful upload
                        const fileUrl = await getFileUrl(presignedData.key, options.fileType)

                        const uploadedFile: UploadedFile = {
                            key: presignedData.key,
                            url: fileUrl,
                            size: file.size,
                            contentType: file.type,
                            originalName: file.name
                        }

                        options.onSuccess?.(uploadedFile)
                        toast({
                            title: "Upload Successful",
                            description: `${file.name} has been uploaded successfully.`,
                            variant: "default"
                        })
                        resolve(uploadedFile)
                    } catch (error: any) {
                        reject(new Error('Failed to get file URL after upload'))
                    }
                } else {
                    reject(new Error(`Upload to S3 failed with status ${xhr.status}`))
                }
            })

            xhr.addEventListener('error', () => {
                reject(new Error('Network error during S3 upload'))
            })

            xhr.open('PUT', presignedData.uploadUrl)
            xhr.setRequestHeader('Content-Type', file.type)
            xhr.send(file)
        })
    }

    const getFileUrl = useCallback(async (key: string, fileType: FileType): Promise<string> => {
        const response = await fetch(`/api/files?key=${encodeURIComponent(key)}&fileType=${fileType}`)

        if (!response.ok) {
            throw new Error('Failed to get file URL')
        }

        const data = await response.json()
        return data.data.url
    }, [])

    const deleteFile = useCallback(async (key: string): Promise<boolean> => {
        try {
            const response = await fetch(`/api/files/${encodeURIComponent(key)}`, {
                method: 'DELETE'
            })

            if (!response.ok) {
                const errorData = await response.json()
                throw new Error(errorData.error || 'Failed to delete file')
            }

            toast({
                title: "File Deleted",
                description: "File has been deleted successfully.",
                variant: "default"
            })

            return true
        } catch (error: any) {
            const errorMessage = error.message || 'Failed to delete file'
            setError(errorMessage)

            toast({
                title: "Delete Failed",
                description: errorMessage,
                variant: "destructive"
            })

            return false
        }
    }, [toast])

    const getFileMetadata = useCallback(async (key: string) => {
        try {
            const response = await fetch(`/api/files/${encodeURIComponent(key)}`)

            if (!response.ok) {
                const errorData = await response.json()
                throw new Error(errorData.error || 'Failed to get file metadata')
            }

            const data = await response.json()
            return data.data
        } catch (error: any) {
            setError(error.message)
            return null
        }
    }, [])

    const uploadMultipleFiles = useCallback(async (
        files: File[],
        options: UploadOptions
    ): Promise<UploadedFile[]> => {
        const uploadPromises = files.map(file => uploadFile(file, {
            ...options,
            onProgress: undefined, // Don't track individual progress for multiple files
            onSuccess: undefined,
            onError: undefined
        }))

        try {
            const results = await Promise.allSettled(uploadPromises)
            const successful: UploadedFile[] = []
            const failed: string[] = []

            results.forEach((result, index) => {
                if (result.status === 'fulfilled' && result.value) {
                    successful.push(result.value)
                } else {
                    failed.push(files[index].name)
                }
            })

            if (failed.length > 0) {
                toast({
                    title: "Partial Upload Success",
                    description: `${successful.length} files uploaded successfully, ${failed.length} failed.`,
                    variant: "default"
                })
            } else {
                toast({
                    title: "All Files Uploaded",
                    description: `Successfully uploaded ${successful.length} files.`,
                    variant: "default"
                })
            }

            return successful
        } catch (error: any) {
            toast({
                title: "Upload Failed",
                description: "Failed to upload files.",
                variant: "destructive"
            })
            return []
        }
    }, [uploadFile, toast])

    return {
        uploadFile,
        deleteFile,
        getFileUrl,
        getFileMetadata,
        uploadMultipleFiles,
        isUploading,
        uploadProgress,
        error
    }
}