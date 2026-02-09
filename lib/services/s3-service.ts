import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import crypto from 'crypto'

// File type configurations
export const S3_CONFIG = {
    PROFILE_PICTURES: {
        folder: 'profile-pictures',
        maxSize: 1 * 1024 * 1024, // 1MB
        allowedTypes: ['image/jpeg', 'image/png', 'image/webp', 'image/gif'] as const,
        expiresIn: 3600 * 24 * 7 // 7 days for profile picture URLs (maximum AWS limit)
    },
    DOCUMENTS: {
        folder: 'documents',
        maxSize: 25 * 1024 * 1024, // 25MB
        allowedTypes: [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'text/plain',
            'text/csv',
            'image/jpeg',
            'image/png',
            'image/webp',
            'image/gif'
        ] as const,
        expiresIn: 3600 * 24 // 24 hours for document URLs
    },
    EMAIL_ATTACHMENTS: {
        folder: 'email-attachments',
        maxSize: 25 * 1024 * 1024, // 25MB
        allowedTypes: [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'text/plain',
            'text/csv',
            'image/jpeg',
            'image/png',
            'image/webp',
            'image/gif',
            'application/zip',
            'application/x-zip-compressed'
        ] as const,
        expiresIn: 3600 * 24 * 3 // 3 days for email attachments (within AWS limit)
    },
    CHAT_ATTACHMENTS: {
        folder: 'chat-attachments',
        maxSize: 25 * 1024 * 1024, // 25MB
        allowedTypes: [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'text/plain',
            'text/csv',
            'image/jpeg',
            'image/png',
            'image/webp',
            'image/gif',
            'image/svg+xml',
            'application/zip',
            'application/x-zip-compressed',
            'video/mp4',
            'video/webm',
            'audio/mpeg',
            'audio/mp3',
            'audio/wav',
            'audio/ogg',
            'audio/webm',
            'audio/webm;codecs=opus'
        ] as const,
        expiresIn: 3600 * 24 * 7 // 7 days for chat attachments
    }
} as const

export type FileType = keyof typeof S3_CONFIG

interface UploadParams {
    file: Buffer
    fileName: string
    contentType: string
    fileType: FileType
    userId: string
    clientId?: string
    metadata?: Record<string, string>
}

interface FileMetadata {
    originalName: string
    size: number
    contentType: string
    uploadedBy: string
    clientId?: string
    uploadedAt: string
    [key: string]: any
}

export class S3Service {
    private static s3Client = new S3Client({
        region: process.env.AWS_REGION!,
        credentials: {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        },
    })

    private static bucketName = process.env.AWS_S3_BUCKET_NAME!

    /**
     * Generate a unique file key for S3
     */
    private static generateFileKey(fileType: FileType, fileName: string, userId: string): string {
        const timestamp = Date.now()
        const randomHash = crypto.randomBytes(8).toString('hex')
        const sanitizedFileName = fileName.replace(/[^a-zA-Z0-9.-]/g, '_')
        const config = S3_CONFIG[fileType]

        return `${config.folder}/${userId}/${timestamp}-${randomHash}-${sanitizedFileName}`
    }

    /**
     * Validate file before upload
     */
    private static validateFile(file: Buffer, contentType: string, fileType: FileType): { valid: boolean; error?: string } {
        const config = S3_CONFIG[fileType]

        // Check file size
        if (file.length > config.maxSize) {
            return {
                valid: false,
                error: `File size exceeds maximum allowed size of ${config.maxSize / (1024 * 1024)}MB for ${fileType}`
            }
        }

        // Check content type - handle MIME types with parameters (e.g., audio/webm;codecs=opus)
        const baseContentType = contentType.split(';')[0].trim()
        const isAllowed = (config.allowedTypes as readonly string[]).some(
            allowed => allowed === contentType || allowed === baseContentType || allowed.startsWith(baseContentType)
        )
        
        if (!isAllowed) {
            return {
                valid: false,
                error: `File type ${contentType} is not allowed for ${fileType}`
            }
        } return { valid: true }
    }

    /**
     * Upload file to S3
     */
    static async uploadFile(params: UploadParams): Promise<{
        success: boolean
        data?: {
            key: string
            url: string
            size: number
            contentType: string
        }
        error?: string
    }> {
        try {
            // Validate file
            const validation = this.validateFile(params.file, params.contentType, params.fileType)
            if (!validation.valid) {
                return { success: false, error: validation.error }
            }

            // Generate file key
            const key = this.generateFileKey(params.fileType, params.fileName, params.userId)

            // Prepare metadata
            const metadata: FileMetadata = {
                originalName: params.fileName,
                size: params.file.length,
                contentType: params.contentType,
                uploadedBy: params.userId,
                uploadedAt: new Date().toISOString(),
                fileType: params.fileType,
                ...params.metadata
            }

            if (params.clientId) {
                metadata.clientId = params.clientId
            }

            // Upload to S3
            const command = new PutObjectCommand({
                Bucket: this.bucketName,
                Key: key,
                Body: params.file,
                ContentType: params.contentType,
                Metadata: Object.entries(metadata).reduce((acc, [k, v]) => {
                    acc[k] = String(v)
                    return acc
                }, {} as Record<string, string>),
                ServerSideEncryption: 'AES256'
            })

            await this.s3Client.send(command)

            // Generate presigned URL for access
            const url = await this.getPresignedUrl(key, params.fileType)

            return {
                success: true,
                data: {
                    key,
                    url,
                    size: params.file.length,
                    contentType: params.contentType
                }
            }

        } catch (error: any) {
            console.error('S3 upload error:', error)
            return {
                success: false,
                error: error.message || 'Failed to upload file'
            }
        }
    }

    /**
     * Get presigned URL for file access
     */
    static async getPresignedUrl(key: string, fileType: FileType): Promise<string> {
        const config = S3_CONFIG[fileType]

        const command = new GetObjectCommand({
            Bucket: this.bucketName,
            Key: key
        })

        return getSignedUrl(this.s3Client, command, {
            expiresIn: config.expiresIn
        })
    }

    /**
     * Get presigned URL for file download with Content-Disposition header
     * This forces the browser to download the file instead of displaying it
     */
    static async getPresignedDownloadUrl(key: string, fileType: FileType, fileName: string): Promise<string> {
        const config = S3_CONFIG[fileType]

        const command = new GetObjectCommand({
            Bucket: this.bucketName,
            Key: key,
            ResponseContentDisposition: `attachment; filename="${encodeURIComponent(fileName)}"`
        })

        return getSignedUrl(this.s3Client, command, {
            expiresIn: config.expiresIn
        })
    }

    /**
     * Get presigned URL for file upload (for direct browser uploads)
     */
    static async getPresignedUploadUrl(
        fileName: string,
        contentType: string,
        fileType: FileType,
        userId: string,
        clientId?: string
    ): Promise<{
        success: boolean
        data?: {
            uploadUrl: string
            key: string
            fields: Record<string, string>
        }
        error?: string
    }> {
        try {
            // Validate content type
            const config = S3_CONFIG[fileType]
            if (!(config.allowedTypes as readonly string[]).includes(contentType)) {
                return {
                    success: false,
                    error: `File type ${contentType} is not allowed for ${fileType}`
                }
            }

            const key = this.generateFileKey(fileType, fileName, userId)

            const metadata: Record<string, string> = {
                'original-name': fileName,
                'uploaded-by': userId,
                'uploaded-at': new Date().toISOString(),
                'file-type': fileType
            }

            if (clientId) {
                metadata['client-id'] = clientId
            }

            const command = new PutObjectCommand({
                Bucket: this.bucketName,
                Key: key,
                ContentType: contentType,
                Metadata: metadata,
                ServerSideEncryption: 'AES256'
            })

            const uploadUrl = await getSignedUrl(this.s3Client, command, {
                expiresIn: 3600 // 1 hour for upload URLs (sufficient for most uploads)
            })

            return {
                success: true,
                data: {
                    uploadUrl,
                    key,
                    fields: metadata
                }
            }

        } catch (error: any) {
            console.error('S3 presigned URL error:', error)
            return {
                success: false,
                error: error.message || 'Failed to generate upload URL'
            }
        }
    }

    /**
     * Delete file from S3
     */
    static async deleteFile(key: string): Promise<{ success: boolean; error?: string }> {
        try {
            const command = new DeleteObjectCommand({
                Bucket: this.bucketName,
                Key: key
            })

            await this.s3Client.send(command)

            return { success: true }

        } catch (error: any) {
            console.error('S3 delete error:', error)
            return {
                success: false,
                error: error.message || 'Failed to delete file'
            }
        }
    }

    /**
     * Get file metadata from S3
     */
    static async getFileMetadata(key: string): Promise<{
        success: boolean
        data?: {
            size: number
            contentType: string
            lastModified: Date
            metadata: Record<string, string>
        }
        error?: string
    }> {
        try {
            const command = new HeadObjectCommand({
                Bucket: this.bucketName,
                Key: key
            })

            const response = await this.s3Client.send(command)

            return {
                success: true,
                data: {
                    size: response.ContentLength || 0,
                    contentType: response.ContentType || '',
                    lastModified: response.LastModified || new Date(),
                    metadata: response.Metadata || {}
                }
            }

        } catch (error: any) {
            console.error('S3 metadata error:', error)
            return {
                success: false,
                error: error.message || 'Failed to get file metadata'
            }
        }
    }

    /**
     * Get file as buffer (for email attachments)
     */
    static async getFileBuffer(key: string): Promise<{
        success: boolean
        data?: {
            buffer: Buffer
            contentType: string
            metadata: Record<string, string>
        }
        error?: string
    }> {
        try {
            const command = new GetObjectCommand({
                Bucket: this.bucketName,
                Key: key
            })

            const response = await this.s3Client.send(command)

            if (!response.Body) {
                return {
                    success: false,
                    error: 'File not found or empty'
                }
            }

            // Convert stream to buffer
            const chunks: Uint8Array[] = []
            const reader = response.Body.transformToWebStream().getReader()

            while (true) {
                const { done, value } = await reader.read()
                if (done) break
                chunks.push(value)
            }

            const buffer = Buffer.concat(chunks)

            return {
                success: true,
                data: {
                    buffer,
                    contentType: response.ContentType || '',
                    metadata: response.Metadata || {}
                }
            }

        } catch (error: any) {
            console.error('S3 file buffer error:', error)
            return {
                success: false,
                error: error.message || 'Failed to get file'
            }
        }
    }

    /**
     * List files by user and type
     */
    static async listUserFiles(
        userId: string,
        fileType: FileType,
        limit = 50
    ): Promise<{
        success: boolean
        data?: Array<{
            key: string
            url: string
            metadata: Record<string, string>
        }>
        error?: string
    }> {
        try {
            const config = S3_CONFIG[fileType]
            const prefix = `${config.folder}/${userId}/`

            // Note: This is a simplified version. For production, you might want to use S3's ListObjectsV2
            // and implement proper pagination. For now, we'll return empty array as this would require
            // additional implementation for proper file listing.

            return {
                success: true,
                data: []
            }

        } catch (error: any) {
            console.error('S3 list files error:', error)
            return {
                success: false,
                error: error.message || 'Failed to list files'
            }
        }
    }
}