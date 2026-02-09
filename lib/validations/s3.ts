import { z } from 'zod'

// File type constants that match S3Service configuration
export const FILE_TYPES = ['PROFILE_PICTURES', 'DOCUMENTS', 'EMAIL_ATTACHMENTS', 'CHAT_ATTACHMENTS'] as const
export type FileType = typeof FILE_TYPES[number]

// File size limits (in bytes)
export const FILE_SIZE_LIMITS = {
    PROFILE_PICTURES: 1 * 1024 * 1024, // 1MB
    DOCUMENTS: 25 * 1024 * 1024, // 25MB
    EMAIL_ATTACHMENTS: 25 * 1024 * 1024, // 25MB
    CHAT_ATTACHMENTS: 25 * 1024 * 1024 // 25MB for chat files
} as const

// Allowed MIME types for each file type
export const ALLOWED_MIME_TYPES = {
    PROFILE_PICTURES: [
        'image/jpeg',
        'image/png',
        'image/webp',
        'image/gif'
    ],
    DOCUMENTS: [
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
    ],
    EMAIL_ATTACHMENTS: [
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
    ],
    CHAT_ATTACHMENTS: [
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
        'audio/ogg'
    ]
} as const

// Base file validation schema
const fileSchema = z.object({
    name: z.string().min(1, 'File name is required').max(255, 'File name too long'),
    size: z.number().positive('File size must be positive'),
    type: z.string().min(1, 'File type is required')
})

// Upload validation schema
export const uploadFileSchema = z.object({
    fileType: z.enum(FILE_TYPES),
    clientId: z.string().optional()
}).and(fileSchema).refine((data) => {
    return data.size <= FILE_SIZE_LIMITS[data.fileType]
}, (data) => ({
    message: `File size exceeds maximum allowed size of ${FILE_SIZE_LIMITS[data.fileType] / (1024 * 1024)}MB for ${data.fileType}`,
    path: ['size']
})).refine((data) => {
    return ALLOWED_MIME_TYPES[data.fileType].includes(data.type as any)
}, (data) => ({
    message: `File type ${data.type} is not allowed for ${data.fileType}`,
    path: ['type']
}))

// Presigned URL request schema
export const presignedUrlSchema = z.object({
    fileName: z.string().min(1, 'File name is required').max(255, 'File name too long'),
    contentType: z.string().min(1, 'Content type is required'),
    fileType: z.enum(FILE_TYPES),
    clientId: z.string().optional()
}).refine((data) => {
    return ALLOWED_MIME_TYPES[data.fileType].includes(data.contentType as any)
}, (data) => ({
    message: `File type ${data.contentType} is not allowed for ${data.fileType}`,
    path: ['contentType']
}))

// File deletion schema
export const deleteFileSchema = z.object({
    key: z.string().min(1, 'File key is required'),
    fileType: z.enum(FILE_TYPES).optional()
})

// File metadata request schema
export const fileMetadataSchema = z.object({
    key: z.string().min(1, 'File key is required')
})

// File list request schema
export const listFilesSchema = z.object({
    fileType: z.enum(FILE_TYPES),
    limit: z.string().regex(/^\d+$/).transform(Number).default('50').refine(val => val <= 100, {
        message: 'Limit cannot exceed 100'
    }),
    userId: z.string().optional()
})

// Profile picture specific validation
export const profilePictureSchema = z.object({
    name: z.string().min(1).max(255),
    size: z.number().max(FILE_SIZE_LIMITS.PROFILE_PICTURES,
        `Profile picture must be less than ${FILE_SIZE_LIMITS.PROFILE_PICTURES / (1024 * 1024)}MB`),
    type: z.string().refine(type => ALLOWED_MIME_TYPES.PROFILE_PICTURES.includes(type as any), {
        message: 'Only JPEG, PNG, WebP, and GIF images are allowed for profile pictures'
    })
})

// Document file validation
export const documentSchema = z.object({
    name: z.string().min(1).max(255),
    size: z.number().max(FILE_SIZE_LIMITS.DOCUMENTS,
        `Document must be less than ${FILE_SIZE_LIMITS.DOCUMENTS / (1024 * 1024)}MB`),
    type: z.string().refine(type => ALLOWED_MIME_TYPES.DOCUMENTS.includes(type as any), {
        message: 'Unsupported document type'
    })
})

// Email attachment validation
export const emailAttachmentSchema = z.object({
    name: z.string().min(1).max(255),
    size: z.number().max(FILE_SIZE_LIMITS.EMAIL_ATTACHMENTS,
        `Attachment must be less than ${FILE_SIZE_LIMITS.EMAIL_ATTACHMENTS / (1024 * 1024)}MB`),
    type: z.string().refine(type => ALLOWED_MIME_TYPES.EMAIL_ATTACHMENTS.includes(type as any), {
        message: 'Unsupported attachment type'
    })
})

// Multiple file upload schema
export const multipleFilesSchema = z.object({
    files: z.array(fileSchema).min(1, 'At least one file is required').max(10, 'Maximum 10 files allowed'),
    fileType: z.enum(FILE_TYPES),
    clientId: z.string().optional()
}).refine((data) => {
    const maxSize = FILE_SIZE_LIMITS[data.fileType]
    const totalSize = data.files.reduce((sum, file) => sum + file.size, 0)
    const maxTotalSize = maxSize * data.files.length
    return totalSize <= maxTotalSize
}, {
    message: 'Total size of all files exceeds maximum allowed',
    path: ['files']
}).refine((data) => {
    const allowedTypes = ALLOWED_MIME_TYPES[data.fileType]
    return data.files.every(file => allowedTypes.includes(file.type as any))
}, {
    message: 'One or more files have unsupported types',
    path: ['files']
})

// S3 email attachment for SES integration
export const s3EmailAttachmentSchema = z.object({
    key: z.string().min(1, 'S3 key is required'),
    filename: z.string().min(1, 'Filename is required'),
    contentType: z.string().min(1, 'Content type is required')
})

// Extended email schema with S3 attachments
export const emailWithS3AttachmentsSchema = z.object({
    to: z.union([
        z.string().email(),
        z.array(z.string().email()).max(50)
    ]),
    cc: z.union([
        z.string().email(),
        z.array(z.string().email()).max(50)
    ]).optional(),
    bcc: z.union([
        z.string().email(),
        z.array(z.string().email()).max(50)
    ]).optional(),
    subject: z.string().min(1).max(200),
    htmlContent: z.string().max(50000).optional(),
    textContent: z.string().max(50000).optional(),
    category: z.enum(['auth', 'notification', 'marketing', 'system', 'client-portal']),
    priority: z.enum(['low', 'normal', 'high', 'urgent']).default('normal'),
    templateId: z.string().optional(),
    templateData: z.record(z.any()).optional(),
    replyTo: z.string().email().optional(),
    clientId: z.string().optional(),

    // S3 attachments
    s3Attachments: z.array(s3EmailAttachmentSchema).max(10).optional(),

    // Traditional base64 attachments (keep for backward compatibility)
    attachments: z.array(z.object({
        filename: z.string().min(1).max(255),
        content: z.string(), // Base64 encoded
        contentType: z.string().min(1)
    })).max(10).optional()
}).refine((data) => {
    // Ensure at least htmlContent or textContent is provided
    return data.htmlContent || data.textContent
}, {
    message: 'Either htmlContent or textContent must be provided',
    path: ['content']
}).refine((data) => {
    // Validate total attachment count
    const s3Count = data.s3Attachments?.length || 0
    const base64Count = data.attachments?.length || 0
    return (s3Count + base64Count) <= 10
}, {
    message: 'Total attachments (S3 + base64) cannot exceed 10',
    path: ['attachments']
})

// File type helper functions
export const getFileTypeFromMimeType = (mimeType: string): FileType | null => {
    for (const [fileType, allowedTypes] of Object.entries(ALLOWED_MIME_TYPES)) {
        if (allowedTypes.includes(mimeType as any)) {
            return fileType as FileType
        }
    }
    return null
}

export const validateFileForType = (file: { name: string; size: number; type: string }, fileType: FileType) => {
    const maxSize = FILE_SIZE_LIMITS[fileType]
    const allowedTypes = ALLOWED_MIME_TYPES[fileType]

    const errors: string[] = []

    if (file.size > maxSize) {
        errors.push(`File size exceeds maximum of ${maxSize / (1024 * 1024)}MB`)
    }

    if (!allowedTypes.includes(file.type as any)) {
        errors.push(`File type ${file.type} is not allowed`)
    }

    return {
        valid: errors.length === 0,
        errors
    }
}

// Type exports
export type UploadFileData = z.infer<typeof uploadFileSchema>
export type PresignedUrlData = z.infer<typeof presignedUrlSchema>
export type DeleteFileData = z.infer<typeof deleteFileSchema>
export type FileMetadataData = z.infer<typeof fileMetadataSchema>
export type ListFilesData = z.infer<typeof listFilesSchema>
export type ProfilePictureData = z.infer<typeof profilePictureSchema>
export type DocumentData = z.infer<typeof documentSchema>
export type EmailAttachmentData = z.infer<typeof emailAttachmentSchema>
export type MultipleFilesData = z.infer<typeof multipleFilesSchema>
export type S3EmailAttachment = z.infer<typeof s3EmailAttachmentSchema>
export type EmailWithS3Attachments = z.infer<typeof emailWithS3AttachmentsSchema>