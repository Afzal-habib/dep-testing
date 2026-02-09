'use client'

import React, { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { X, Paperclip, File, Image, FileText, Download } from 'lucide-react'
import { FileUpload } from '../upload/file-upload'
import type { S3EmailAttachment } from '@/lib/validations/s3'
import { cn } from '@/lib/utils'

interface EmailAttachmentSelectorProps {
    attachments: S3EmailAttachment[]
    onAttachmentsChange: (attachments: S3EmailAttachment[]) => void
    maxAttachments?: number
    className?: string
    disabled?: boolean
}

interface UploadedFile {
    key: string
    url: string
    size: number
    contentType: string
    originalName: string
}

export function EmailAttachmentSelector({
    attachments,
    onAttachmentsChange,
    maxAttachments = 10,
    className,
    disabled = false
}: EmailAttachmentSelectorProps) {
    const [showUploader, setShowUploader] = useState(false)

    const getFileIcon = (contentType: string) => {
        if (contentType.startsWith('image/')) return <Image className="h-4 w-4" />
        if (contentType.includes('pdf')) return <FileText className="h-4 w-4" />
        return <File className="h-4 w-4" />
    }

    const formatFileSize = (bytes: number): string => {
        if (bytes === 0) return '0 Bytes'

        const k = 1024
        const sizes = ['Bytes', 'KB', 'MB', 'GB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))

        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
    }

    const handleFilesUploaded = (uploadedFiles: UploadedFile[]) => {
        const newAttachments: S3EmailAttachment[] = uploadedFiles.map(file => ({
            key: file.key,
            filename: file.originalName,
            contentType: file.contentType
        }))

        const updatedAttachments = [...attachments, ...newAttachments]
        onAttachmentsChange(updatedAttachments)
        setShowUploader(false)
    }

    const removeAttachment = (index: number) => {
        const updatedAttachments = attachments.filter((_, i) => i !== index)
        onAttachmentsChange(updatedAttachments)
    }

    const canAddMore = attachments.length < maxAttachments

    return (
        <div className={cn("space-y-4", className)}>
            {/* Current Attachments */}
            {attachments.length > 0 && (
                <Card>
                    <CardHeader className="pb-3">
                        <CardTitle className="text-sm flex items-center gap-2">
                            <Paperclip className="h-4 w-4" />
                            Attachments ({attachments.length}/{maxAttachments})
                        </CardTitle>
                    </CardHeader>
                    <CardContent className="pt-0">
                        <div className="space-y-2">
                            {attachments.map((attachment, index) => (
                                <div key={`${attachment.key}-${index}`} className="flex items-center justify-between p-2 border rounded-lg">
                                    <div className="flex items-center gap-3 flex-1 min-w-0">
                                        <div className="flex-shrink-0">
                                            {getFileIcon(attachment.contentType)}
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm font-medium truncate">
                                                {attachment.filename}
                                            </p>
                                            <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                                <Badge variant="outline" className="text-xs">
                                                    {attachment.contentType}
                                                </Badge>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-1">
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => window.open(attachment.key, '_blank')}
                                            disabled={disabled}
                                            title="Preview file"
                                        >
                                            <Download className="h-4 w-4" />
                                        </Button>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => removeAttachment(index)}
                                            disabled={disabled}
                                            title="Remove attachment"
                                        >
                                            <X className="h-4 w-4" />
                                        </Button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* Add Attachment Button */}
            {!showUploader && canAddMore && (
                <Button
                    variant="outline"
                    onClick={() => setShowUploader(true)}
                    disabled={disabled}
                    className="w-full"
                >
                    <Paperclip className="h-4 w-4 mr-2" />
                    Add Attachments ({attachments.length}/{maxAttachments})
                </Button>
            )}

            {/* File Uploader */}
            {showUploader && (
                <Card>
                    <CardContent className="pt-6">
                        <FileUpload
                            fileType="EMAIL_ATTACHMENTS"
                            multiple={true}
                            maxFiles={maxAttachments - attachments.length}
                            onFilesUploaded={handleFilesUploaded}
                            onError={(error: string) => {
                                console.error('Upload error:', error)
                                // You could show a toast here
                            }}
                            disabled={disabled}
                            accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.csv,.jpg,.jpeg,.png,.webp,.gif,.zip"
                        />

                        <div className="flex gap-2 mt-4">
                            <Button
                                variant="outline"
                                onClick={() => setShowUploader(false)}
                                disabled={disabled}
                                className="flex-1"
                            >
                                Cancel
                            </Button>
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* Attachment Limits Info */}
            {attachments.length === 0 && !showUploader && (
                <div className="text-center p-4 border-2 border-dashed border-muted rounded-lg">
                    <Paperclip className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">
                        No attachments added yet
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                        Max {maxAttachments} files, 25MB each
                    </p>
                </div>
            )}

            {!canAddMore && !showUploader && (
                <div className="text-center p-2">
                    <Badge variant="secondary">
                        Maximum attachments reached ({maxAttachments})
                    </Badge>
                </div>
            )}
        </div>
    )
}