'use client'

import React, { useState, useCallback, useRef } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { X, Upload, File, Image, FileText, AlertCircle, CheckCircle } from 'lucide-react'
import { useFileUpload } from '@/hooks/use-file-upload'
import { validateFileForType, type FileType } from '@/lib/validations/s3'
import { cn } from '@/lib/utils'

interface FileUploadProps {
    fileType: FileType
    multiple?: boolean
    maxFiles?: number
    onFilesUploaded?: (files: Array<{
        key: string
        url: string
        size: number
        contentType: string
        originalName: string
    }>) => void
    onError?: (error: string) => void
    className?: string
    clientId?: string
    disabled?: boolean
    accept?: string
}

interface FileState {
    file: File
    id: string
    status: 'pending' | 'uploading' | 'success' | 'error'
    progress: number
    error?: string
    uploadedData?: {
        key: string
        url: string
        size: number
        contentType: string
        originalName: string
    }
}

export function FileUpload({
    fileType,
    multiple = false,
    maxFiles = 10,
    onFilesUploaded,
    onError,
    className,
    clientId,
    disabled = false,
    accept
}: FileUploadProps) {
    const [files, setFiles] = useState<FileState[]>([])
    const [isDragOver, setIsDragOver] = useState(false)
    const fileInputRef = useRef<HTMLInputElement>(null)

    const { uploadFile, isUploading } = useFileUpload()

    const getFileIcon = (file: File) => {
        if (file.type.startsWith('image/')) return <Image className="h-4 w-4" />
        if (file.type.includes('pdf')) return <FileText className="h-4 w-4" />
        return <File className="h-4 w-4" />
    }

    const getFileTypeLabel = (fileType: FileType) => {
        switch (fileType) {
            case 'PROFILE_PICTURES': return 'Profile Pictures'
            case 'DOCUMENTS': return 'Documents'
            case 'EMAIL_ATTACHMENTS': return 'Email Attachments'
            default: return 'Files'
        }
    }

    const validateFiles = (selectedFiles: File[]): { valid: File[], invalid: Array<{ file: File, errors: string[] }> } => {
        const valid: File[] = []
        const invalid: Array<{ file: File, errors: string[] }> = []

        for (const file of selectedFiles) {
            const validation = validateFileForType(
                { name: file.name, size: file.size, type: file.type },
                fileType
            )

            if (validation.valid) {
                valid.push(file)
            } else {
                invalid.push({ file, errors: validation.errors })
            }
        }

        return { valid, invalid }
    }

    const handleFileSelect = useCallback((selectedFiles: File[]) => {
        if (disabled) return

        // Check file limits
        const currentFileCount = files.length
        const availableSlots = maxFiles - currentFileCount

        if (selectedFiles.length > availableSlots) {
            onError?.(`Cannot add more than ${maxFiles} files. You can add ${availableSlots} more files.`)
            return
        }

        // Validate files
        const { valid, invalid } = validateFiles(selectedFiles)

        // Show errors for invalid files
        if (invalid.length > 0) {
            const errorMessages = invalid.map(({ file, errors }) =>
                `${file.name}: ${errors.join(', ')}`
            ).join('\n')
            onError?.(errorMessages)
        }

        // Add valid files to state
        if (valid.length > 0) {
            const newFiles: FileState[] = valid.map(file => ({
                file,
                id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                status: 'pending',
                progress: 0
            }))

            setFiles(prev => [...prev, ...newFiles])
        }
    }, [files.length, maxFiles, onError, disabled, fileType])

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault()
        setIsDragOver(false)

        if (disabled) return

        const droppedFiles = Array.from(e.dataTransfer.files)
        if (!multiple && droppedFiles.length > 1) {
            onError?.('Only one file is allowed')
            return
        }

        handleFileSelect(droppedFiles)
    }, [handleFileSelect, multiple, onError, disabled])

    const handleFileInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFiles = Array.from(e.target.files || [])
        handleFileSelect(selectedFiles)

        // Reset input value to allow selecting the same file again
        if (fileInputRef.current) {
            fileInputRef.current.value = ''
        }
    }, [handleFileSelect])

    const removeFile = useCallback((fileId: string) => {
        setFiles(prev => prev.filter(f => f.id !== fileId))
    }, [])

    const uploadFiles = useCallback(async () => {
        const pendingFiles = files.filter(f => f.status === 'pending')
        if (pendingFiles.length === 0) return

        const uploadedFiles: Array<{
            key: string
            url: string
            size: number
            contentType: string
            originalName: string
        }> = []

        for (const fileState of pendingFiles) {
            try {
                // Update status to uploading
                setFiles(prev => prev.map(f =>
                    f.id === fileState.id
                        ? { ...f, status: 'uploading', progress: 0 }
                        : f
                ))

                const result = await uploadFile(fileState.file, {
                    fileType,
                    clientId,
                    onProgress: (progress) => {
                        setFiles(prev => prev.map(f =>
                            f.id === fileState.id
                                ? { ...f, progress }
                                : f
                        ))
                    },
                    onSuccess: (uploadedFile) => {
                        setFiles(prev => prev.map(f =>
                            f.id === fileState.id
                                ? { ...f, status: 'success', uploadedData: uploadedFile }
                                : f
                        ))
                        uploadedFiles.push(uploadedFile)
                    },
                    onError: (error) => {
                        setFiles(prev => prev.map(f =>
                            f.id === fileState.id
                                ? { ...f, status: 'error', error }
                                : f
                        ))
                    }
                })

                if (!result) {
                    // Error was already handled in onError callback
                    continue
                }

            } catch (error: any) {
                setFiles(prev => prev.map(f =>
                    f.id === fileState.id
                        ? { ...f, status: 'error', error: error.message }
                        : f
                ))
            }
        }

        if (uploadedFiles.length > 0) {
            onFilesUploaded?.(uploadedFiles)
        }
    }, [files, uploadFile, fileType, clientId, onFilesUploaded])

    const hasValidFiles = files.some(f => f.status === 'pending')
    const allFilesProcessed = files.length > 0 && files.every(f => f.status === 'success' || f.status === 'error')

    return (
        <Card className={cn("w-full", className)}>
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Upload className="h-5 w-5" />
                    Upload {getFileTypeLabel(fileType)}
                </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
                {/* Drop Zone */}
                <div
                    className={cn(
                        "border-2 border-dashed rounded-lg p-8 text-center transition-colors",
                        isDragOver ? "border-primary bg-primary/5" : "border-muted-foreground/25",
                        disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer hover:border-primary hover:bg-primary/5"
                    )}
                    onDrop={handleDrop}
                    onDragOver={(e) => {
                        e.preventDefault()
                        if (!disabled) setIsDragOver(true)
                    }}
                    onDragLeave={() => setIsDragOver(false)}
                    onClick={() => !disabled && fileInputRef.current?.click()}
                >
                    <Upload className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-lg font-medium mb-2">
                        {isDragOver ? 'Drop files here' : 'Click to upload or drag and drop'}
                    </p>
                    <p className="text-sm text-muted-foreground">
                        {multiple ? `Up to ${maxFiles} files` : 'Single file only'}
                    </p>
                </div>

                <input
                    ref={fileInputRef}
                    type="file"
                    multiple={multiple}
                    accept={accept}
                    onChange={handleFileInputChange}
                    className="hidden"
                    disabled={disabled}
                />

                {/* File List */}
                {files.length > 0 && (
                    <div className="space-y-2">
                        <h4 className="font-medium">Selected Files ({files.length}/{maxFiles})</h4>
                        <div className="space-y-2">
                            {files.map((fileState) => (
                                <div key={fileState.id} className="flex items-center gap-3 p-3 border rounded-lg">
                                    <div className="flex-shrink-0">
                                        {getFileIcon(fileState.file)}
                                    </div>

                                    <div className="flex-1 min-w-0">
                                        <p className="text-sm font-medium truncate">{fileState.file.name}</p>
                                        <p className="text-xs text-muted-foreground">
                                            {(fileState.file.size / 1024 / 1024).toFixed(2)} MB
                                        </p>

                                        {fileState.status === 'uploading' && (
                                            <Progress value={fileState.progress} className="mt-1" />
                                        )}

                                        {fileState.error && (
                                            <p className="text-xs text-destructive mt-1">{fileState.error}</p>
                                        )}
                                    </div>

                                    <div className="flex items-center gap-2">
                                        <Badge variant={
                                            fileState.status === 'success' ? 'default' :
                                                fileState.status === 'error' ? 'destructive' :
                                                    fileState.status === 'uploading' ? 'secondary' : 'outline'
                                        }>
                                            {fileState.status === 'success' && <CheckCircle className="h-3 w-3 mr-1" />}
                                            {fileState.status === 'error' && <AlertCircle className="h-3 w-3 mr-1" />}
                                            {fileState.status === 'pending' && 'Pending'}
                                            {fileState.status === 'uploading' && 'Uploading'}
                                            {fileState.status === 'success' && 'Success'}
                                            {fileState.status === 'error' && 'Error'}
                                        </Badge>

                                        {(fileState.status === 'pending' || fileState.status === 'error') && (
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={() => removeFile(fileState.id)}
                                                disabled={disabled}
                                            >
                                                <X className="h-4 w-4" />
                                            </Button>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Upload Button */}
                {hasValidFiles && (
                    <Button
                        onClick={uploadFiles}
                        disabled={isUploading || disabled}
                        className="w-full"
                    >
                        {isUploading ? 'Uploading...' : `Upload ${files.filter(f => f.status === 'pending').length} file(s)`}
                    </Button>
                )}

                {allFilesProcessed && (
                    <Button
                        variant="outline"
                        onClick={() => setFiles([])}
                        className="w-full"
                        disabled={disabled}
                    >
                        Clear All
                    </Button>
                )}
            </CardContent>
        </Card>
    )
}