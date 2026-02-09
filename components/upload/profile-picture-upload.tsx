'use client'

import React, { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Camera, Upload, X, User } from 'lucide-react'
import { useFileUpload } from '@/hooks/use-file-upload'
import { cn } from '@/lib/utils'

interface ProfilePictureUploadProps {
    currentImageUrl?: string
    currentImageKey?: string
    onImageUploaded?: (imageData: {
        key: string
        url: string
        size: number
        contentType: string
        originalName: string
    }) => void
    onImageRemoved?: () => void
    className?: string
    disabled?: boolean
    size?: 'sm' | 'md' | 'lg' | 'xl'
    showRemoveButton?: boolean
    fallbackText?: string
}

const sizeClasses = {
    sm: 'h-16 w-16',
    md: 'h-24 w-24',
    lg: 'h-32 w-32',
    xl: 'h-40 w-40'
}

export function ProfilePictureUpload({
    currentImageUrl,
    currentImageKey,
    onImageUploaded,
    onImageRemoved,
    className,
    disabled = false,
    size = 'lg',
    showRemoveButton = true,
    fallbackText = 'User'
}: ProfilePictureUploadProps) {
    const [previewUrl, setPreviewUrl] = useState<string | null>(null)
    const [isUploading, setIsUploading] = useState(false)

    const { uploadFile, deleteFile } = useFileUpload()

    const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0]
        if (!file || disabled) return

        // Validate file type and size
        if (!file.type.startsWith('image/')) {
            alert('Please select an image file')
            return
        }

        if (file.size > 1024 * 1024) { // 1MB limit
            alert('Image must be less than 1MB')
            return
        }

        // Create preview
        const reader = new FileReader()
        reader.onload = (e) => {
            setPreviewUrl(e.target?.result as string)
        }
        reader.readAsDataURL(file)

        // Upload file
        setIsUploading(true)
        try {
            const result = await uploadFile(file, {
                fileType: 'PROFILE_PICTURES',
                onSuccess: (uploadedFile) => {
                    onImageUploaded?.(uploadedFile)
                    setPreviewUrl(null) // Clear preview since we now have the actual URL
                },
                onError: (error) => {
                    alert(`Upload failed: ${error}`)
                    setPreviewUrl(null)
                }
            })
        } catch (error) {
            console.error('Upload error:', error)
            setPreviewUrl(null)
        } finally {
            setIsUploading(false)
            // Reset input
            event.target.value = ''
        }
    }

    const handleRemoveImage = async () => {
        if (!currentImageKey || disabled) return

        try {
            const success = await deleteFile(currentImageKey)
            if (success) {
                onImageRemoved?.()
            }
        } catch (error) {
            console.error('Failed to remove image:', error)
        }
    }

    const displayImageUrl = previewUrl || currentImageUrl
    const showUploadOverlay = !displayImageUrl || isUploading

    return (
        <Card className={cn("w-fit", className)}>
            <CardContent className="p-6">
                <div className="flex flex-col items-center space-y-4">
                    {/* Avatar with upload overlay */}
                    <div className="relative">
                        <Avatar className={cn(sizeClasses[size], "border-2 border-muted")}>
                            <AvatarImage
                                src={displayImageUrl || undefined}
                                alt="Profile"
                                className="object-cover"
                            />
                            <AvatarFallback className="bg-muted">
                                {isUploading ? (
                                    <Upload className="h-6 w-6 animate-pulse" />
                                ) : (
                                    <User className="h-6 w-6" />
                                )}
                            </AvatarFallback>
                        </Avatar>

                        {/* Upload overlay */}
                        {!disabled && (
                            <label className={cn(
                                "absolute inset-0 flex items-center justify-center bg-black/50 text-white rounded-full cursor-pointer opacity-0 hover:opacity-100 transition-opacity",
                                showUploadOverlay && !isUploading && "opacity-100"
                            )}>
                                <Camera className="h-6 w-6" />
                                <input
                                    type="file"
                                    accept="image/*"
                                    onChange={handleFileSelect}
                                    className="hidden"
                                    disabled={disabled || isUploading}
                                />
                            </label>
                        )}

                        {/* Loading overlay */}
                        {isUploading && (
                            <div className="absolute inset-0 flex items-center justify-center bg-black/50 text-white rounded-full">
                                <Upload className="h-6 w-6 animate-pulse" />
                            </div>
                        )}
                    </div>

                    {/* Action buttons */}
                    <div className="flex gap-2">
                        {!disabled && (
                            <label>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    disabled={isUploading}
                                    asChild
                                >
                                    <span className="cursor-pointer">
                                        <Upload className="h-4 w-4 mr-2" />
                                        {isUploading ? 'Uploading...' : 'Upload'}
                                    </span>
                                </Button>
                                <input
                                    type="file"
                                    accept="image/*"
                                    onChange={handleFileSelect}
                                    className="hidden"
                                    disabled={disabled || isUploading}
                                />
                            </label>
                        )}

                        {showRemoveButton && (currentImageUrl || previewUrl) && !disabled && (
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={previewUrl ? () => setPreviewUrl(null) : handleRemoveImage}
                                disabled={isUploading}
                            >
                                <X className="h-4 w-4 mr-2" />
                                Remove
                            </Button>
                        )}
                    </div>

                    {/* File size info */}
                    <p className="text-xs text-muted-foreground text-center">
                        Max file size: 1MB<br />
                        Supported formats: JPEG, PNG, WebP, GIF
                    </p>
                </div>
            </CardContent>
        </Card>
    )
}