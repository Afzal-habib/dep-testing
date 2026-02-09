'use client';

import React, { useState, useRef, useCallback, useEffect } from 'react';
import { Camera, X, Loader2 } from 'lucide-react';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { cn } from '@/lib/utils';
import { uploadFileWithMulter } from '@/server-actions/upload';

export interface ImageUploaderProps {
    // Core props
    value?: string | null;
    onChange: (imageUrl: string | null) => void;

    // Configuration
    maxSize?: number; // in MB
    acceptedTypes?: string[];
    placeholder?: string;
    disabled?: boolean;
    required?: boolean;

    // Styling
    className?: string;
    containerClassName?: string;
    avatarClassName?: string;
    size?: 'sm' | 'md' | 'lg' | 'xl';
    db_model: string; // Mongoose model for updating DB directly

    // Labels and text
    uploadText?: string;
    dragText?: string;
    fallbackText?: string;
    errorMessages?: {
        fileSize?: string;
        fileType?: string;
        uploadError?: string;
    };
    documentId: string;

    // Callback when upload is successful
    onUploadSuccess?: (imageUrl: string) => void;
}

export interface ImageUploaderRef {
    clearImage: () => void;
    triggerUpload: () => void;
}

const ImageUploader = React.forwardRef<ImageUploaderRef, ImageUploaderProps>(({
    value,
    onChange,
    // onUpload,
    maxSize = 5, // 5MB default
    acceptedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'],
    placeholder = "Click to upload image",
    disabled = false,
    required = false,
    className,
    containerClassName,
    avatarClassName,
    size = 'lg',
    uploadText = "Upload Image",
    dragText = "Drop image here",
    fallbackText = "User",
    errorMessages = {},
    documentId,
    db_model,
    onUploadSuccess
}, ref) => {
    const [isUploading, setIsUploading] = useState(false);
    const [isDragOver, setIsDragOver] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [preview, setPreview] = useState<string | null>(value || null);

    const fileInputRef = useRef<HTMLInputElement>(null);

    // Sync preview with value prop changes
    useEffect(() => {
        setPreview(value || null);
    }, [value]);

    // Size configurations
    const sizeClasses = {
        sm: 'w-16 h-16',
        md: 'w-24 h-24',
        lg: 'w-32 h-32',
        xl: 'w-40 h-40'
    };

    const iconSizes = {
        sm: 'w-4 h-4',
        md: 'w-5 h-5',
        lg: 'w-6 h-6',
        xl: 'w-8 h-8'
    };

    // Default error messages
    const defaultErrorMessages = {
        fileSize: `File size must be less than ${maxSize}MB`,
        fileType: `File type must be one of: ${acceptedTypes.map(type => type.split('/')[1]).join(', ')}`,
        uploadError: 'Failed to upload image. Please try again.',
        ...errorMessages
    };

    // Validate file
    const validateFile = (file: File): string | null => {
        if (file.size > maxSize * 1024 * 1024) {
            return defaultErrorMessages.fileSize;
        }

        if (!acceptedTypes.includes(file.type)) {
            return defaultErrorMessages.fileType;
        }

        return null;
    };

    // Handle file upload
    const handleFileUpload = useCallback(async (file: File) => {
        const validationError = validateFile(file);
        console.log('handleFileUpload file116:', file.type, file.size, validationError);
        if (validationError) {
            setError(validationError);
            return;
        }

        setError(null);
        setIsUploading(true);
        const onUpload = await uploadFileWithMulter({
            file,
            db_model: db_model,
            field_name: 'avatar',
            fileType: 'image',
            documentId: documentId
        })

        try {
            if (onUpload && onUpload.success && onUpload.fileUrl) {
                setPreview(onUpload.fileUrl);
                onChange(onUpload.fileUrl);

                // Call the success callback if provided
                if (onUploadSuccess) {
                    onUploadSuccess(onUpload.fileUrl);
                }
            }
        } catch (uploadError) {
            console.error('Upload error:', uploadError);
            setError(defaultErrorMessages.uploadError);
            // Revert to original value on error
            setPreview(value || null);
            onChange(value || null);
        } finally {
            setIsUploading(false);
        }
    }, [maxSize, acceptedTypes, onChange, value, defaultErrorMessages.uploadError, defaultErrorMessages.fileSize, defaultErrorMessages.fileType, onUploadSuccess]);

    // Handle file input change
    const handleInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (file) {
            handleFileUpload(file);
        }
    };

    // Handle drag and drop
    const handleDrop = useCallback((event: React.DragEvent) => {
        event.preventDefault();
        setIsDragOver(false);

        if (disabled) return;

        const file = event.dataTransfer.files?.[0];
        if (file) {
            handleFileUpload(file);
        }
    }, [disabled, handleFileUpload]);

    const handleDragOver = useCallback((event: React.DragEvent) => {
        event.preventDefault();
        if (!disabled) {
            setIsDragOver(true);
        }
    }, [disabled]);

    const handleDragLeave = useCallback(() => {
        setIsDragOver(false);
    }, []);

    // Clear image
    const clearImage = useCallback(() => {
        setPreview(null);
        setError(null);
        onChange('');
        if (fileInputRef.current) {
            fileInputRef.current.value = '';
        }
    }, [onChange]);

    // Trigger upload programmatically
    const triggerUpload = useCallback(() => {
        if (!disabled && fileInputRef.current) {
            fileInputRef.current.click();
        }
    }, [disabled]);

    // Expose methods through ref
    React.useImperativeHandle(ref, () => ({
        clearImage,
        triggerUpload
    }), [clearImage, triggerUpload]);

    return (
        <div className={cn("space-y-3", containerClassName)}>
            <div
                className={cn(
                    "relative group flex",
                    disabled && "opacity-50 cursor-not-allowed",
                    className
                )}
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
            >
                <input
                    ref={fileInputRef}
                    type="file"
                    accept={acceptedTypes.join(',')}
                    onChange={handleInputChange}
                    className="sr-only"
                    disabled={disabled}
                    required={required}
                />

                {/* Avatar with image */}
                <div className="relative">
                    <Avatar
                        className={cn(
                            sizeClasses[size],
                            "transition-all duration-200 cursor-pointer border-2",
                            isDragOver ? "border-primary scale-105" : "border-muted hover:border-primary/50",
                            error && "border-destructive",
                            avatarClassName
                        )}
                        onClick={triggerUpload}
                    >
                        <AvatarImage
                            src={preview || undefined}
                            alt="Profile image"
                            className="object-cover"
                        />
                        <AvatarFallback className="bg-muted text-muted-foreground">
                            {isUploading ? (
                                <Loader2 className={cn(iconSizes[size], "animate-spin")} />
                            ) : (
                                <Camera className={cn(iconSizes[size])} />
                            )}
                        </AvatarFallback>
                    </Avatar>

                    {/* Camera overlay when hovering over existing image */}
                    {preview && !isUploading && (
                        <div className="absolute cursor-pointer inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-all duration-200 rounded-full flex items-center justify-center">
                            <Camera className={cn(iconSizes[size], "text-white")} />
                        </div>
                    )}

                    {/* Loading overlay */}
                    {isUploading && (
                        <div className="absolute inset-0 bg-black/60 flex items-center justify-center rounded-full">
                            <Loader2 className={cn(iconSizes[size], "animate-spin text-white")} />
                        </div>
                    )}

                    {/* Clear button */}
                    {preview && !isUploading && (
                        <button
                            type="button"
                            onClick={(e) => {
                                e.stopPropagation();
                                clearImage();
                            }}
                            disabled={disabled}
                            className={cn(
                                "absolute -top-1 -right-1 p-1 bg-destructive text-destructive-foreground rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-200 hover:bg-destructive/90",
                                size === 'sm' && "p-0.5 -top-0.5 -right-0.5"
                            )}
                            title="Remove image"
                        >
                            <X className={cn(size === 'sm' ? 'w-3 h-3' : 'w-4 h-4')} />
                        </button>
                    )}

                    {/* Drag indicator */}
                    {isDragOver && (
                        <div className="absolute inset-0 border-2 border-dashed border-primary rounded-full bg-primary/10 flex items-center justify-center">
                            <span className="text-xs font-medium text-primary">Drop here</span>
                        </div>
                    )}
                </div>


                <div className='flex flex-col space-y-2 items-center justify-center ml-4'>
                    {/* Upload text */}
                    {!preview && !isUploading && (
                        <div className="text-center mt-2">
                            <p className="text-sm font-medium text-foreground">
                                {uploadText}
                            </p>
                            <p className="text-xs text-muted-foreground mt-1">
                                {placeholder}
                            </p>
                        </div>
                    )}

                    {/* File info */}
                    <div className="text-center mt-2">
                        <p className="text-xs text-muted-foreground">
                            Max {maxSize}MB • {acceptedTypes.map(type => type.split('/')[1].toUpperCase()).join(', ')}
                        </p>
                    </div>
                </div>
            </div>

            {/* Error message */}
            {error && (
                <div className="flex items-center space-x-1 text-destructive">
                    <X className="w-4 h-4 flex-shrink-0" />
                    <p className="text-sm">{error}</p>
                </div>
            )}

            {/* Upload status */}
            {isUploading && (
                <div className="flex items-center justify-center space-x-2 text-sm text-muted-foreground">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Uploading image...</span>
                </div>
            )}
        </div>
    );
});

ImageUploader.displayName = 'ImageUploader';

export { ImageUploader };