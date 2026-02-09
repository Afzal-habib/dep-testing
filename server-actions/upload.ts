'use server'

import connectToDatabase from '@/lib/mongodb'
import { revalidatePath } from 'next/cache'
import { ObjectId } from 'mongodb'
import multer from 'multer'
import path from 'path'
import fs from 'fs'
import { promisify } from 'util'
import { NextRequest } from 'next/server'
import mongoose from 'mongoose'

// Define allowed file types
const ALLOWED_FILE_TYPES = {
    image: ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'],
    document: ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    spreadsheet: ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    audio: ['audio/mpeg', 'audio/wav', 'audio/ogg'],
    video: ['video/mp4', 'video/avi', 'video/mov'],
    any: [] // For any file type
}

export interface FileUploadParams {
    file: File | any // The file to upload
    db_model: string // Mongoose model or collection name
    field_name: string // Field name in the document where file path will be stored
    fileType: keyof typeof ALLOWED_FILE_TYPES // Type of file being uploaded
    documentId: string
    userId?: string // Optional - for audit trails
}

export interface FileUploadResult {
    success: boolean
    message: string
    fileUrl?: string
    filePath?: string
    documentId?: string
    fileName?: string
}

export interface ValidationResult {
    success: boolean
    message: string
    collectionExists?: boolean
    fieldExists?: boolean
    documentExists?: boolean
}

/**
 * Validate collection, field, and document existence before upload
 */
async function validateUploadPrerequisites(
    db_model: string,
    field_name: string,
    documentId: string
): Promise<ValidationResult> {
    try {
        const { db } = await connectToDatabase()

        // 1. Check if collection exists
        const collections = await db?.listCollections().toArray()
        const collectionExists = collections?.some(col => col.name === db_model) || false

        if (!collectionExists) {
            return {
                success: false,
                message: `Collection '${db_model}' does not exist in the database`,
                collectionExists: false
            }
        }

        // 2. Check if document exists (if documentId is provided)
        if (documentId) {
            if (!ObjectId.isValid(documentId)) {
                return {
                    success: false,
                    message: `Invalid document ID format: ${documentId}`,
                    collectionExists: true,
                    documentExists: false
                }
            }

            const document = await db?.collection(db_model).findOne({ _id: new ObjectId(documentId) })

            if (!document) {
                return {
                    success: false,
                    message: `Document with ID '${documentId}' not found in collection '${db_model}'`,
                    collectionExists: true,
                    documentExists: false
                }
            }

            // 3. Check if field exists in the document schema or allow new fields
            // For MongoDB, we'll check if the field exists in any document or allow it to be created
            const fieldExistsInCollection = await db?.collection(db_model).findOne(
                { [field_name]: { $exists: true } }
            )

            // Note: In MongoDB, fields can be dynamically added, so we'll allow new fields
            // but warn if the field doesn't exist in any document
            const fieldExists = !!fieldExistsInCollection

            return {
                success: true,
                message: fieldExists
                    ? `All validations passed. Collection, document, and field exist.`
                    : `Collection and document exist. Field '${field_name}' will be created as a new field.`,
                collectionExists: true,
                documentExists: true,
                fieldExists
            }
        }

        // If no documentId is provided, just validate collection existence
        return {
            success: true,
            message: `Collection '${db_model}' exists. Ready for new document creation.`,
            collectionExists: true,
            documentExists: false // Will be created
        }

    } catch (error) {
        console.error('Validation error:', error)
        return {
            success: false,
            message: `Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        }
    }
}

/**
 * Alternative validation using Mongoose models (if available)
 */
async function validateWithMongooseModel(
    db_model: string,
    field_name: string,
    documentId: string
): Promise<ValidationResult> {
    try {
        // Check if it's a registered Mongoose model
        const modelNames = mongoose.modelNames()
        const isMongooseModel = modelNames.includes(db_model) || modelNames.includes(db_model.charAt(0).toUpperCase() + db_model.slice(1))

        if (isMongooseModel) {
            const modelName = modelNames.find(name =>
                name.toLowerCase() === db_model.toLowerCase()
            ) || db_model

            const Model = mongoose.models[modelName]

            if (!Model) {
                return {
                    success: false,
                    message: `Mongoose model '${modelName}' not found`
                }
            }

            // Check if document exists
            if (documentId) {
                if (!ObjectId.isValid(documentId)) {
                    return {
                        success: false,
                        message: `Invalid document ID format: ${documentId}`
                    }
                }

                const document = await Model.findById(documentId)

                if (!document) {
                    return {
                        success: false,
                        message: `Document with ID '${documentId}' not found in model '${modelName}'`,
                        collectionExists: true,
                        documentExists: false
                    }
                }

                // Check schema for field (Mongoose schema validation)
                const schemaFields = Object.keys(Model.schema.paths)
                const fieldExists = schemaFields.includes(field_name)

                return {
                    success: true,
                    message: fieldExists
                        ? `All validations passed using Mongoose model.`
                        : `Document exists. Field '${field_name}' will be added dynamically.`,
                    collectionExists: true,
                    documentExists: true,
                    fieldExists
                }
            }

            return {
                success: true,
                message: `Mongoose model '${modelName}' exists. Ready for new document creation.`,
                collectionExists: true
            }
        }

        // Fall back to native MongoDB validation
        return await validateUploadPrerequisites(db_model, field_name, documentId)

    } catch (error) {
        console.error('Mongoose validation error:', error)
        // Fall back to native MongoDB validation
        return await validateUploadPrerequisites(db_model, field_name, documentId)
    }
}

// Configure multer storage
const createMulterStorage = (db_model: any) => {
    return multer.diskStorage({
        destination: (req, file, cb) => {
            // Determine folder based on model
            let uploadPath: string

            if (db_model === 'users') {
                uploadPath = path.join(process.cwd(), 'public', 'uploads', 'user')
            } else {
                uploadPath = path.join(process.cwd(), 'public', 'uploads', 'project')
            }

            // Create directory if it doesn't exist
            if (!fs.existsSync(uploadPath)) {
                fs.mkdirSync(uploadPath, { recursive: true })
            }

            cb(null, uploadPath)
        },
        filename: (req, file, cb) => {
            // Generate unique filename
            const timestamp = Date.now()
            const ext = path.extname(file.originalname)
            const name = path.basename(file.originalname, ext)
            const fileName = `${name}_${timestamp}${ext}`
            cb(null, fileName)
        }
    })
}

// File filter for validation
const fileFilter = (fileType: keyof typeof ALLOWED_FILE_TYPES) => {
    return (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
        if (fileType === 'any' || ALLOWED_FILE_TYPES[fileType].length === 0) {
            cb(null, true)
        } else if (ALLOWED_FILE_TYPES[fileType].includes(file.mimetype)) {
            cb(null, true)
        } else {
            cb(new Error(`Invalid file type. Allowed types: ${ALLOWED_FILE_TYPES[fileType].join(', ')}`))
        }
    }
}

/**
 * Main server action for file upload with Multer
 */
export async function uploadFileWithMulter(params: FileUploadParams): Promise<FileUploadResult> {
    const maxSizes = {
        image: 5 * 1024 * 1024, // 5MB
        document: 10 * 1024 * 1024, // 10MB
        spreadsheet: 10 * 1024 * 1024, // 10MB
        audio: 50 * 1024 * 1024, // 50MB
        video: 100 * 1024 * 1024, // 100MB
        any: 50 * 1024 * 1024 // 50MB default
    }

    try {
        const { file, db_model, field_name, fileType, documentId, userId } = params

        // Basic parameter validation
        if (!file || !db_model || !field_name) {
            return {
                success: false,
                message: 'Missing required parameters: file, db_model, or field_name'
            }
        }

        // **NEW: Validate database prerequisites before proceeding**
        console.log(`🔍 Validating prerequisites for collection: ${db_model}, field: ${field_name}, documentId: ${documentId}`)

        const validation = await validateWithMongooseModel(db_model, field_name, documentId)

        if (!validation.success) {
            return {
                success: false,
                message: `Upload failed - ${validation.message}`
            }
        }

        console.log(`✅ Validation passed: ${validation.message}`)

        // Validate file type
        if (fileType !== 'any' && ALLOWED_FILE_TYPES[fileType].length > 0) {
            if (!ALLOWED_FILE_TYPES[fileType].includes(file.type)) {
                return {
                    success: false,
                    message: `Invalid file type. Allowed types: ${ALLOWED_FILE_TYPES[fileType].join(', ')}`
                }
            }
        }

        // Validate file size
        if (file.size > maxSizes[fileType]) {
            return {
                success: false,
                message: `File size exceeds limit of ${Math.round(maxSizes[fileType] / (1024 * 1024))}MB`
            }
        }

        // Create multer upload configuration
        const storage = createMulterStorage(db_model)
        const upload = multer({
            storage,
            fileFilter: fileFilter(fileType),
            limits: {
                fileSize: maxSizes[fileType]
            }
        })

        // Handle the actual file saving
        const buffer = await file.arrayBuffer()
        const uploadPath = db_model === 'users'
            ? path.join(process.cwd(), 'public', 'uploads', 'user')
            : path.join(process.cwd(), 'public', 'uploads', 'project')

        // Ensure directory exists
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true })
        }

        // Generate filename
        const timestamp = Date.now()
        const ext = path.extname(file.name || 'file')
        const name = path.basename(file.name || 'file', ext)
        const fileName = `${name}_${timestamp}${ext}`
        const fullPath = path.join(uploadPath, fileName)

        // Write file to disk
        fs.writeFileSync(fullPath, Buffer.from(buffer))

        // Generate URL path
        const fileUrl = db_model === 'users'
            ? `/uploads/user/${fileName}`  // Note the leading slash for absolute path
            : `/uploads/project/${fileName}`

        // Update database
        const dbResult = await updateDatabaseWithFilePath({
            db_model,
            field_name,
            filePath: fileUrl,
            fileName,
            documentId,
            userId,
            originalName: file.name,
            mimeType: file.type,
            fileSize: file.size
        })

        if (!dbResult.success) {
            // Clean up uploaded file if database update fails
            if (fs.existsSync(fullPath)) {
                fs.unlinkSync(fullPath)
            }
            return dbResult
        }

        return {
            success: true,
            message: 'File uploaded successfully',
            fileUrl,
            filePath: fullPath,
            fileName,
            documentId: dbResult.documentId
        }

    } catch (error) {
        console.error('File upload error:', error)
        return {
            success: false,
            message: error instanceof Error ? error.message : 'An error occurred during file upload'
        }
    }
}

/**
 * Helper function to update database with file path
 */
async function updateDatabaseWithFilePath(params: {
    db_model: string
    field_name: string
    filePath: string
    fileName: string
    documentId?: string
    userId?: string
    originalName?: string
    mimeType?: string
    fileSize?: number
}): Promise<{ success: boolean; message: string; documentId?: string }> {
    try {
        const { db_model, field_name, filePath, fileName, documentId, userId, originalName, mimeType, fileSize } = params

        // Check if it's a Mongoose model or collection name
        const modelNames = mongoose.modelNames()
        const isMongooseModel = modelNames.some(name =>
            name.toLowerCase() === db_model.toLowerCase()
        )

        if (isMongooseModel) {
            // Handle Mongoose model
            const modelName = modelNames.find(name =>
                name.toLowerCase() === db_model.toLowerCase()
            ) || db_model

            const Model = mongoose.models[modelName]

            const updateData: any = {
                [field_name]: filePath,
                [`${field_name}FileName`]: fileName,
                updatedAt: new Date()
            }

            // Add optional metadata
            if (originalName) updateData[`${field_name}OriginalName`] = originalName
            if (mimeType) updateData[`${field_name}MimeType`] = mimeType
            if (fileSize) updateData[`${field_name}Size`] = fileSize
            if (userId) updateData[`${field_name}UpdatedBy`] = userId

            if (documentId) {
                // Update existing document
                updateData[`${field_name}UpdatedAt`] = new Date()
                const result = await Model.findByIdAndUpdate(documentId, updateData, { new: true })

                if (!result) {
                    return { success: false, message: 'Document not found' }
                }

                return { success: true, message: 'File reference updated', documentId }
            } else {
                // Create new document
                updateData[`${field_name}UploadedAt`] = new Date()
                updateData.createdAt = new Date()
                if (userId) updateData[`${field_name}UploadedBy`] = userId

                const result = await Model.create(updateData)
                return { success: true, message: 'File reference created', documentId: result._id.toString() }
            }
        } else {
            // Handle MongoDB collection (native driver)
            const { db } = await connectToDatabase()
            const collectionName = db_model

            const updateData: any = {
                [field_name]: filePath,
                [`${field_name}FileName`]: fileName,
                updatedAt: new Date()
            }

            // Add optional metadata
            if (originalName) updateData[`${field_name}OriginalName`] = originalName
            if (mimeType) updateData[`${field_name}MimeType`] = mimeType
            if (fileSize) updateData[`${field_name}Size`] = fileSize
            if (userId) updateData[`${field_name}UpdatedBy`] = userId

            if (documentId) {
                // Update existing document
                updateData[`${field_name}UpdatedAt`] = new Date()
                const result = await db?.collection(collectionName).updateOne(
                    { _id: new ObjectId(documentId) },
                    { $set: updateData }
                )

                if (result?.matchedCount === 0) {
                    return { success: false, message: 'Document not found' }
                }

                return { success: true, message: 'File reference updated', documentId }
            } else {
                // Create new document
                updateData[`${field_name}UploadedAt`] = new Date()
                updateData.createdAt = new Date()
                if (userId) updateData[`${field_name}UploadedBy`] = userId

                const result = await db?.collection(collectionName).insertOne(updateData)
                return { success: true, message: 'File reference created', documentId: result?.insertedId.toString() }
            }
        }

    } catch (error) {
        console.error('Database update error:', error)
        return {
            success: false,
            message: error instanceof Error ? error.message : 'Database update failed'
        }
    }
}

/**
 * Exported function to manually validate upload prerequisites
 */
export async function validateUploadRequirements(
    db_model: string,
    field_name: string,
    documentId?: string
): Promise<ValidationResult> {
    if (!documentId) {
        return await validateUploadPrerequisites(db_model, field_name, '')
    }

    return await validateWithMongooseModel(db_model, field_name, documentId)
}


