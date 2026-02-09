import mongoose, { Document, Schema } from 'mongoose'

export interface IMedia extends Document {
    file_type: string
    file: string
    original_name?: string
    mime_type: string
    size?: number
    uploaded_by?: mongoose.Types.ObjectId
    createdAt: Date
    updatedAt: Date
}

const MediaSchema = new Schema<IMedia>({
    file_type: {
        type: String,
        required: [true, "File type is required"],
        trim: true,
        maxlength: [50, "File type cannot exceed 50 characters"],
        // index: true, // Removed - covered by compound indexes
    },
    file: {
        type: String,
        required: [true, "File path is required"],
        trim: true,
        maxlength: [500, "File path cannot exceed 500 characters"],
        unique: true,
    },
    mime_type: {
        type: String,
        trim: true,
        maxlength: [100, "MIME type cannot exceed 100 characters"],
        // index: true, // Removed - covered by compound indexes
    },
    uploaded_by: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        // index: true, // Removed - covered by compound indexes
    },
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
})

// Compound indexes for better query performance
MediaSchema.index({ file_type: 1, status: 1, createdAt: -1 })
MediaSchema.index({ uploaded_by: 1, status: 1, createdAt: -1 })
MediaSchema.index({ mime_type: 1, status: 1 })

// Text search index for file names
MediaSchema.index({
    original_name: 'text'
}, {
    name: 'media_search_index'
})


// Pre-remove middleware to handle file cleanup
MediaSchema.pre('deleteOne', { document: true, query: false }, async function (next) {
    // You can add file system cleanup logic here if needed
    // const fs = require('fs').promises
    // try {
    //   await fs.unlink(this.file_path)
    // } catch (error) {
    //   console.log('Error deleting file:', error)
    // }
    next()
})

// Static method to find active media
MediaSchema.statics.findActive = function () {
    return this.find({ status: 'active' })
}

// Instance method to soft delete
MediaSchema.methods.softDelete = function () {
    this.status = 'deleted'
    return this.save()
}

export default mongoose.models.Media || mongoose.model<IMedia>("Media", MediaSchema)



