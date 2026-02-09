import mongoose, { Document, Schema } from 'mongoose'

export interface IDepartment extends Document {
  name: string
  category: 'sales' | 'support' | 'it' | 'management'
  description?: string
  status: 'active' | 'inactive' | 'deleted'
  createdAt: Date
  updatedAt: Date
  isDeleted: boolean
  deletedAt?: Date
  deletedBy?: mongoose.Types.ObjectId
  deletionReason?: string
}

const DepartmentSchema = new Schema<IDepartment>({
  name: {
    type: String,
    required: [true, "Department name is required"],
    trim: true,
    maxlength: [100, "Name cannot exceed 100 characters"],
    unique: true, // This already creates an index, so remove index: true
  },
  category: {
    type: String,
    required: [true, "Department category is required"],
    trim: true,
    maxlength: [100, "Category cannot exceed 100 characters"],
    enum: ['sales', 'support', 'it', 'management'],
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, "Description cannot exceed 500 characters"],
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'deleted'],
    default: 'active',
    // index: true, // Removed - covered by compound indexes
  },
  isDeleted: {
    type: Boolean,
    default: false,
  },
  deletedAt: {
    type: Date,
  },
  deletedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  deletionReason: {
    type: String,
    trim: true,
  },
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
})

// Compound indexes for better query performance
DepartmentSchema.index({ status: 1, createdAt: -1 })
DepartmentSchema.index({ category: 1, createdAt: -1 })

// Text search index
DepartmentSchema.index({
  name: 'text',
  description: 'text'
}, {
  weights: { name: 10, description: 5 },
  name: 'department_search_index'
})

// Pre-save middleware to ensure unique name (case insensitive)
DepartmentSchema.pre('save', async function (next) {
  if (this.isModified('name')) {
    const existingDept = await mongoose.model('Department').findOne({
      name: { $regex: new RegExp(`^${this.name}$`, 'i') },
      _id: { $ne: this._id }
    })

    if (existingDept) {
      const error = new Error('Department name already exists')
      return next(error)
    }
  }
  next()
})

export default mongoose.models.Department || mongoose.model<IDepartment>("Department", DepartmentSchema)