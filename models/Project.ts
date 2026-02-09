import mongoose, { Document, Schema } from 'mongoose'

export interface IProject extends Document {
  name: string
  description?: string
  clientId: mongoose.Types.ObjectId
  departmentIds: mongoose.Types.ObjectId[]
  status: 'pending' | 'active' | 'completed' | 'approved' | 'inactive' | 'deleted'
  budget?: number
  startDate?: Date
  endDate?: Date
  priority: 'low' | 'medium' | 'high' | 'urgent'

  // Fields from lead project info
  projectType?: string
  complexity?: string
  requirements?: string[]
  customerServices?: string[]
  timeline?: string

  // Enhanced professional CRM fields
  budgetBreakdown?: {
    development?: number
    design?: number
    testing?: number
    deployment?: number
    maintenance?: number
    contingency?: number
  }


  risks?: {
    description: string
    impact: 'low' | 'medium' | 'high' | 'critical'
    probability: 'low' | 'medium' | 'high'
    mitigation?: string
    status: 'identified' | 'mitigated' | 'occurred'
  }[]

  // Progress calculated dynamically from tasks
  progress?: {
    overall: number
    totalTasks: number
    completedTasks: number
  }

  resources?: {
    estimatedHours?: number
    actualHours?: number
    tools?: string[]
    externalResources?: string[]
  }

  qualityMetrics?: {
    requirementsCoverage?: number
    defectDensity?: number
    customerSatisfaction?: number
    onTimeDelivery?: boolean
    withinBudget?: boolean
  }

  // Meta fields
  createdBy: mongoose.Types.ObjectId
  approvedBy?: mongoose.Types.ObjectId
  approvedAt?: Date
  createdAt: Date
  updatedAt: Date
  isDeleted: boolean
  deletedAt?: Date
  deletedBy?: mongoose.Types.ObjectId
  deletionReason?: string
}

const ProjectSchema = new Schema<IProject>({
  name: {
    type: String,
    required: [true, "Project name is required"],
    trim: true,
    maxlength: [200, "Name cannot exceed 200 characters"],
    // index: true, // Removed - covered by text search index
  },
  description: {
    type: String,
    trim: true,
    maxlength: [1000, "Description cannot exceed 1000 characters"],
  },
  clientId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, "Client is required"],
    // index: true, // Removed - covered by compound indexes
  },
  departmentIds: [{
    type: Schema.Types.ObjectId,
    ref: 'Department',
    // index: true, // Removed - covered by compound indexes
  }],
  status: {
    type: String,
    enum: ['pending', 'active', 'completed', 'approved', 'inactive', 'deleted'],
    default: 'pending',
    // index: true, // Removed - covered by compound indexes
  },
  budget: {
    type: Number,
    min: [0, "Budget must be positive"],
  },
  startDate: {
    type: Date,
  },
  endDate: {
    type: Date,
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium',
    // index: true, // Removed - covered by compound indexes
  },

  // Fields from lead project info
  projectType: {
    type: String,
    trim: true,
    maxlength: [100, "Project type cannot exceed 100 characters"],
  },
  complexity: {
    type: String,
    trim: true,
    maxlength: [100, "Project complexity cannot exceed 100 characters"],
  },
  requirements: [{
    type: String,
    trim: true,
    maxlength: [200, "Requirement cannot exceed 200 characters"],
  }],
  customerServices: [{
    type: String,
    trim: true,
    maxlength: [200, "Customer service cannot exceed 200 characters"],
  }],
  timeline: {
    type: String,
    trim: true,
    maxlength: [500, "Timeline cannot exceed 500 characters"],
  },

  // Enhanced professional CRM fields
  budgetBreakdown: {
    development: { type: Number, min: [0, "Development budget must be positive"] },
    design: { type: Number, min: [0, "Design budget must be positive"] },
    testing: { type: Number, min: [0, "Testing budget must be positive"] },
    deployment: { type: Number, min: [0, "Deployment budget must be positive"] },
    maintenance: { type: Number, min: [0, "Maintenance budget must be positive"] },
    contingency: { type: Number, min: [0, "Contingency budget must be positive"] },
  },



  risks: [{
    description: { type: String, required: true, trim: true, maxlength: [500, "Risk description cannot exceed 500 characters"] },
    impact: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
    probability: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
    mitigation: { type: String, trim: true, maxlength: [500, "Mitigation cannot exceed 500 characters"] },
    status: { type: String, enum: ['identified', 'mitigated', 'occurred'], default: 'identified' },
  }],

  resources: {
    estimatedHours: { type: Number, min: [0, "Estimated hours cannot be negative"] },
    actualHours: { type: Number, min: [0, "Actual hours cannot be negative"] },
    tools: [{ type: String, trim: true, maxlength: [100, "Tool name cannot exceed 100 characters"] }],
    externalResources: [{ type: String, trim: true, maxlength: [200, "External resource cannot exceed 200 characters"] }],
  },

  qualityMetrics: {
    requirementsCoverage: { type: Number, min: [0, "Requirements coverage cannot be negative"], max: [100, "Requirements coverage cannot exceed 100"] },
    defectDensity: { type: Number, min: [0, "Defect density cannot be negative"] },
    customerSatisfaction: { type: Number, min: [0, "Customer satisfaction cannot be negative"], max: [5, "Customer satisfaction cannot exceed 5"] },
    onTimeDelivery: { type: Boolean, default: false },
    withinBudget: { type: Boolean, default: false },
  },

  // Meta fields
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, "Creator is required"],
    // index: true, // Removed - covered by compound indexes
  },
  approvedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  approvedAt: {
    type: Date,
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

// Performance indexes
ProjectSchema.index({ clientId: 1, status: 1 })
ProjectSchema.index({ status: 1, createdAt: -1 })
ProjectSchema.index({ departmentIds: 1, status: 1 })
ProjectSchema.index({ createdBy: 1, status: 1 })
ProjectSchema.index({ priority: 1, status: 1 })
ProjectSchema.index({ isDeleted: 1, status: 1, createdAt: -1 })

// Text search index
ProjectSchema.index({
  name: 'text',
  description: 'text',
}, {
  weights: { name: 10, description: 5 },
  name: 'project_search_index'
})

// Virtuals for populated fields
ProjectSchema.virtual('client', {
  ref: 'User',
  localField: 'clientId',
  foreignField: '_id',
  justOne: true,
})

ProjectSchema.virtual('departments', {
  ref: 'Department',
  localField: 'departmentIds',
  foreignField: '_id',
})

ProjectSchema.virtual('creator', {
  ref: 'User',
  localField: 'createdBy',
  foreignField: '_id',
  justOne: true,
})

ProjectSchema.virtual('approver', {
  ref: 'User',
  localField: 'approvedBy',
  foreignField: '_id',
  justOne: true,
})

// Virtual for task count
ProjectSchema.virtual('taskCount', {
  ref: 'Task',
  localField: '_id',
  foreignField: 'projectId',
  count: true,
})

// Virtual for all tasks
ProjectSchema.virtual('tasks', {
  ref: 'Task',
  localField: '_id',
  foreignField: 'projectId',
})

// Virtual for main tasks only (not sub-tasks)
ProjectSchema.virtual('mainTasks', {
  ref: 'Task',
  localField: '_id',
  foreignField: 'projectId',
  match: { type: 'task' }
})

// Virtual for sub-tasks only
ProjectSchema.virtual('subTasks', {
  ref: 'Task',
  localField: '_id',
  foreignField: 'projectId',
  match: { type: 'sub-task' }
})


// Pre-save validation
ProjectSchema.pre('save', async function (next) {
  // Validate dates
  if (this.startDate && this.endDate && this.startDate > this.endDate) {
    const error = new Error('Start date cannot be after end date')
    return next(error)
  }

  // Validate client is qualified
  if (this.isModified('clientId')) {
    const User = mongoose.model('User')
    const client = await User.findById(this.clientId)

    // if (!client || client.role !== 'client' || client.status !== 'qualified') {
    //   const error = new Error('Client must be qualified to create project')
    //   return next(error)
    // }
  }

  // Auto approve for certain statuses
  if (this.isModified('status') && this.status === 'approved' && !this.approvedAt) {
    this.approvedAt = new Date()
  }

  next()
})

// Static methods
ProjectSchema.statics.findByClient = function (clientId: string, options = {}) {
  return this.find({ clientId, ...options })
    .populate('client', 'name email')
    .populate('departments', 'name status')
    .sort({ createdAt: -1 })
}

ProjectSchema.statics.findByDepartment = function (departmentId: string, options = {}) {
  return this.find({ departmentIds: departmentId, ...options })
    .populate('client', 'name email')
    .populate('creator', 'name email')
    .sort({ createdAt: -1 })
}

export default mongoose.models.Project || mongoose.model<IProject>("Project", ProjectSchema)

// Register the model with the generic registry
import { registerModel } from '../lib/modelRegistry'
registerModel('Project', mongoose.models.Project || mongoose.model<IProject>("Project", ProjectSchema), ProjectSchema, '1.0.0', ['User', 'Department'])