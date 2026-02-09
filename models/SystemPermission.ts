import mongoose, { Document, Schema } from 'mongoose'

export interface IResourceAction {
  action: string
  description: string
  conditions?: string[]
}

export interface ISystemPermission extends Document {
  resource: string // The resource/entity name (users, departments, products, etc.)
  displayName: string // Human readable name
  description?: string
  category: string // Grouping category (User Management, System, Reports, etc.)
  availableActions: IResourceAction[]
  isCore: boolean // Core permissions cannot be deleted
  status: 'active' | 'inactive' | 'archived'
  metadata?: {
    createdBy?: string
    updatedBy?: string
    version?: string
    notes?: string
  }
  createdAt: Date
  updatedAt: Date
}

const ResourceActionSchema = new Schema<IResourceAction>({
  action: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
  },
  description: {
    type: String,
    required: true,
    trim: true,
  },
  conditions: [{
    type: String,
    trim: true,
    enum: ['own', 'department', 'assigned', 'subordinates', 'unrestricted', 'all']
  }]
}, { _id: false })

const SystemPermissionSchema = new Schema<ISystemPermission>({
  resource: {
    type: String,
    required: [true, "Resource is required"],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^[a-z][a-z0-9_]*$/, "Resource must start with letter and contain only lowercase letters, numbers, and underscores"]
  },
  displayName: {
    type: String,
    required: [true, "Display name is required"],
    trim: true,
    maxlength: [100, "Display name cannot exceed 100 characters"],
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, "Description cannot exceed 500 characters"],
  },
  category: {
    type: String,
    required: [true, "Category is required"],
    trim: true,
    // index: true, // Removed - covered by compound indexes
    enum: [
      'user_management',
      'department_management',
      'role_management',
      'system_administration',
      'reporting',
      'data_management',
      'security',
      'integration',
      'communication_management',
      'project_management',
      'task_management',
      'lead_management',
      'proposal_management',
      'custom'
    ]
  },
  availableActions: {
    type: [ResourceActionSchema],
    required: true,
    validate: {
      validator: function (actions: IResourceAction[]) {
        return actions && actions.length > 0;
      },
      message: "Resource must have at least one available action"
    }
  },
  isCore: {
    type: Boolean,
    default: false,
    // index: true, // Removed - covered by compound indexes
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'archived'],
    default: 'active',
    // index: true, // Removed - covered by compound indexes
  },
  metadata: {
    createdBy: String,
    updatedBy: String,
    version: {
      type: String,
      default: '1.0.0'
    },
    notes: String,
  },
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
})

// Indexes
SystemPermissionSchema.index({ category: 1, status: 1 })
SystemPermissionSchema.index({ isCore: 1, status: 1 })

// Text search
SystemPermissionSchema.index({
  resource: 'text',
  displayName: 'text',
  description: 'text'
}, {
  weights: {
    resource: 10,
    displayName: 8,
    description: 5
  },
  name: 'permission_search_index'
})

// Instance methods
SystemPermissionSchema.methods.hasAction = function (action: string): boolean {
  return this.availableActions.some((a: IResourceAction) => a.action === action.toLowerCase())
}

SystemPermissionSchema.methods.getActionConditions = function (action: string): string[] {
  const actionObj = this.availableActions.find((a: IResourceAction) => a.action === action.toLowerCase())
  return actionObj?.conditions || []
}

// Static methods
SystemPermissionSchema.statics.findByCategory = function (category: string) {
  return this.find({
    category: category.toLowerCase(),
    status: 'active'
  }).sort({ displayName: 1 })
}

SystemPermissionSchema.statics.findCorePermissions = function () {
  return this.find({
    isCore: true,
    status: 'active'
  }).sort({ category: 1, displayName: 1 })
}

SystemPermissionSchema.statics.getResourceActions = function (resource: string) {
  return this.findOne({
    resource: resource.toLowerCase(),
    status: 'active'
  }).then((permission: any) => permission?.availableActions || [])
}

// Pre-save middleware
SystemPermissionSchema.pre('save', function (next) {
  // Ensure resource is lowercase
  this.resource = this.resource.toLowerCase()
  this.category = this.category.toLowerCase()

  // Ensure all actions are lowercase
  this.availableActions.forEach(action => {
    action.action = action.action.toLowerCase()
  })

  next()
})

// Pre-remove middleware
SystemPermissionSchema.pre('deleteOne', { document: true, query: false }, function (next) {
  if (this.isCore) {
    return next(new Error('Core permissions cannot be deleted'))
  }
  next()
})

export default mongoose.models.SystemPermission || mongoose.model<ISystemPermission>("SystemPermission", SystemPermissionSchema)