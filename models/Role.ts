import mongoose, { Document, Schema } from 'mongoose'

export interface IPermission {
  resource: string // e.g., 'users', 'departments', 'products', 'reports'
  actions: string[] // e.g., ['create', 'read', 'update', 'delete']
  conditions?: {
    own?: boolean // Can only access own records
    department?: boolean // Can access department records
    assigned?: boolean // Can access assigned records
    subordinates?: boolean // Can access subordinate records
    unrestricted?: boolean // Can access all records
  }
}

export interface IRole extends Document {
  name: string
  displayName: string
  description?: string
  department: mongoose.Types.ObjectId // Department this role belongs to
  permissions?: IPermission[]
  hierarchyLevel: number // Higher level can manage lower levels
  isSystemRole: boolean // Cannot be deleted (admin, super admin)
  status: "active" | "inactive" | "archived" | "deleted"
  maxUsers?: number // Limit how many users can have this role
  validityPeriod?: {
    startDate?: Date
    endDate?: Date
  }
  metadata?: {
    createdBy?: string
    updatedBy?: string
    notes?: string
    tags?: string[]
  }
  createdAt: Date
  updatedAt: Date
  isDeleted: boolean
  deletedAt?: Date
  deletedBy?: mongoose.Types.ObjectId
  deletionReason?: string
}

const PermissionSchema = new Schema<IPermission>({
  resource: {
    type: String,
    required: [true, "Resource is required"],
    trim: true,
    lowercase: true,
    // index: true, // Removed - not frequently queried alone
  },
  actions: [{
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    enum: ['create', 'read', 'update', 'delete', 'assign', 'approve', 'reject', 'export', 'import', 'archive', 'manage', 'configure', 'audit']
  }],
  conditions: {
    own: {
      type: Boolean,
      default: false,
    },
    department: {
      type: Boolean,
      default: false,
    },
    assigned: {
      type: Boolean,
      default: false,
    },
    subordinates: {
      type: Boolean,
      default: false,
    },
    unrestricted: {
      type: Boolean,
      default: false,
    },
  }
}, { _id: false })

const RoleSchema = new Schema<IRole>({
  name: {
    type: String,
    required: [true, "Role name is required"],
    trim: true,
    maxlength: [100, "Name cannot exceed 100 characters"],
    // index: true, // Removed - covered by compound unique index
  },
  displayName: {
    type: String,
    required: [true, "Display name is required"],
    trim: true,
    maxlength: [150, "Display name cannot exceed 150 characters"],
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, "Description cannot exceed 500 characters"],
  },
  department: {
    type: Schema.Types.ObjectId,
    ref: 'Department',
    required: function (this: IRole) {
      // Department is required for non-system roles and for specific system roles
      if (!this.isSystemRole) return true;
      // For system roles, only super_admin and hr_manager require department
      return ['super_admin', 'hr_manager'].includes(this.name);
    },
    validate: {
      validator: function (this: IRole, value: any) {
        if (!this.isSystemRole) {
          // Non-system roles must have department
          return value != null && mongoose.Types.ObjectId.isValid(value);
        }
        // For system roles, only super_admin and hr_manager should have department
        if (['super_admin', 'hr_manager'].includes(this.name)) {
          return value != null && mongoose.Types.ObjectId.isValid(value);
        }
        // Other system roles should not have department
        return value === null || value === undefined;
      },
      message: function (this: IRole) {
        if (!this.isSystemRole) {
          return "Department is required for non-system roles";
        }
        if (['super_admin', 'hr_manager'].includes(this.name)) {
          return `${this.name} role must be associated with a department`;
        }
        return "System roles should not be associated with a specific department";
      }
    },
    // index: true, // Removed - covered by compound indexes
  },
  permissions: {
    type: [PermissionSchema],
    required: false,
    // validate: {
    //   validator: function (permissions: IPermission[]) {
    //     return permissions && permissions.length > 0;
    //   },
    //   message: "Role must have at least one permission"
    // }
  },
  hierarchyLevel: {
    type: Number,
    required: true,
    min: [1, "Hierarchy level must be at least 1"],
    max: [10, "Hierarchy level cannot exceed 10"],
    default: 1,
    // index: true, // Removed - covered by compound indexes
  },
  isSystemRole: {
    type: Boolean,
    default: false,
    // index: true, // Removed - covered by compound indexes
  },
  status: {
    type: String,
    enum: ["active", "inactive", "archived", "deleted"],
    default: "active",
    // index: true, // Removed - covered by compound indexes
  },
  maxUsers: {
    type: Number,
    min: [1, "Max users must be at least 1"],
    max: [1000, "Max users cannot exceed 1000"],
  },
  validityPeriod: {
    startDate: Date,
    endDate: Date,
  },
  metadata: {
    createdBy: String,
    updatedBy: String,
    notes: String,
    tags: [String],
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

// Indexes for better performance
RoleSchema.index({ department: 1, status: 1 })
RoleSchema.index({ department: 1, hierarchyLevel: -1 })
RoleSchema.index({ name: 1, department: 1 }, { unique: true })
RoleSchema.index({ isSystemRole: 1, status: 1 })
RoleSchema.index({ 'validityPeriod.endDate': 1 }, { sparse: true })

// Text search index
RoleSchema.index({
  name: 'text',
  displayName: 'text',
  description: 'text'
}, {
  weights: {
    name: 10,
    displayName: 8,
    description: 5
  },
  name: 'role_search_index'
})

// Virtual to populate department details
RoleSchema.virtual('departmentDetails', {
  ref: 'Department',
  localField: 'department',
  foreignField: '_id',
  justOne: true,
})

// Virtual to count users with this role
RoleSchema.virtual('userCount', {
  ref: 'User',
  localField: '_id',
  foreignField: 'role',
  count: true,
})

// Instance methods
RoleSchema.methods.hasPermission = function (resource: string, action: string): boolean {
  return this.permissions.some((perm: IPermission) =>
    perm.resource === resource.toLowerCase() &&
    perm.actions.includes(action.toLowerCase())
  )
}

RoleSchema.methods.canAccessResource = function (resource: string, condition?: keyof IPermission['conditions']): boolean {
  const permission = this.permissions.find((perm: IPermission) => perm.resource === resource.toLowerCase())
  if (!permission) return false

  if (!condition) return true
  return permission.conditions?.[condition] || false
}

RoleSchema.methods.toJSON = function () {
  const roleObject = this.toObject()
  return roleObject
}

// Static methods
RoleSchema.statics.findByDepartment = function (departmentId: string | mongoose.Types.ObjectId) {
  return this.find({
    department: departmentId,
    status: 'active'
  }).populate('departmentDetails', 'name description')
}

RoleSchema.statics.findSystemRoles = function () {
  return this.find({
    isSystemRole: true,
    status: 'active'
  })
}

RoleSchema.statics.getHierarchyRoles = function (maxLevel: number) {
  return this.find({
    hierarchyLevel: { $lte: maxLevel },
    status: 'active'
  }).sort({ hierarchyLevel: -1 })
}

// Pre-save middleware
RoleSchema.pre('save', function (next) {
  // Auto-generate role name from display name if not provided
  if (!this.name && this.displayName) {
    this.name = this.displayName
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '')
  }

  // System roles don't need department validation
  if (this.isSystemRole) {
    this.department = undefined as any
  }

  next()
})

// Pre-remove middleware to prevent system role deletion
RoleSchema.pre('deleteOne', { document: true, query: false }, function (next) {
  if (this.isSystemRole) {
    return next(new Error('System roles cannot be deleted'))
  }
  next()
})

const Role = mongoose.models.Role || mongoose.model<IRole>("Role", RoleSchema)

// Register the model with the generic registry
import { registerModel } from '../lib/modelRegistry'
registerModel('Role', Role, RoleSchema, '1.0.0', ['Department'])

export default Role