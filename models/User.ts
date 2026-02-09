import mongoose, { Schema, type Document } from "mongoose"
import * as bcrypt from "bcryptjs"

export interface IUser extends Document {
  name: string
  email: string
  password: string
  role: mongoose.Types.ObjectId // Reference to Role model
  avatar?: string
  phone?: string
  department?: mongoose.Types.ObjectId // Reference to Department model (optional for clients)
  position?: string
  reportsTo?: mongoose.Types.ObjectId // For subordinate relationships
  assignedTo?: mongoose.Types.ObjectId[] // For assignment tracking
  status: "active" | "inactive" | "deleted" | "suspended" | "qualified" | "unqualified" // Extended for clients

  // Client-specific fields
  isClient: boolean // Flag to identify client users
  leadId?: mongoose.Types.ObjectId // Reference to Lead model (for clients created from leads)
  project?: mongoose.Types.ObjectId // Reference to Project model (for clients created from leads)
  clientStatus?: "qualified" | "unqualified" // Client-specific status
  company?: string // Client's company name
  website?: string // Client's website
  lastLogin?: Date
  emailVerified: boolean
  phoneVerified: boolean
  twoFactorEnabled: boolean
  twoFactorAttempts: number
  twoFactorLockedUntil?: Date
  twoFactorVerified: boolean
  passwordChangedAt?: Date
  resetPasswordToken?: string
  resetPasswordExpire?: Date
  address?: {
    street?: string
    city?: string
    state?: string
    country?: string
    zipCode?: string
  }
  socialLinks?: {
    linkName?: string
    linkUrl?: string
  }[]
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
  comparePassword(candidatePassword: string): Promise<boolean>
  generatePasswordResetToken(): string
  changedPasswordAfter(JWTTimestamp: number): boolean

  // Client-specific methods
  qualifyClient(): Promise<void>
  unqualifyClient(reason?: string): Promise<void>
}

const UserSchema = new Schema<IUser>(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      maxlength: [100, "Name cannot be more than 100 characters"],
      // index: true, // Removed - covered by text search index
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, "Please enter a valid email"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters"],
      select: false,
    },
    role: {
      type: Schema.Types.ObjectId,
      ref: 'Role',
      required: [true, "Role is required"],
      // index: true, // Removed - covered by compound indexes
    },
    avatar: {
      type: String,
      default: "",
    },
    phone: {
      type: String,
      trim: true,
      validate: {
        validator: function (v: string) {
          return !v || /^(\+[1-9][0-9]{6,14}|[0-9]{7,15})$/.test(v);
        },
        message: "Please enter a valid phone number"
      }
    },
    department: {
      type: Schema.Types.ObjectId,
      ref: 'Department',
      required: function (this: IUser) {
        return !this.isClient; // Department not required for clients
      },
      // index: true, // Removed - covered by compound indexes
    },
    position: {
      type: String,
      trim: true,
    },
    // For subordinate relationships (hierarchy)
    reportsTo: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: false,
      // index: true, // Removed - not frequently queried, can be sparse if needed
    },
    // For assignment tracking
    assignedTo: [{
      type: Schema.Types.ObjectId,
      ref: 'User'
    }],
    status: {
      type: String,
      enum: ["active", "inactive", "deleted", "suspended", "qualified", "unqualified"],
      default: "active",
      // index: true, // Removed - covered by compound indexes
    },

    // Client-specific fields
    isClient: {
      type: Boolean,
      default: false,
      // index: true, // Removed - covered by compound indexes
    },
    leadId: {
      type: Schema.Types.ObjectId,
      ref: 'Lead',
      required: false,
    },
    project: {
      type: Schema.Types.ObjectId,
      ref: 'Project',
      required: false,
    },
    clientStatus: {
      type: String,
      enum: ["qualified", "unqualified"],
      required: function (this: IUser) {
        return this.isClient; // Only required for client users
      },
      // index: true, // Removed - covered by compound indexes
    },
    company: {
      type: String,
      trim: true,
      maxlength: [200, "Company name cannot exceed 200 characters"],
      required: function (this: IUser) {
        return this.isClient; // Company required for clients
      },
    },
    website: {
      type: String,
      trim: true,
      maxlength: [200, "Company website cannot exceed 200 characters"],
      required: function (this: IUser) {
        return this.isClient; // Company required for clients
      },
    },
    lastLogin: {
      type: Date,
    },
    emailVerified: {
      type: Boolean,
      default: false,
    },
    phoneVerified: {
      type: Boolean,
      default: false,
    },
    twoFactorEnabled: {
      type: Boolean,
      default: true,
    },
    // 2FA specific fields
    twoFactorAttempts: {
      type: Number,
      default: 0,
    },
    twoFactorLockedUntil: {
      type: Date,
      default: null,
    },
    twoFactorVerified: {
      type: Boolean,
      default: false,
    },
    passwordChangedAt: {
      type: Date,
    },
    resetPasswordToken: {
      type: String,
      select: false,
    },
    resetPasswordExpire: {
      type: Date,
      select: false,
    },
    address: {
      street: { type: String, trim: true },
      city: { type: String, trim: true },
      state: { type: String, trim: true },
      country: { type: String, trim: true },
      zipCode: { type: String, trim: true },
    },
    socialLinks: [{
      linkName: { type: String, required: true, trim: true },
      linkUrl: { type: String, required: true, trim: true },
    }],
    metadata: {
      createdBy: { type: String },
      updatedBy: { type: String },
      notes: { type: String, trim: true },
      tags: [{ type: String, trim: true }],
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
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  },
)

// Optimized indexes for better query performance and CRUD operations
UserSchema.index({ role: 1, status: 1 }); // Common filter combination in user list
UserSchema.index({ status: 1, createdAt: -1 }); // Status with date sorting
UserSchema.index({ department: 1, status: 1 }); // Department filtering
UserSchema.index({ status: 1, lastLogin: -1 }); // Active users sorted by last login

// Text search index for name and email search in user list
UserSchema.index({
  name: 'text',
  email: 'text'
}, {
  weights: {
    name: 10,
    email: 8
  },
  name: 'user_search_index'
});

// Performance indexes for authentication and session management
UserSchema.index({ 'resetPasswordToken': 1 }, { sparse: true });
UserSchema.index({ 'resetPasswordExpire': 1 }, {
  sparse: true,
  expireAfterSeconds: 0 // TTL index for automatic cleanup
});

// Frequently accessed fields
UserSchema.index({ 'metadata.tags': 1 }, { sparse: true });
UserSchema.index({ emailVerified: 1, status: 1 });

// Client-specific indexes
UserSchema.index({ isClient: 1, status: 1 }); // Filter clients vs regular users
UserSchema.index({ isClient: 1, clientStatus: 1 }); // Client status filtering
UserSchema.index({ leadId: 1 }, { sparse: true }); // Link to leads
UserSchema.index({ project: 1 }, { sparse: true }); // Link to projects
UserSchema.index({ isClient: 1, createdAt: -1 }); // Client chronological listing
UserSchema.index({ company: 1 }, { sparse: true }); // Company-based searches

// Virtual for full name (if needed)
UserSchema.virtual('fullName').get(function () {
  return this.name;
});

// Virtual to populate role details
UserSchema.virtual('roleDetails', {
  ref: 'Role',
  localField: 'role',
  foreignField: '_id',
  justOne: true,
});

// Virtual to populate department details
UserSchema.virtual('departmentDetails', {
  ref: 'Department',
  localField: 'department',
  foreignField: '_id',
  justOne: true,
});

// Virtual to populate lead details (for clients)
UserSchema.virtual('leadDetails', {
  ref: 'Lead',
  localField: 'leadId',
  foreignField: '_id',
  justOne: true,
});

// Virtual to populate project details (for clients)
UserSchema.virtual('projectDetails', {
  ref: 'Project',
  localField: 'project',
  foreignField: '_id',
  justOne: true,
});

// Virtual to populate all projects for this client
UserSchema.virtual('projects', {
  ref: 'Project',
  localField: '_id',
  foreignField: 'clientId',
});

// Hash password before saving
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next()

  try {
    const salt = await bcrypt.genSalt(12)
    this.password = await bcrypt.hash(this.password, salt)
    this.passwordChangedAt = new Date(Date.now() - 1000); // Subtract 1 second to handle JWT timing
    next()
  } catch (error: any) {
    next(error)
  }
})

// Update passwordChangedAt when password is modified
UserSchema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) return next();
  this.passwordChangedAt = new Date(Date.now() - 1000);
  next();
});

// Compare password method
UserSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password)
}

// Generate password reset token
UserSchema.methods.generatePasswordResetToken = function (): string {
  const resetToken = require('crypto').randomBytes(32).toString('hex');

  this.resetPasswordToken = require('crypto')
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.resetPasswordExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  return resetToken;
}

// Check if password was changed after JWT was issued
UserSchema.methods.changedPasswordAfter = function (JWTTimestamp: number): boolean {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      (this.passwordChangedAt.getTime() / 1000).toString(),
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
}

// Remove sensitive fields from JSON output
UserSchema.methods.toJSON = function () {
  const userObject = this.toObject()
  delete userObject.password
  delete userObject.resetPasswordToken
  delete userObject.resetPasswordExpire
  delete userObject.__v
  return userObject
}

// New role-based permission methods
UserSchema.methods.hasPermission = async function (resource: string, action: string, condition?: string): Promise<boolean> {
  // Populate role if not already populated
  if (!this.roleDetails) {
    await this.populate('roleDetails')
  }

  if (!this.roleDetails) return false

  // Check if role has the permission
  const hasRolePermission = this.roleDetails.permissions.some((perm: any) =>
    perm.resource === resource.toLowerCase() &&
    perm.actions.includes(action.toLowerCase()) &&
    (!condition || perm.conditions?.[condition] === true)
  )

  // Also check additional user permissions
  const additionalPermission = `${resource.toLowerCase()}.${action.toLowerCase()}`
  const hasAdditionalPermission = this.permissions.includes(additionalPermission) || this.permissions.includes('*')

  return hasRolePermission || hasAdditionalPermission
}

UserSchema.methods.getAllPermissions = async function (): Promise<string[]> {
  // Populate role if not already populated
  if (!this.roleDetails) {
    await this.populate('roleDetails')
  }

  const rolePermissions: string[] = []

  if (this.roleDetails) {
    this.roleDetails.permissions.forEach((perm: any) => {
      perm.actions.forEach((action: string) => {
        rolePermissions.push(`${perm.resource}.${action}`)
      })
    })
  }

  // Combine role permissions with additional permissions
  return Array.from(new Set([...rolePermissions, ...this.permissions]))
}

UserSchema.methods.canAccessDepartment = async function (departmentId: string): Promise<boolean> {
  // Populate role if not already populated
  if (!this.roleDetails) {
    await this.populate('roleDetails')
  }

  // User can always access their own department
  if (this.department.toString() === departmentId.toString()) return true

  // Check if role has department-wide access conditions
  if (!this.roleDetails) return false

  return this.roleDetails.permissions.some((perm: any) =>
    perm.conditions?.department === true
  )
}

UserSchema.methods.canManageUser = async function (targetUser: any): Promise<boolean> {
  // Populate role if not already populated
  if (!this.roleDetails) {
    await this.populate('roleDetails')
  }

  if (!this.roleDetails) return false

  // Check hierarchy level - can only manage lower or equal levels
  if (targetUser.roleDetails?.hierarchyLevel >= this.roleDetails.hierarchyLevel) {
    return false
  }

  // Check if has user management permissions
  return this.hasPermission('users', 'update')
}

// Client-specific methods
UserSchema.methods.isClientUser = function (): boolean {
  return this.isClient === true
}

UserSchema.methods.isQualifiedClient = function (): boolean {
  return this.isClient && this.clientStatus === 'qualified'
}

UserSchema.methods.qualifyClient = async function (): Promise<void> {
  if (!this.isClient) {
    throw new Error('User is not a client')
  }

  this.clientStatus = 'qualified'
  this.status = 'qualified'
  await this.save()
}

UserSchema.methods.unqualifyClient = async function (reason?: string): Promise<void> {
  if (!this.isClient) {
    throw new Error('User is not a client')
  }

  this.clientStatus = 'unqualified'
  this.status = 'unqualified'

  // Update metadata with unqualification reason
  if (reason) {
    this.metadata = this.metadata || {}
    this.metadata.notes = reason
  }

  await this.save()
}

// Static methods for client management
UserSchema.statics.createClientFromLead = async function (leadData: any, createdBy: string) {
  // Find the client role
  const Role = mongoose.model('Role')
  const clientRole = await Role.findOne({ name: /^client$/i })

  if (!clientRole) {
    throw new Error('Client role not found. Please create a client role first.')
  }

  // Always enforce isClient: true
  const clientUser = new this({
    ...leadData,
    name: leadData.name,
    email: leadData.email,
    phone: leadData.phone,
    company: leadData.company,
    website: leadData.website,
    role: clientRole._id,
    isClient: true, // Explicitly enforce
    clientStatus: 'qualified',
    status: 'qualified',
    leadId: leadData._id,
    department: leadData.createdByDepartment, // Use sales department
    emailVerified: false,
    phoneVerified: false,
    twoFactorEnabled: false,
    metadata: {
      createdBy: createdBy,
      notes: `Created from lead qualification on ${new Date().toISOString()}`
    }
  })

  // Ensure isClient is true (redundant but defensive)
  clientUser.isClient = true;
  return await clientUser.save()
}

UserSchema.statics.getClientStats = async function (filter = {}) {
  const clientFilter = { ...filter, isClient: true }
  const stats = await this.aggregate([
    { $match: clientFilter },
    {
      $group: {
        _id: null,
        totalClients: { $sum: 1 },
        qualifiedClients: { $sum: { $cond: [{ $eq: ['$clientStatus', 'qualified'] }, 1, 0] } },
        unqualifiedClients: { $sum: { $cond: [{ $eq: ['$clientStatus', 'unqualified'] }, 1, 0] } },
      }
    }
  ])

  console.log('Client stats aggregation result:', stats)
  return stats
}

// Static method to get user roles and permissions
UserSchema.statics.getRolePermissions = function (role: string): string[] {
  const rolePermissions: Record<string, string[]> = {
    admin: ['*'], // Full access
    manager: [
      'users.read', 'users.create', 'users.update',
      'reports.read', 'reports.create',
      'dashboard.read'
    ],
    hr: [
      'users.read', 'users.create', 'users.update',
      'reports.read', 'dashboard.read'
    ],
    finance: [
      'users.read', 'reports.read', 'reports.create',
      'dashboard.read', 'finance.read', 'finance.create', 'finance.update'
    ],
    sales: [
      'users.read', 'reports.read', 'dashboard.read',
      'sales.read', 'sales.create', 'sales.update'
    ],
    user: [
      'dashboard.read', 'profile.read', 'profile.update'
    ]
  };

  return rolePermissions[role] || rolePermissions.user;
}

// Interface for static methods
interface IUserModel extends mongoose.Model<IUser> {
  getRolePermissions(role: string): string[];
  createClientFromLead(leadData: any, createdBy: string): Promise<IUser>;
  getClientStats(filter?: any): Promise<any>;
}

const User = mongoose.models.User as IUserModel || mongoose.model<IUser, IUserModel>("User", UserSchema)

// Register the model with the generic registry
import { registerModel } from '../lib/modelRegistry'
registerModel('User', User, UserSchema, '1.0.0', ['Role', 'Department'])

export default User
