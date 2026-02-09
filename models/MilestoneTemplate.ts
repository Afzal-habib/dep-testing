import mongoose, { Document, Schema, Types } from 'mongoose';

export interface IMilestoneTemplate extends Document {
  _id: string;
  name: string;
  description?: string;
  departmentId?: Types.ObjectId | string;
  category: 'design' | 'development' | 'marketing' | 'hr' | 'finance' | 'operations' | 'generic';
  
  // Template structure
  milestones: {
    title: string;
    description?: string;
    durationDays: number;
    dependencies?: string[]; // References to other milestone titles in template
    deliverables: string[];
    successCriteria: string[];
    priority: 'low' | 'medium' | 'high' | 'urgent';
    requiredApprovals?: string[]; // Role names that need to approve
    estimatedBudget?: number;
    estimatedHours?: number;
  }[];
  
  // Workflow configuration
  workflowConfig: {
    requiresApproval: boolean;
    approvalStages: {
      stageName: string;
      requiredRoles: string[];
      isOptional: boolean;
      order: number;
    }[];
    autoProgressRules?: {
      condition: string;
      action: string;
    }[];
  };
  
  // Metadata
  isActive: boolean;
  isPublic: boolean; // Can be used by other departments
  usageCount: number;
  tags: string[];
  
  // Audit fields
  createdBy: Types.ObjectId | string;
  updatedBy?: Types.ObjectId | string;
  isDeleted: boolean;
  deletedAt?: Date;
  deletedBy?: Types.ObjectId | string;
}

export interface MilestoneTemplateModel extends mongoose.Model<IMilestoneTemplate> {
  findByDepartment(departmentId: string): Promise<IMilestoneTemplate[]>;
  findPublicTemplates(): Promise<IMilestoneTemplate[]>;
  incrementUsage(templateId: string): Promise<void>;
}

const MilestoneTemplateSchema = new Schema<IMilestoneTemplate>({
  name: {
    type: String,
    required: [true, "Template name is required"],
    trim: true,
    maxlength: [100, "Name cannot exceed 100 characters"],
    minlength: [2, "Name must be at least 2 characters"]
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, "Description cannot exceed 500 characters"]
  },
  departmentId: {
    type: Schema.Types.ObjectId,
    ref: 'Department',
    index: true
  },
  category: {
    type: String,
    enum: ['design', 'development', 'marketing', 'hr', 'finance', 'operations', 'generic'],
    required: true,
    default: 'generic',
    index: true
  },
  milestones: [{
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: [200, "Milestone title cannot exceed 200 characters"]
    },
    description: {
      type: String,
      trim: true,
      maxlength: [1000, "Description cannot exceed 1000 characters"]
    },
    durationDays: {
      type: Number,
      required: true,
      min: [1, "Duration must be at least 1 day"],
      max: [365, "Duration cannot exceed 365 days"]
    },
    dependencies: [{
      type: String,
      trim: true
    }],
    deliverables: [{
      type: String,
      required: true,
      trim: true,
      maxlength: [300, "Deliverable description too long"]
    }],
    successCriteria: [{
      type: String,
      required: true,
      trim: true,
      maxlength: [300, "Success criteria description too long"]
    }],
    priority: {
      type: String,
      enum: ['low', 'medium', 'high', 'urgent'],
      default: 'medium'
    },
    requiredApprovals: [{
      type: String,
      trim: true
    }],
    estimatedBudget: {
      type: Number,
      min: [0, "Budget cannot be negative"]
    },
    estimatedHours: {
      type: Number,
      min: [0, "Hours cannot be negative"]
    }
  }],
  workflowConfig: {
    requiresApproval: {
      type: Boolean,
      default: false
    },
    approvalStages: [{
      stageName: {
        type: String,
        required: true,
        trim: true
      },
      requiredRoles: [{
        type: String,
        required: true
      }],
      isOptional: {
        type: Boolean,
        default: false
      },
      order: {
        type: Number,
        required: true,
        min: 0
      }
    }],
    autoProgressRules: [{
      condition: String,
      action: String
    }]
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  isPublic: {
    type: Boolean,
    default: false,
    index: true
  },
  usageCount: {
    type: Number,
    default: 0,
    min: 0
  },
  tags: [{
    type: String,
    trim: true,
    lowercase: true
  }],
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  isDeleted: {
    type: Boolean,
    default: false,
    index: true
  },
  deletedAt: Date,
  deletedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
MilestoneTemplateSchema.index({ departmentId: 1, isActive: 1, isDeleted: 1 });
MilestoneTemplateSchema.index({ category: 1, isPublic: 1, isActive: 1 });
MilestoneTemplateSchema.index({ tags: 1 });
MilestoneTemplateSchema.index({ usageCount: -1 });

// Virtual for milestone count
MilestoneTemplateSchema.virtual('milestoneCount').get(function(this: IMilestoneTemplate) {
  return this.milestones?.length || 0;
});

// Virtual for estimated total duration
MilestoneTemplateSchema.virtual('estimatedTotalDuration').get(function(this: IMilestoneTemplate) {
  return this.milestones?.reduce((total: number, milestone: any) => total + milestone.durationDays, 0) || 0;
});

// Static methods
MilestoneTemplateSchema.statics.findByDepartment = function(departmentId: string) {
  return this.find({
    $or: [
      { departmentId, isActive: true, isDeleted: false },
      { isPublic: true, isActive: true, isDeleted: false }
    ]
  }).populate('createdBy', 'firstName lastName email')
    .populate('departmentId', 'name')
    .sort({ usageCount: -1, createdAt: -1 });
};

MilestoneTemplateSchema.statics.findPublicTemplates = function() {
  return this.find({
    isPublic: true,
    isActive: true,
    isDeleted: false
  }).populate('createdBy', 'firstName lastName email')
    .populate('departmentId', 'name')
    .sort({ usageCount: -1, createdAt: -1 });
};

MilestoneTemplateSchema.statics.incrementUsage = function(templateId: string) {
  return this.findByIdAndUpdate(
    templateId,
    { $inc: { usageCount: 1 } },
    { new: true }
  );
};

// Middleware for validation
MilestoneTemplateSchema.pre('save', function(this: IMilestoneTemplate, next) {
  // Validate milestone dependencies
  const milestoneNames = this.milestones.map((m: any) => m.title);
  
  for (const milestone of this.milestones) {
    if (milestone.dependencies) {
      for (const dep of milestone.dependencies) {
        if (!milestoneNames.includes(dep)) {
          return next(new Error(`Invalid dependency: "${dep}" not found in milestone titles`));
        }
      }
    }
  }
  
  // Validate approval stages order
  if (this.workflowConfig.approvalStages) {
    const orders = this.workflowConfig.approvalStages.map((stage: any) => stage.order);
    const uniqueOrders = new Set(orders);
    if (orders.length !== uniqueOrders.size) {
      return next(new Error('Approval stages must have unique order values'));
    }
  }
  
  next();
});

const MilestoneTemplateModel = (mongoose.models.MilestoneTemplate as mongoose.Model<IMilestoneTemplate> & MilestoneTemplateModel) || 
  mongoose.model<IMilestoneTemplate, MilestoneTemplateModel>("MilestoneTemplate", MilestoneTemplateSchema);

export default MilestoneTemplateModel;