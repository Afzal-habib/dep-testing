import mongoose, { Document, Schema, Types } from 'mongoose';

export interface IMilestoneApproval extends Document {
  _id: string;
  milestoneId: Types.ObjectId | string;
  projectId: Types.ObjectId | string;
  phaseId?: Types.ObjectId | string;
  
  // Approval workflow
  currentStage: string;
  stages: {
    stageName: string;
    requiredRoles: string[];
    approvals: {
      userId: Types.ObjectId | string;
      userRole: string;
      status: 'pending' | 'approved' | 'rejected' | 'delegated';
      comments?: string;
      approvedAt?: Date;
      delegatedTo?: Types.ObjectId | string;
    }[];
    stageStatus: 'pending' | 'in-review' | 'approved' | 'rejected';
    completedAt?: Date;
    isOptional: boolean;
    order: number;
  }[];
  
  // Overall status
  overallStatus: 'pending' | 'in-review' | 'approved' | 'rejected' | 'cancelled';
  finalApprovedAt?: Date;
  finalApprovedBy?: Types.ObjectId | string;
  
  // Metadata
  submittedBy: Types.ObjectId | string;
  submittedAt: Date;
  completionDeadline?: Date;
  
  // Comments and attachments
  submissionComments?: string;
  rejectionReason?: string;
  attachments?: {
    fileName: string;
    filePath: string;
    uploadedBy: Types.ObjectId | string;
    uploadedAt: Date;
  }[];
  
  // Audit fields
  isActive: boolean;
  cancelledAt?: Date;
  cancelledBy?: Types.ObjectId | string;
  cancellationReason?: string;
}

export interface MilestoneApprovalModel extends mongoose.Model<IMilestoneApproval> {
  findPendingApprovals(userId: string, userRoles: string[]): Promise<IMilestoneApproval[]>;
  findByMilestone(milestoneId: string): Promise<IMilestoneApproval | null>;
  createFromTemplate(milestoneId: string, workflowConfig: any, submittedBy: string): Promise<IMilestoneApproval>;
}

const MilestoneApprovalSchema = new Schema<IMilestoneApproval>({
  milestoneId: {
    type: Schema.Types.ObjectId,
    ref: 'Milestone',
    required: true,
    index: true
  },
  projectId: {
    type: Schema.Types.ObjectId,
    ref: 'Project',
    required: true,
    index: true
  },
  phaseId: {
    type: Schema.Types.ObjectId,
    ref: 'Phase',
    index: true
  },
  currentStage: {
    type: String,
    required: true,
    trim: true
  },
  stages: [{
    stageName: {
      type: String,
      required: true,
      trim: true
    },
    requiredRoles: [{
      type: String,
      required: true
    }],
    approvals: [{
      userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
      },
      userRole: {
        type: String,
        required: true
      },
      status: {
        type: String,
        enum: ['pending', 'approved', 'rejected', 'delegated'],
        default: 'pending'
      },
      comments: String,
      approvedAt: Date,
      delegatedTo: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      }
    }],
    stageStatus: {
      type: String,
      enum: ['pending', 'in-review', 'approved', 'rejected'],
      default: 'pending'
    },
    completedAt: Date,
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
  overallStatus: {
    type: String,
    enum: ['pending', 'in-review', 'approved', 'rejected', 'cancelled'],
    default: 'pending',
    index: true
  },
  finalApprovedAt: Date,
  finalApprovedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  submittedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  submittedAt: {
    type: Date,
    default: Date.now,
    required: true
  },
  completionDeadline: Date,
  submissionComments: {
    type: String,
    maxlength: [1000, "Submission comments cannot exceed 1000 characters"]
  },
  rejectionReason: {
    type: String,
    maxlength: [1000, "Rejection reason cannot exceed 1000 characters"]
  },
  attachments: [{
    fileName: {
      type: String,
      required: true
    },
    filePath: {
      type: String,
      required: true
    },
    uploadedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  cancelledAt: Date,
  cancelledBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  cancellationReason: String
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
MilestoneApprovalSchema.index({ milestoneId: 1, isActive: 1 });
MilestoneApprovalSchema.index({ projectId: 1, overallStatus: 1 });
MilestoneApprovalSchema.index({ 'stages.approvals.userId': 1, 'stages.approvals.status': 1 });
MilestoneApprovalSchema.index({ submittedBy: 1 });
MilestoneApprovalSchema.index({ completionDeadline: 1 });

// Virtuals
MilestoneApprovalSchema.virtual('isOverdue').get(function(this: IMilestoneApproval) {
  return this.completionDeadline && 
         this.completionDeadline < new Date() && 
         !['approved', 'rejected', 'cancelled'].includes(this.overallStatus);
});

MilestoneApprovalSchema.virtual('totalStages').get(function(this: IMilestoneApproval) {
  return this.stages?.length || 0;
});

MilestoneApprovalSchema.virtual('completedStages').get(function(this: IMilestoneApproval) {
  return this.stages?.filter((stage: any) => stage.stageStatus === 'approved').length || 0;
});

// Static methods
MilestoneApprovalSchema.statics.findPendingApprovals = function(userId: string, userRoles: string[]) {
  return this.find({
    isActive: true,
    overallStatus: { $in: ['pending', 'in-review'] },
    'stages.approvals': {
      $elemMatch: {
        userId,
        status: 'pending'
      }
    }
  }).populate('milestoneId', 'title description dueDate priority')
    .populate('projectId', 'title client')
    .populate('submittedBy', 'firstName lastName email')
    .sort({ submittedAt: 1 });
};

MilestoneApprovalSchema.statics.findByMilestone = function(milestoneId: string) {
  return this.findOne({
    milestoneId,
    isActive: true
  }).populate('milestoneId')
    .populate('projectId', 'title client')
    .populate('submittedBy', 'firstName lastName email')
    .populate('stages.approvals.userId', 'firstName lastName email role')
    .populate('finalApprovedBy', 'firstName lastName email');
};

MilestoneApprovalSchema.statics.createFromTemplate = function(
  milestoneId: string, 
  workflowConfig: any, 
  submittedBy: string
) {
  interface StageTemplate {
    stageName: string;
    requiredRoles: string[];
    approvals: any[];
    stageStatus: string;
    isOptional: boolean;
    order: number;
  }

  const stages: StageTemplate[] = workflowConfig.approvalStages.map((stage: any) => ({
    stageName: stage.stageName,
    requiredRoles: stage.requiredRoles,
    approvals: [], // Will be populated when users are assigned
    stageStatus: 'pending',
    isOptional: stage.isOptional,
    order: stage.order
  }));

  return this.create({
    milestoneId,
    currentStage: stages[0]?.stageName || 'Initial Review',
    stages: stages.sort((a: StageTemplate, b: StageTemplate) => a.order - b.order),
    submittedBy,
    submittedAt: new Date()
  });
};

// Middleware
MilestoneApprovalSchema.pre('save', function(this: IMilestoneApproval, next) {
  // Update overall status based on stage statuses
  if (this.isModified('stages')) {
    const allStages = this.stages;
    const requiredStages = allStages.filter((stage: any) => !stage.isOptional);
    const approvedRequired = requiredStages.filter((stage: any) => stage.stageStatus === 'approved');
    const rejectedAny = allStages.some((stage: any) => stage.stageStatus === 'rejected');
    
    if (rejectedAny) {
      this.overallStatus = 'rejected';
    } else if (approvedRequired.length === requiredStages.length) {
      this.overallStatus = 'approved';
      this.finalApprovedAt = new Date();
    } else if (allStages.some((stage: any) => stage.stageStatus === 'in-review')) {
      this.overallStatus = 'in-review';
    }
  }
  
  next();
});

const MilestoneApprovalModel = (mongoose.models.MilestoneApproval as mongoose.Model<IMilestoneApproval> & MilestoneApprovalModel) || 
  mongoose.model<IMilestoneApproval, MilestoneApprovalModel>("MilestoneApproval", MilestoneApprovalSchema);

export default MilestoneApprovalModel;