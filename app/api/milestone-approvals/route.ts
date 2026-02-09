import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { clearCache, executeGenericDbQuery } from '@/lib/mongodb'
import MilestoneApproval from '@/models/MilestoneApproval'
import Milestone from '@/models/Milestone'
import User from '@/models/User'
import Role from '@/models/Role'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

// Validation schemas
const submitApprovalSchema = z.object({
  milestoneId: z.string().regex(/^[0-9a-fA-F]{24}$/),
  projectId: z.string().regex(/^[0-9a-fA-F]{24}$/),
  phaseId: z.string().regex(/^[0-9a-fA-F]{24}$/).optional(),
  workflowConfig: z.object({
    requiresApproval: z.boolean(),
    approvalStages: z.array(z.object({
      stageName: z.string(),
      requiredRoles: z.array(z.string()),
      isOptional: z.boolean().default(false),
      order: z.number()
    }))
  }),
  submissionComments: z.string().max(1000).optional(),
  completionDeadline: z.string().datetime().optional()
})

const approvalActionSchema = z.object({
  approvalId: z.string().regex(/^[0-9a-fA-F]{24}$/),
  action: z.enum(['approve', 'reject', 'delegate']),
  comments: z.string().max(1000).optional(),
  delegateToUserId: z.string().regex(/^[0-9a-fA-F]{24}$/).optional()
})

const approvalQuerySchema = z.object({
  status: z.enum(['pending', 'in-review', 'approved', 'rejected', 'cancelled']).optional(),
  projectId: z.string().regex(/^[0-9a-fA-F]{24}$/).optional(),
  milestoneId: z.string().regex(/^[0-9a-fA-F]{24}$/).optional(),
  assignedToMe: z.boolean().optional(),
  overdue: z.boolean().optional(),
  limit: z.string().transform(val => parseInt(val) || 20).optional(),
  page: z.string().transform(val => parseInt(val) || 1).optional()
})

// GET /api/milestone-approvals - List milestone approvals
export async function GET(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'read')

    const searchParams = request.nextUrl.searchParams
    const queryParams = {
      status: searchParams.get('status') || undefined,
      projectId: searchParams.get('projectId') || undefined,
      milestoneId: searchParams.get('milestoneId') || undefined,
      assignedToMe: searchParams.get('assignedToMe') === 'true',
      overdue: searchParams.get('overdue') === 'true',
      limit: searchParams.get('limit') || '20',
      page: searchParams.get('page') || '1'
    }

    const validatedParams = approvalQuerySchema.parse(queryParams)

    const approvals = await executeGenericDbQuery(async () => {
      const filter: any = { isActive: true }

      // Status filter
      if (validatedParams.status) {
        filter.overallStatus = validatedParams.status
      }

      // Project filter
      if (validatedParams.projectId) {
        filter.projectId = validatedParams.projectId
      }

      // Milestone filter
      if (validatedParams.milestoneId) {
        filter.milestoneId = validatedParams.milestoneId
      }

      // Assigned to me filter
      if (validatedParams.assignedToMe) {
        filter['stages.approvals.userId'] = user.id
        filter['stages.approvals.status'] = 'pending'
      }

      // Overdue filter
      if (validatedParams.overdue) {
        filter.completionDeadline = { $lt: new Date() }
        filter.overallStatus = { $in: ['pending', 'in-review'] }
      }

      // Pagination
      const skip = ((validatedParams.page || 1) - 1) * (validatedParams.limit || 20)

      const [approvals, total] = await Promise.all([
        MilestoneApproval.find(filter)
          .populate('milestoneId', 'title description priority dueDate')
          .populate('projectId', 'title client')
          .populate('submittedBy', 'firstName lastName email')
          .populate('stages.approvals.userId', 'firstName lastName email role')
          .sort({ submittedAt: -1 })
          .skip(skip)
          .limit(validatedParams.limit || 20)
          .lean(),
        MilestoneApproval.countDocuments(filter)
      ])

      return {
        approvals,
        pagination: {
          page: validatedParams.page || 1,
          limit: validatedParams.limit || 20,
          total,
          pages: Math.ceil(total / (validatedParams.limit || 20))
        }
      }
    }, `milestone-approvals-${JSON.stringify(validatedParams)}`, 60000)

    return NextResponse.json({
      success: true,
      data: approvals.approvals,
      pagination: approvals.pagination,
      message: 'Milestone approvals retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching milestone approvals:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid query parameters',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch milestone approvals'
    }, { status: 500 })
  }
}

// POST /api/milestone-approvals - Submit milestone for approval
export async function POST(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'update')

    const body = await request.json()
    const validatedData = submitApprovalSchema.parse(body)

    const approval = await executeGenericDbQuery(async () => {
      // Check if milestone exists and user has permission
      const milestone = await Milestone.findOne({
        _id: validatedData.milestoneId,
        isDeleted: { $ne: true }
      }).populate('projectId', '_id title')
      
      console.log('Milestone approval check:', {
        milestoneId: validatedData.milestoneId,
        milestone: milestone ? {
          id: milestone._id,
          title: milestone.title,
          createdBy: milestone.createdBy,
          assigneeId: milestone.assigneeId,
          projectId: milestone.projectId
        } : null,
        userId: user.id,
        userRole: user.role
      });
      
      if (!milestone) {
        throw new Error('Milestone not found')
      }
      

      // Check if approval already exists
      const existingApproval = await MilestoneApproval.findOne({
        milestoneId: validatedData.milestoneId,
        isActive: true
      })

      if (existingApproval && existingApproval.overallStatus !== 'rejected') {
        throw new Error('Milestone is already in approval process')
      }

      // Create approval stages with assigned users
      const stages = []
      for (const stageConfig of validatedData.workflowConfig.approvalStages) {
        // Find roles first, then find users with those roles
        const roles = await Role.find({
          name: { $in: stageConfig.requiredRoles },
          isActive: true
        }).select('_id name')
        
        const roleIds = roles.map(role => role._id)
        
        // Find users with required roles (by role ObjectId) or super admins
        const stageUsers = await User.find({
          isActive: true,
          $or: [
            { role: { $in: roleIds } },
            { role: 'super-administrator' }, // String-based role for super admin
            { 'permissions.isSuperAdmin': true } // Alternative super admin check
          ]
        }).select('_id firstName lastName role').populate('role', 'name')

        const approvals = stageUsers.map(stageUser => ({
          userId: stageUser._id,
          userRole: typeof stageUser.role === 'string' ? stageUser.role : (stageUser.role as { name?: string } | null)?.name || 'unknown',
          status: 'pending'
        }))

        stages.push({
          stageName: stageConfig.stageName,
          requiredRoles: stageConfig.requiredRoles,
          approvals,
          stageStatus: 'pending',
          isOptional: stageConfig.isOptional,
          order: stageConfig.order
        })
      }

      // Sort stages by order
      stages.sort((a, b) => a.order - b.order)

      // Create approval record
      const approvalData = {
        milestoneId: validatedData.milestoneId,
        projectId: validatedData.projectId,
        phaseId: validatedData.phaseId,
        currentStage: stages[0]?.stageName || 'Initial Review',
        stages,
        submittedBy: user.id,
        submissionComments: validatedData.submissionComments,
        completionDeadline: validatedData.completionDeadline ? 
          new Date(validatedData.completionDeadline) : undefined
      }

      const approval = new MilestoneApproval(approvalData)
      await approval.save()

      // Update milestone status
      await Milestone.findByIdAndUpdate(validatedData.milestoneId, {
        status: 'pending', // Milestone is pending approval
        updatedBy: user.id
      })

      return await MilestoneApproval.findById(approval._id)
        .populate('milestoneId', 'title description priority')
        .populate('projectId', 'title client')
        .populate('submittedBy', 'firstName lastName email')
        .populate('stages.approvals.userId', 'firstName lastName email role')

    }, undefined, 0)

    // Clear caches
    clearCache('milestone-approvals')
    clearCache('milestones')

    return NextResponse.json({
      success: true,
      data: approval,
      message: 'Milestone submitted for approval successfully'
    }, { status: 201 })

  } catch (error: any) {
    console.error('Error submitting milestone approval:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid approval data',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to submit milestone for approval'
    }, { status: 500 })
  }
}

// PUT /api/milestone-approvals - Process approval action
export async function PUT(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'update')

    const body = await request.json()
    const validatedData = approvalActionSchema.parse(body)

    const result = await executeGenericDbQuery(async () => {
      const approval = await MilestoneApproval.findById(validatedData.approvalId)
      
      if (!approval || !approval.isActive) {
        throw new Error('Approval record not found')
      }

      // Find user's pending approval in current stage
      const currentStageIndex = approval.stages.findIndex(
        stage => stage.stageName === approval.currentStage
      )
      
      if (currentStageIndex === -1) {
        throw new Error('Current approval stage not found')
      }

      const currentStage = approval.stages[currentStageIndex]
      const userApprovalIndex = currentStage.approvals.findIndex(
        app => app.userId.toString() === user.id && app.status === 'pending'
      )

      if (userApprovalIndex === -1) {
        throw new Error('No pending approval found for current user in this stage')
      }

      // Process the approval action
      const userApproval = currentStage.approvals[userApprovalIndex]
      
      if (validatedData.action === 'approve') {
        userApproval.status = 'approved'
        userApproval.approvedAt = new Date()
        userApproval.comments = validatedData.comments
      } else if (validatedData.action === 'reject') {
        userApproval.status = 'rejected'
        userApproval.comments = validatedData.comments
        currentStage.stageStatus = 'rejected'
        approval.overallStatus = 'rejected'
        approval.rejectionReason = validatedData.comments
      } else if (validatedData.action === 'delegate') {
        if (!validatedData.delegateToUserId) {
          throw new Error('Delegate user ID is required for delegation')
        }
        userApproval.status = 'delegated'
        userApproval.delegatedTo = validatedData.delegateToUserId
        userApproval.comments = validatedData.comments
        
        // Add new approval for delegated user
        currentStage.approvals.push({
          userId: validatedData.delegateToUserId,
          userRole: userApproval.userRole,
          status: 'pending'
        })
      }

      // Check if current stage is complete
      if (validatedData.action !== 'reject') {
        const pendingApprovals = currentStage.approvals.filter(app => app.status === 'pending')
        const approvedApprovals = currentStage.approvals.filter(app => app.status === 'approved')
        
        // Stage is complete if all required approvals are done
        if (pendingApprovals.length === 0 && approvedApprovals.length > 0) {
          currentStage.stageStatus = 'approved'
          currentStage.completedAt = new Date()
          
          // Move to next stage or complete approval
          const nextStageIndex = currentStageIndex + 1
          if (nextStageIndex < approval.stages.length) {
            approval.currentStage = approval.stages[nextStageIndex].stageName
            approval.overallStatus = 'in-review'
          } else {
            // All stages complete
            approval.overallStatus = 'approved'
            approval.finalApprovedAt = new Date()
            approval.finalApprovedBy = user.id
            
            // Update milestone status
            await Milestone.findByIdAndUpdate(approval.milestoneId, {
              status: 'in-progress',
              updatedBy: user.id
            })
          }
        } else if (pendingApprovals.length > 0) {
          currentStage.stageStatus = 'in-review'
          approval.overallStatus = 'in-review'
        }
      } else {
        // Rejection: update milestone status
        await Milestone.findByIdAndUpdate(approval.milestoneId, {
          status: 'on-hold',
          updatedBy: user.id
        })
      }

      await approval.save()
      return approval

    }, undefined, 0)

    // Clear caches
    clearCache('milestone-approvals')
    clearCache('milestones')

    return NextResponse.json({
      success: true,
      data: result,
      message: `Approval ${validatedData.action} processed successfully`
    })

  } catch (error: any) {
    console.error('Error processing approval:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid approval action data',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to process approval'
    }, { status: 500 })
  }
}