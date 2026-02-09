import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { clearCache, executeGenericDbQuery } from '@/lib/mongodb'
import MilestoneTemplate from '@/models/MilestoneTemplate'
import Milestone from '@/models/Milestone'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

interface RouteParams {
  params: Promise<{ id: string }>
}

const templateIdSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid template ID')
})

const applyTemplateSchema = z.object({
  projectId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid project ID'),
  phaseId: z.string().regex(/^[0-9a-fA-F]{24}$/).optional(),
  startDate: z.string().datetime().optional(),
  adjustments: z.object({
    milestones: z.array(z.object({
      originalTitle: z.string(),
      title: z.string().optional(),
      description: z.string().optional(),
      durationDays: z.number().min(1).optional(),
      estimatedBudget: z.number().min(0).optional(),
      priority: z.enum(['low', 'medium', 'high', 'urgent']).optional()
    })).optional().default([])
  }).optional()
})

// GET /api/milestone-templates/[id] - Get specific template
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'read')
    
    const resolvedParams = await params
    const validatedParams = templateIdSchema.parse({ id: resolvedParams.id })

    const template = await executeGenericDbQuery(async () => {
      return await MilestoneTemplate.findOne({
        _id: validatedParams.id,
        isActive: true,
        isDeleted: false,
        $or: [
          { departmentId: user.departmentId },
          { isPublic: true },
          { createdBy: user.id }
        ]
      }).populate('createdBy', 'firstName lastName email')
        .populate('departmentId', 'name')
        .lean()
    }, `milestone-template-${validatedParams.id}`, 300000)

    if (!template) {
      return NextResponse.json({
        success: false,
        error: 'Template not found or access denied'
      }, { status: 404 })
    }

    return NextResponse.json({
      success: true,
      data: template,
      message: 'Template retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching template:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid template ID',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch template'
    }, { status: 500 })
  }
}

// POST /api/milestone-templates/[id]/apply - Apply template to project
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'create')
    
    const resolvedParams = await params
    const validatedParams = templateIdSchema.parse({ id: resolvedParams.id })
    
    const body = await request.json()
    const validatedData = applyTemplateSchema.parse(body)

    const result = await executeGenericDbQuery(async () => {
      // Fetch template
      const template = await MilestoneTemplate.findOne({
        _id: validatedParams.id,
        isActive: true,
        isDeleted: false,
        $or: [
          { departmentId: user.departmentId },
          { isPublic: true },
          { createdBy: user.id }
        ]
      })

      if (!template) {
        throw new Error('Template not found or access denied')
      }

      // Calculate start dates for milestones
      const baseStartDate = validatedData.startDate ? new Date(validatedData.startDate) : new Date()
      const createdMilestones = []
      
      // Create dependency map
      const milestoneMap = new Map()
      let currentDate = new Date(baseStartDate)

      // First pass: create milestones without dependencies
      for (let i = 0; i < template.milestones.length; i++) {
        const templateMilestone = template.milestones[i]
        const adjustment = validatedData.adjustments?.milestones?.find(
          adj => adj.originalTitle === templateMilestone.title
        )

        // Calculate due date
        const durationDays = adjustment?.durationDays || templateMilestone.durationDays
        const dueDate = new Date(currentDate)
        dueDate.setDate(dueDate.getDate() + durationDays)

        const milestoneData = {
          title: adjustment?.title || templateMilestone.title,
          description: adjustment?.description || templateMilestone.description,
          projectId: validatedData.projectId,
          phaseId: validatedData.phaseId,
          dueDate,
          priority: adjustment?.priority || templateMilestone.priority,
          deliverables: templateMilestone.deliverables,
          successCriteria: templateMilestone.successCriteria,
          budgetAllocation: adjustment?.estimatedBudget || templateMilestone.estimatedBudget,
          linkedTaskIds: [],
          dependencies: [], // Will be updated in second pass
          createdBy: user.id,
          status: 'pending'
        }

        const milestone = new Milestone(milestoneData)
        await milestone.save()
        
        milestoneMap.set(templateMilestone.title, milestone._id)
        createdMilestones.push(milestone)

        // Move to next milestone start date (allow some overlap/buffer)
        currentDate.setDate(currentDate.getDate() + Math.max(1, Math.floor(durationDays * 0.8)))
      }

      // Second pass: update dependencies
      for (let i = 0; i < template.milestones.length; i++) {
        const templateMilestone = template.milestones[i]
        const milestone = createdMilestones[i]

        if (templateMilestone.dependencies && templateMilestone.dependencies.length > 0) {
          const dependencyIds = templateMilestone.dependencies
            .map(depTitle => milestoneMap.get(depTitle))
            .filter(Boolean)

          if (dependencyIds.length > 0) {
            await Milestone.findByIdAndUpdate(milestone._id, {
              dependencies: dependencyIds
            })
            milestone.dependencies = dependencyIds
          }
        }
      }

      // Increment template usage count
      await MilestoneTemplate.findByIdAndUpdate(validatedParams.id, {
        $inc: { usageCount: 1 }
      })

      return {
        templateId: validatedParams.id,
        templateName: template.name,
        createdMilestones: createdMilestones.map(m => ({
          _id: m._id,
          title: m.title,
          dueDate: m.dueDate,
          priority: m.priority,
          status: m.status
        })),
        projectId: validatedData.projectId,
        phaseId: validatedData.phaseId
      }
    }, undefined, 0)

    // Clear caches
    clearCache('milestones')
    clearCache(`project-${validatedData.projectId}`)
    if (validatedData.phaseId) {
      clearCache(`phase-${validatedData.phaseId}`)
    }

    return NextResponse.json({
      success: true,
      data: result,
      message: `Successfully created ${result.createdMilestones.length} milestones from template "${result.templateName}"`
    })

  } catch (error: any) {
    console.error('Error applying template:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid request data',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to apply template'
    }, { status: 500 })
  }
}

// PUT /api/milestone-templates/[id] - Update template
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'update')
    
    const resolvedParams = await params
    const validatedParams = templateIdSchema.parse({ id: resolvedParams.id })
    
    const body = await request.json()
    // Remove _id and audit fields from update data
    const { _id, createdBy, createdAt, updatedAt, usageCount, ...updateData } = body

    const template = await executeGenericDbQuery(async () => {
      // Check ownership/permissions
      const existingTemplate = await MilestoneTemplate.findOne({
        _id: validatedParams.id,
        isActive: true,
        isDeleted: false,
        $or: [
          { createdBy: user.id },
          { departmentId: user.departmentId } // Department members can edit department templates
        ]
      })

      if (!existingTemplate) {
        throw new Error('Template not found or insufficient permissions')
      }

      const updated = await MilestoneTemplate.findByIdAndUpdate(
        validatedParams.id,
        {
          ...updateData,
          updatedBy: user.id
        },
        { new: true, runValidators: true }
      ).populate('createdBy', 'firstName lastName email')
       .populate('departmentId', 'name')

      return updated
    }, undefined, 0)

    // Clear caches
    clearCache('milestone-templates')
    clearCache(`milestone-template-${validatedParams.id}`)

    return NextResponse.json({
      success: true,
      data: template,
      message: 'Template updated successfully'
    })

  } catch (error: any) {
    console.error('Error updating template:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid template data',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to update template'
    }, { status: 500 })
  }
}

// DELETE /api/milestone-templates/[id] - Soft delete template
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'delete')
    
    const resolvedParams = await params
    const validatedParams = templateIdSchema.parse({ id: resolvedParams.id })

    const template = await executeGenericDbQuery(async () => {
      // Check ownership/permissions
      const existingTemplate = await MilestoneTemplate.findOne({
        _id: validatedParams.id,
        isActive: true,
        isDeleted: false,
        createdBy: user.id // Only creator can delete
      })

      if (!existingTemplate) {
        throw new Error('Template not found or insufficient permissions')
      }

      return await MilestoneTemplate.findByIdAndUpdate(
        validatedParams.id,
        {
          isDeleted: true,
          isActive: false,
          deletedAt: new Date(),
          deletedBy: user.id
        },
        { new: true }
      )
    }, undefined, 0)

    // Clear caches
    clearCache('milestone-templates')
    clearCache(`milestone-template-${validatedParams.id}`)

    return NextResponse.json({
      success: true,
      message: 'Template deleted successfully'
    })

  } catch (error: any) {
    console.error('Error deleting template:', error)

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to delete template'
    }, { status: 500 })
  }
}