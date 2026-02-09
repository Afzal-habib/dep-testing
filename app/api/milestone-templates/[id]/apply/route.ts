import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { clearCache, executeGenericDbQuery } from '@/lib/mongodb'
import MilestoneTemplate from '@/models/MilestoneTemplate'
import Milestone from '@/models/Milestone'
import Project from '@/models/Project'
import Phase from '@/models/Phase'
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
  startDate: z.string().optional(),
  adjustments: z.object({
    milestones: z.array(z.object({
      originalTitle: z.string(),
      title: z.string().optional(),
      description: z.string().optional(),
      durationDays: z.number().min(1).optional(),
      estimatedBudget: z.number().min(0).optional(),
      estimatedHours: z.number().min(0).optional(),
      priority: z.enum(['low', 'medium', 'high', 'urgent']).optional()
    })).optional().default([])
  }).optional().default({ milestones: [] })
})

// POST /api/milestone-templates/[id]/apply - Apply template to project
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'milestones', 'create')
    
    const resolvedParams = await params
    const validatedParams = templateIdSchema.parse({ id: resolvedParams.id })
    
    const body = await request.json()
    const validatedBody = applyTemplateSchema.parse(body)

    const result = await executeGenericDbQuery(async () => {
      console.log('Apply template debug:', {
        templateId: validatedParams.id,
        projectId: validatedBody.projectId,
        userId: user.id,
        isSuperAdmin,
        userRole: user.role
      })

      // Get template (super admin can access any template)
      const templateQuery: any = {
        _id: validatedParams.id,
        isActive: true,
        isDeleted: false
      }

      if (!isSuperAdmin) {
        templateQuery.$or = [
          { departmentId: user.departmentId },
          { isPublic: true },
          { createdBy: user.id }
        ]
      }

      const template = await MilestoneTemplate.findOne(templateQuery)

      if (!template) {
        throw new Error('Template not found or access denied')
      }

      // Verify project access (super admin can access any project)
      let project
      if (isSuperAdmin) {
        project = await Project.findOne({ _id: validatedBody.projectId })
      } else {
        project = await Project.findOne({
          _id: validatedBody.projectId,
          $or: [
            { 'team.members': user.id },
            { clientId: user.id },
            { createdBy: user.id }
          ]
        })
      }
      
      if (!project) {
        throw new Error('Project not found or access denied')
      }

      // Verify phase if provided
      let phase = null
      if (validatedBody.phaseId) {
        phase = await Phase.findOne({
          _id: validatedBody.phaseId,
          projectId: validatedBody.projectId
        })

        if (!phase) {
          throw new Error('Phase not found')
        }
      }

      // Calculate start date
      const startDate = validatedBody.startDate ? new Date(validatedBody.startDate) : new Date()
      
      // Create adjustments map
      const adjustmentsMap = new Map()
      if (validatedBody.adjustments?.milestones) {
        validatedBody.adjustments.milestones.forEach(adj => {
          adjustmentsMap.set(adj.originalTitle, adj)
        })
      }

      // Create milestones from template
      const createdMilestones = []
      let currentDate = new Date(startDate)

      for (let i = 0; i < template.milestones.length; i++) {
        const templateMilestone = template.milestones[i]
        const adjustment = adjustmentsMap.get(templateMilestone.title)
        
        // Calculate due date based on duration
        const durationDays = adjustment?.durationDays || templateMilestone.durationDays
        const dueDate = new Date(currentDate)
        dueDate.setDate(dueDate.getDate() + durationDays)

        // Create milestone
        const milestoneData = {
          title: adjustment?.title || templateMilestone.title,
          description: adjustment?.description || templateMilestone.description || `Generated from template: ${template.name}`,
          projectId: validatedBody.projectId,
          phaseId: validatedBody.phaseId,
          assigneeId: user.id, // Assign to current user by default
          dueDate: dueDate,
          priority: adjustment?.priority || templateMilestone.priority || 'medium',
          status: 'pending' as const,
          progress: 0,
          budgetAllocation: adjustment?.estimatedBudget || templateMilestone.estimatedBudget || 0,
          deliverables: templateMilestone.deliverables || [],
          successCriteria: templateMilestone.successCriteria || [],
          dependencies: [],
          linkedTaskIds: [],
          createdBy: user.id,
          isDeleted: false
        }

        const milestone = await Milestone.create(milestoneData)
        createdMilestones.push(milestone)

        // Move to next start date (end of current milestone)
        currentDate = new Date(dueDate)
        currentDate.setDate(currentDate.getDate() + 1)
      }

      // Update template usage count
      await MilestoneTemplate.findByIdAndUpdate(
        template._id,
        { $inc: { usageCount: 1 } }
      )

      return {
        template: template,
        milestones: createdMilestones,
        project: project,
        phase: phase
      }
    }, undefined, 0)

    // Clear relevant caches
    clearCache('milestones')
    clearCache(`milestones-list`)
    clearCache(`project-milestones-${validatedBody.projectId}`)
    clearCache(`project-${validatedBody.projectId}-milestones`)
    if (validatedBody.phaseId) {
      clearCache(`phase-milestones-${validatedBody.phaseId}`)
      clearCache(`phase-${validatedBody.phaseId}-milestones`)
    }
    
    // Clear any generic milestone caches
    clearCache(`/api/milestones`)
    clearCache(`milestones-data`)
    
    console.log('Cleared caches for milestone template application')

    return NextResponse.json({
      success: true,
      data: result,
      message: `Successfully applied template "${result.template.name}" - ${result.milestones.length} milestones created`
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