import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { clearCache, executeGenericDbQuery } from '@/lib/mongodb'
import MilestoneTemplate from '@/models/MilestoneTemplate'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

// Validation schemas
const milestoneItemSchema = z.object({
  title: z.string().min(2).max(200),
  description: z.string().max(1000).optional(),
  durationDays: z.number().min(1).max(365),
  dependencies: z.array(z.string()).optional().default([]),
  deliverables: z.array(z.string().min(1).max(300)).min(1),
  successCriteria: z.array(z.string().min(1).max(300)).min(1),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
  requiredApprovals: z.array(z.string()).optional().default([]),
  estimatedBudget: z.number().min(0).optional(),
  estimatedHours: z.number().min(0).optional()
})

const approvalStageSchema = z.object({
  stageName: z.string().min(2).max(100),
  requiredRoles: z.array(z.string()).min(1),
  isOptional: z.boolean().default(false),
  order: z.number().min(0)
})

const workflowConfigSchema = z.object({
  requiresApproval: z.boolean().default(false),
  approvalStages: z.array(approvalStageSchema).default([]),
  autoProgressRules: z.array(z.object({
    condition: z.string(),
    action: z.string()
  })).optional().default([])
})

const createTemplateSchema = z.object({
  name: z.string().min(2).max(100),
  description: z.string().max(500).optional(),
  departmentId: z.string().regex(/^[0-9a-fA-F]{24}$/).optional(),
  category: z.enum(['design', 'development', 'marketing', 'hr', 'finance', 'operations', 'generic']).default('generic'),
  milestones: z.array(milestoneItemSchema).min(1).max(20),
  workflowConfig: workflowConfigSchema,
  isPublic: z.boolean().default(false),
  tags: z.array(z.string().min(1)).max(10).default([])
})

const templateQuerySchema = z.object({
  departmentId: z.string().regex(/^[0-9a-fA-F]{24}$/).optional(),
  category: z.enum(['design', 'development', 'marketing', 'hr', 'finance', 'operations', 'generic']).optional(),
  search: z.string().optional(),
  tags: z.string().optional(), // Comma-separated tags
  isPublic: z.boolean().optional(),
  limit: z.string().transform(val => parseInt(val) || 20).optional(),
  page: z.string().transform(val => parseInt(val) || 1).optional()
})

// GET /api/milestone-templates - List milestone templates
export async function GET(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'read')

    const searchParams = request.nextUrl.searchParams
    const queryParams = {
      departmentId: searchParams.get('departmentId') || undefined,
      category: searchParams.get('category') || undefined,
      search: searchParams.get('search') || undefined,
      tags: searchParams.get('tags') || undefined,
      isPublic: searchParams.get('isPublic') === 'true' ? true : undefined,
      limit: searchParams.get('limit') || '20',
      page: searchParams.get('page') || '1'
    }

    const validatedParams = templateQuerySchema.parse(queryParams)

    const templates = await executeGenericDbQuery(async () => {
      // Build filter
      const filter: any = {
        isActive: true,
        isDeleted: false
      }

      // Department filter - show department templates + public ones
      if (validatedParams.departmentId) {
        filter.$or = [
          { departmentId: validatedParams.departmentId },
          { isPublic: true }
        ]
      } else if (user.departmentId && validatedParams.isPublic !== true) {
        filter.$or = [
          { departmentId: user.departmentId },
          { isPublic: true }
        ]
      }

      // Category filter
      if (validatedParams.category) {
        filter.category = validatedParams.category
      }

      // Public filter
      if (validatedParams.isPublic === true) {
        filter.isPublic = true
      }

      // Search filter
      if (validatedParams.search) {
        filter.$and = filter.$and || []
        filter.$and.push({
          $or: [
            { name: { $regex: validatedParams.search, $options: 'i' } },
            { description: { $regex: validatedParams.search, $options: 'i' } },
            { tags: { $in: [new RegExp(validatedParams.search, 'i')] } }
          ]
        })
      }

      // Tags filter
      if (validatedParams.tags) {
        const tagList = validatedParams.tags.split(',').map(tag => tag.trim())
        filter.tags = { $in: tagList }
      }

      // Pagination
      const skip = ((validatedParams.page || 1) - 1) * (validatedParams.limit || 20)

      const [templatesRaw, total] = await Promise.all([
        MilestoneTemplate.find(filter)
          .populate('createdBy', 'firstName lastName email')
          .populate('departmentId', 'name')
          .sort({ usageCount: -1, createdAt: -1 })
          .skip(skip)
          .limit(validatedParams.limit || 20),
        MilestoneTemplate.countDocuments(filter)
      ])

      // Add computed fields manually to ensure they're included
      const templates = templatesRaw.map(template => {
        const templateObj = template.toObject()
        return {
          ...templateObj,
          milestoneCount: templateObj.milestones?.length || 0,
          estimatedTotalDuration: templateObj.milestones?.reduce((total: number, milestone: any) => total + (milestone.durationDays || 0), 0) || 0
        }
      })

      return {
        templates,
        pagination: {
          page: validatedParams.page || 1,
          limit: validatedParams.limit || 20,
          total,
          pages: Math.ceil(total / (validatedParams.limit || 20))
        }
      }
    }, `milestone-templates-${JSON.stringify(validatedParams)}`, 300000) // 5 minute cache

    return NextResponse.json({
      success: true,
      data: templates.templates,
      pagination: templates.pagination,
      message: 'Milestone templates retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching milestone templates:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid request parameters',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch milestone templates'
    }, { status: 500 })
  }
}

// POST /api/milestone-templates - Create new milestone template
export async function POST(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'create')

    const body = await request.json()
    const validatedData = createTemplateSchema.parse(body)

    // Validate milestone dependencies
    const milestoneNames = validatedData.milestones.map(m => m.title)
    for (const milestone of validatedData.milestones) {
      if (milestone.dependencies) {
        for (const dep of milestone.dependencies) {
          if (!milestoneNames.includes(dep)) {
            return NextResponse.json({
              success: false,
              error: `Invalid dependency: "${dep}" not found in milestone titles`
            }, { status: 400 })
          }
        }
      }
    }

    const template = await executeGenericDbQuery(async () => {
      const newTemplate = new MilestoneTemplate({
        ...validatedData,
        createdBy: user.id,
        departmentId: validatedData.departmentId || user.departmentId
      })

      await newTemplate.save()
      
      return await MilestoneTemplate.findById(newTemplate._id)
        .populate('createdBy', 'firstName lastName email')
        .populate('departmentId', 'name')
        .lean()
    }, undefined, 0) // No cache for create operations

    // Clear relevant caches
    clearCache('milestone-templates')
    
    return NextResponse.json({
      success: true,
      data: template,
      message: 'Milestone template created successfully'
    }, { status: 201 })

  } catch (error: any) {
    console.error('Error creating milestone template:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid template data',
        details: error.errors
      }, { status: 400 })
    }

    if (error.code === 11000) {
      return NextResponse.json({
        success: false,
        error: 'Template name already exists in this department'
      }, { status: 409 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to create milestone template'
    }, { status: 500 })
  }
}