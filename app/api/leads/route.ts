import { type NextRequest, NextResponse } from "next/server"
import mongoose from "mongoose"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Lead from "@/models/Lead"
import User from "@/models/User"
import { createLeadSchema, leadQuerySchema } from "@/lib/validations/lead"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { addSoftDeleteFilter } from "@/lib/utils/soft-delete"

// Cache TTL for lead queries
const CACHE_TTL = 30000 // 30 seconds for volatile lead data

// GET /api/leads - List leads with pagination, search, and filters
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions) with filtering
    const { session, user, userEmail, isSuperAdmin, applyFilters } = await genericApiRoutesMiddleware(request, 'leads', 'read')

    // Parse and validate query parameters
    const { searchParams } = new URL(request.url)
    const queryParams = {
      page: searchParams.get('page') || '1',
      limit: searchParams.get('limit') || '10',
      search: searchParams.get('search') || '',
      status: searchParams.get('status') || '',
      source: searchParams.get('source') || '',
      priority: searchParams.get('priority') || '',
      createdBy: searchParams.get('createdBy') || undefined,
      clientId: searchParams.get('clientId') || '',
      sortBy: searchParams.get('sortBy') || 'createdAt',
      sortOrder: searchParams.get('sortOrder') || 'desc',
      createdAfter: searchParams.get('createdAfter') || undefined,
      createdBefore: searchParams.get('createdBefore') || undefined,
      minBudget: searchParams.get('minBudget') || undefined,
      maxBudget: searchParams.get('maxBudget') || undefined,
      hasFollowUp: searchParams.get('hasFollowUp') || undefined,
      followUpOverdue: searchParams.get('followUpOverdue') || undefined,
    }

    const validatedParams = leadQuerySchema.parse(queryParams)

    // Build MongoDB filter with soft delete filtering
    let filter: any = {}

    // Apply soft delete filter - exclude deleted records unless super admin
    filter = addSoftDeleteFilter(filter, isSuperAdmin)

    // Apply user filters - sales agents can only see their own leads unless super admin
    if (!isSuperAdmin) {
      // Check if user is from sales department
      const salesUser = await executeGenericDbQuery(async () => {
        return await User.findById(user._id).populate('department', 'name')
      })

      const deptName = (salesUser?.department as any)?.name?.toLowerCase()
      if (deptName !== 'sales') {
        return NextResponse.json({
          success: false,
          error: 'Access denied. Only sales department members can access leads.'
        }, { status: 403 })
      }

      // Sales agents can only see their own leads
      filter.createdBy = user._id
    }

    // Text search across multiple fields
    if (validatedParams.search) {
      filter.$or = [
        { name: { $regex: validatedParams.search, $options: 'i' } },
        { email: { $regex: validatedParams.search, $options: 'i' } },
        { company: { $regex: validatedParams.search, $options: 'i' } },
        { projectName: { $regex: validatedParams.search, $options: 'i' } }
      ]
    }

    // Status filter
    if (validatedParams.status) {
      filter.status = validatedParams.status
    }

    // Source filter
    if (validatedParams.source) {
      filter.source = validatedParams.source
    }

    // Priority filter
    if (validatedParams.priority) {
      filter.priority = validatedParams.priority
    }

    // Created by filter (for admin/manager views)
    if (validatedParams.createdBy && isSuperAdmin) {
      filter.createdBy = validatedParams.createdBy
    }

    // Client ID filter
    if (validatedParams.clientId) {
      filter.clientId = validatedParams.clientId
    }

    // Date range filters
    if (validatedParams.createdAfter || validatedParams.createdBefore) {
      filter.createdAt = {}
      if (validatedParams.createdAfter) {
        filter.createdAt.$gte = validatedParams.createdAfter
      }
      if (validatedParams.createdBefore) {
        filter.createdAt.$lte = validatedParams.createdBefore
      }
    }

    // Budget range filters
    if (validatedParams.minBudget || validatedParams.maxBudget) {
      filter.projectBudget = {}
      if (validatedParams.minBudget) {
        filter.projectBudget.$gte = validatedParams.minBudget
      }
      if (validatedParams.maxBudget) {
        filter.projectBudget.$lte = validatedParams.maxBudget
      }
    }

    // Follow-up filters
    if (validatedParams.hasFollowUp) {
      filter.nextFollowUpDate = { $exists: true, $ne: null }
    }

    if (validatedParams.followUpOverdue) {
      filter.nextFollowUpDate = { $lt: new Date() }
    }

    // Build sort object
    const sort: any = {}
    sort[validatedParams.sortBy] = validatedParams.sortOrder === 'asc' ? 1 : -1

    // Calculate pagination
    const skip = (validatedParams.page - 1) * validatedParams.limit

    // Execute parallel queries with caching
    const cacheKey = `leads-${JSON.stringify({ filter, sort, skip, limit: validatedParams.limit })}`

    const [leads, total, stats] = await Promise.all([
      executeGenericDbQuery(async () => {
        return await Lead.find(filter)
          .sort(sort)
          .skip(skip)
          .limit(validatedParams.limit)
          .populate('createdBy', 'name email')
          .populate('clientId', 'name email')
          .lean()
      }, cacheKey, CACHE_TTL),

      executeGenericDbQuery(async () => {
        return await Lead.countDocuments(filter)
      }, `leads-count-${JSON.stringify(filter)}`, CACHE_TTL),

      executeGenericDbQuery(async () => {
        return await Lead.getLeadStats(filter)
      }, `leads-stats-${JSON.stringify(filter)}`, 60000) // 1-minute cache for stats
    ])

    // Calculate pagination info
    const pages = Math.ceil(total / validatedParams.limit)

    return NextResponse.json({
      success: true,
      data: {
        leads,
        pagination: {
          page: validatedParams.page,
          limit: validatedParams.limit,
          total,
          pages,
        },
        stats,
        filters: validatedParams,
      },
      message: 'Leads retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching leads:', error)
    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }
    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid query parameters',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch leads'
    }, { status: 500 })
  }
}

// POST /api/leads - Create new lead
export async function POST(request: NextRequest) {
  try {
    // Security & Authentication - only sales department can create leads (unless super admin)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'leads', 'create')

    // Super admin can create leads regardless of department
    if (!isSuperAdmin) {
      // Verify user is from sales department
      const salesUser = await executeGenericDbQuery(async () => {
        return await User.findById(user._id).populate('department', 'name')
      })

      const deptName = (salesUser?.department as any)?.name?.toLowerCase()
      if (deptName !== 'sales') {
        return NextResponse.json({
          success: false,
          error: 'Access denied. Only sales department members can create leads.'
        }, { status: 403 })
      }
    }

    // Parse & validate request body
    const body = await request.json()
    const validatedData = createLeadSchema.parse(body)

    // Create lead with automatic connection management
    const lead = await executeGenericDbQuery(async () => {
      // Check for duplicate email in Lead collection
      const existingLead = await Lead.findOne({
        email: { $regex: new RegExp(`^${validatedData.email}$`, 'i') }
      })

      if (existingLead) {
        throw new Error('A client or employee with this email already exists')
      }

      // Also prevent creating a lead using an email that belongs to a registered User
      const existingUser = await User.findOne({
        email: { $regex: new RegExp(`^${validatedData.email}$`, 'i') }
      })

      if (existingUser) {
        throw new Error('A user with this email already exists')
      }

      // Create new lead
      const newLead = new Lead({
        ...validatedData,
        createdBy: new mongoose.Types.ObjectId(user._id),
        source: validatedData.source || 'website',
        priority: validatedData.priority || 'medium',
        status: validatedData.status || 'active'
      })

      return await newLead.save()
    })

    // Clear relevant cache patterns after creation
    clearCache('leads')

    // Populate the created lead for response
    const populatedLead = await executeGenericDbQuery(async () => {
      return await Lead.findById(lead._id)
        .populate('createdBy', 'name email')
        .lean()
    })

    return NextResponse.json({
      success: true,
      data: populatedLead,
      message: 'Lead created successfully'
    }, { status: 201 })

  } catch (error: any) {
    console.error('Error creating lead:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid lead data',
        details: error.errors
      }, { status: 400 })
    }

    // Handle Mongoose validation errors
    if (error.name === 'ValidationError') {
      const validationErrors = Object.values(error.errors).map((err: any) => err.message)
      return NextResponse.json({
        success: false,
        error: 'Lead validation failed',
        details: validationErrors
      }, { status: 400 })
    }

    if (error.message.includes('already exists')) {
      return NextResponse.json({
        success: false,
        error: error.message
      }, { status: 409 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to create lead'
    }, { status: 500 })
  }
}