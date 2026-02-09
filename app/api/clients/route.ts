import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import User from "@/models/User"
import Lead from "@/models/Lead"
import Role from "@/models/Role"
import { clientQuerySchema } from "@/lib/validations/client"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { registerModels } from '@/lib/models'
import { addSoftDeleteFilter } from "@/lib/utils/soft-delete"

// Cache TTL for client queries
const CACHE_TTL = 60000 // 1 minute for client data

// GET /api/clients - List clients with pagination, search, and filters
export async function GET(request: NextRequest) {
  try {
    // Ensure models are registered
    await registerModels()

    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin, applyFilters } = await genericApiRoutesMiddleware(request, 'clients', 'read')

    // Parse and validate query parameters
    const { searchParams } = new URL(request.url)
    const queryParams = {
      page: searchParams.get('page') || '1',
      limit: searchParams.get('limit') || '10',
      search: searchParams.get('search') || '',
      status: searchParams.get('status') || '',
      clientStatus: searchParams.get('clientStatus') || '',
      company: searchParams.get('company') || '',
      hasLead: searchParams.get('hasLead'),
      sortBy: searchParams.get('sortBy') || 'createdAt',
      sortOrder: searchParams.get('sortOrder') || 'desc',
      qualifiedAfter: searchParams.get('qualifiedAfter'),
      qualifiedBefore: searchParams.get('qualifiedBefore'),
    }

    const validatedParams = clientQuerySchema.parse(queryParams)
    console.log("clients34", validatedParams);
    // Build MongoDB filter - always filter for clients only with soft delete filter
    let filter: any = { isClient: true }

    // Apply soft delete filter - exclude deleted records unless super admin
    filter = addSoftDeleteFilter(filter, isSuperAdmin)
    console.log("clients46", filter);

    // Text search across multiple fields
    if (validatedParams.search) {
      filter.$or = [
        { name: { $regex: validatedParams.search, $options: 'i' } },
        { email: { $regex: validatedParams.search, $options: 'i' } },
        { company: { $regex: validatedParams.search, $options: 'i' } }
      ]
    }

    // Status filters - if user is not super admin, ensure we don't override soft delete filter
    if (validatedParams.status) {
      if (isSuperAdmin) {
        filter.status = validatedParams.status
      } else {
        // For non-super admins, combine status filter with soft delete exclusion
        filter.status = { $and: [{ $ne: 'deleted' }, { $eq: validatedParams.status }] }
      }
    }

    if (validatedParams.clientStatus) {
      filter.clientStatus = validatedParams.clientStatus
    }

    // Company filter
    if (validatedParams.company) {
      filter.company = { $regex: validatedParams.company, $options: 'i' }
    }

    // Lead association filter
    if (validatedParams.hasLead !== undefined) {
      if (validatedParams.hasLead) {
        filter.leadId = { $exists: true, $ne: null }
      } else {
        filter.leadId = { $exists: false }
      }
    }

    // Date range filters for qualification
    if (validatedParams.qualifiedAfter || validatedParams.qualifiedBefore) {
      filter.createdAt = {}
      if (validatedParams.qualifiedAfter) {
        filter.createdAt.$gte = validatedParams.qualifiedAfter
      }
      if (validatedParams.qualifiedBefore) {
        filter.createdAt.$lte = validatedParams.qualifiedBefore
      }
    }

    // Apply department-based filters if not super admin
    if (!isSuperAdmin && typeof applyFilters === 'function') {
      // Support and sales can see all clients, others see department-specific
      const userWithDept = await executeGenericDbQuery(async () => {
        return await User.findById(user._id).populate('department', 'name')
      })

      const deptName = (userWithDept?.department as any)?.name?.toLowerCase()
      if (deptName && !['sales', 'support'].includes(deptName)) {
        // Other departments might have restricted access based on your business rules
        filter.department = user.department
      }
    }

    // Build sort object
    const sort: any = {}
    sort[validatedParams.sortBy] = validatedParams.sortOrder === 'asc' ? 1 : -1

    // Calculate pagination
    const skip = (validatedParams.page - 1) * validatedParams.limit

    // Execute parallel queries with caching
    const cacheKey = `clients-${JSON.stringify({ filter, sort, skip, limit: validatedParams.limit })}`
    console.log("clients119", filter);
    const [clients, total, stats] = await Promise.all([
      executeGenericDbQuery(async () => {
        // return await User.find(filter)
        return await User.find({ isClient: true })
          .sort(sort)
          .skip(skip)
          .limit(validatedParams.limit)
          .populate('role', 'name')
          .populate('department', 'name')
          .populate('projects','name status startDate endDate')
          .populate('leadId', 'name projectName status createdAt')
          .select('-password -resetPasswordToken -resetPasswordExpire')
          .lean()
      }, cacheKey, CACHE_TTL),

      executeGenericDbQuery(async () => {
        return await User.countDocuments(filter)
      }, `clients-count-${JSON.stringify(filter)}`, CACHE_TTL),

      executeGenericDbQuery(async () => {
        return await User.getClientStats(filter)
      }, `clients-stats-${JSON.stringify(filter)}`, 300000) // 5-minute cache for stats
    ]);

    console.log("clients127", clients);

    // Calculate pagination info
    const pages = Math.ceil(total / validatedParams.limit)
    console.log("clients129", clients);
    return NextResponse.json({
      success: true,
      data: {
        clients,
        pagination: {
          page: validatedParams.page,
          limit: validatedParams.limit,
          total,
          pages,
        },
        stats,
        filters: validatedParams,
      },
      message: 'Clients retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching clients:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid query parameters',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch clients'
    }, { status: 500 })
  }
}

// POST /api/clients - Create client (typically done automatically from lead qualification)
export async function POST(request: NextRequest) {
  try {
    // Ensure models are registered
    await registerModels()

    // Security & Authentication - only support/sales can create clients directly (unless super admin)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'clients', 'create')

    // Super admin can create clients regardless of department
    if (!isSuperAdmin) {
      // Verify user has permission to create clients
      const currentUser = await executeGenericDbQuery(async () => {
        return await User.findById(user._id).populate('department', 'name')
      })

      const deptName = (currentUser?.department as any)?.name?.toLowerCase()
      if (!['sales', 'support'].includes(deptName || '')) {
        return NextResponse.json({
          success: false,
          error: 'Access denied. Only sales and support departments can create clients directly.'
        }, { status: 403 })
      }
    }

    // Parse request body
    const body = await request.json()

    // Check if creating from lead qualification
    if (body.leadId) {
      return await createClientFromLead(body, user)
    }

    // Direct client creation
    return await createClientDirectly(body, user)

  } catch (error: any) {
    console.error('Error creating client:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid client data',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to create client'
    }, { status: 500 })
  }
}

// Helper function to create client from lead qualification
async function createClientFromLead(data: any, user: any) {
  try {
    const client = await executeGenericDbQuery(async () => {
      // Get the lead
      const lead = await Lead.findById(data.leadId)
      if (!lead) {
        throw new Error('Lead not found')
      }

      // Check if lead is qualified
      if (lead.status !== 'qualified') {
        throw new Error('Lead must be qualified to create client')
      }

      // Check if client already exists for this lead
      const existingClient = await User.findOne({ leadId: data.leadId, isClient: true })
      if (existingClient) {
        throw new Error('Client already exists for this lead')
      }

      // Find client role
      const clientRole = await User.findOne({ 'role.name': /^client$/i }).populate('role')
      if (!clientRole?.role) {
        throw new Error('Client role not found. Please create a client role first.')
      }

      // Create client from lead data
      return await User.createClientFromLead(lead, user._id)
    })

    // Clear cache
    clearCache('clients')
    clearCache('leads')

    // Get populated client data
    const populatedClient = await executeGenericDbQuery(async () => {
      return await User.findById(client._id)
        .populate('role', 'name')
        .populate('department', 'name')
        .populate('projects')
        .populate('leadId', 'name projectName status createdAt')
        .select('-password -resetPasswordToken -resetPasswordExpire')
        .lean()
    })

    return NextResponse.json({
      success: true,
      data: populatedClient,
      message: 'Client created successfully from lead qualification'
    }, { status: 201 })

  } catch (error: any) {
    throw error // Re-throw to be handled by main POST handler
  }
}

// Helper function for direct client creation
async function createClientDirectly(data: any, user: any) {
  const { createClientSchema } = await import('@/lib/validations/client')

  try {
    // Validate the input data
    const validatedData = createClientSchema.parse(data)

    // Prevent creating clients with deleted status
    if (validatedData.status === 'deleted') {
      throw new Error("Cannot create clients with deleted status")
    }

    const client = await executeGenericDbQuery(async () => {
      // Check if user with same email already exists
      const existingUser = await User.findOne({ email: validatedData.email })
      if (existingUser) {
        throw new Error('A user with this email already exists')
      }

      // Find client role - assume there's a role named 'client'
      const clientRole = await Role.findOne({ name: /^client$/i }, { _id: 1 })
      if (!clientRole) {
        throw new Error('Client role not found. Please create a client role first.')
      }

      // Find a default department for clients or use the creator's department
      const creatorUser = await User.findById(user._id).populate('department')
      const defaultDepartment = creatorUser?.department?._id

      // Create client user
      const clientData = {
        ...validatedData,
        isClient: true,
        role: clientRole._id,
        department: validatedData.departmentId || validatedData.department || defaultDepartment,
        emailVerified: false,
        status: validatedData.status || 'qualified',
        createdBy: user._id,
        // Generate a temporary password if none provided
        password: validatedData.password || Math.random().toString(36).slice(-8) + 'Temp123!',
      }

      const newClient = new User(clientData)
      return await newClient.save()
    })

    // Clear cache
    clearCache('clients')

    // Get populated client data
    const populatedClient = await executeGenericDbQuery(async () => {
      return await User.findById(client._id)
        .populate('role', 'name')
        .populate('department', 'name')
        .populate('projects')
        .select('-password -resetPasswordToken -resetPasswordExpire')
        .lean()
    })

    return NextResponse.json({
      success: true,
      data: populatedClient,
      message: 'Client created successfully'
    }, { status: 201 })

  } catch (error: any) {
    throw error // Re-throw to be handled by main POST handler
  }
}