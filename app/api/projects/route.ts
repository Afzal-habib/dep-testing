import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Project from "@/models/Project"
import User from "@/models/User"
import { createProjectFormSchema, projectQuerySchema } from "@/lib/validations/project"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { addSoftDeleteFilter } from "@/lib/utils/soft-delete"
import mongoose from 'mongoose'

// GET /api/projects - List with pagination and filtering
export async function GET(request: NextRequest) {
  try {
    // Security & Authentication - Support team can read projects
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'projects', 'read')

    // Parse & validate query parameters
    const searchParams = request.nextUrl.searchParams
    const queryParams = {
      page: searchParams.get('page') || '1',
      limit: searchParams.get('limit') || '10',
      search: searchParams.get('search') || '',
      status: searchParams.get('status') || '',
      priority: searchParams.get('priority') || '',
      clientId: searchParams.get('clientId') || undefined,
      departmentId: searchParams.get('departmentId') || undefined,
      sortBy: searchParams.get('sortBy') || 'createdAt',
      sortOrder: searchParams.get('sortOrder') || 'desc',
    }

    const validatedParams = projectQuerySchema.parse(queryParams)

    // Build MongoDB filter
    const filter: any = {}

    if (validatedParams.search) {
      filter.$or = [
        { name: { $regex: validatedParams.search, $options: 'i' } },
        { description: { $regex: validatedParams.search, $options: 'i' } },
        { requirements: { $regex: validatedParams.search, $options: 'i' } }
      ]
    }

    if (validatedParams.status) {
      filter.status = validatedParams.status
    }

    if (validatedParams.priority) {
      filter.priority = validatedParams.priority
    }

    if (validatedParams.clientId) {
      filter.clientId = new mongoose.Types.ObjectId(validatedParams.clientId)
    }

    if (validatedParams.departmentId) {
      filter.departmentIds = { $in: [new mongoose.Types.ObjectId(validatedParams.departmentId)] }
    }

    // Department-based filtering for non-support users
    if (user.departmentId && !['support', 'admin'].includes(user.department?.name?.toLowerCase())) {
      filter.departmentIds = { $in: [user.departmentId] }
    }

    // Apply soft delete filter - only super admins can see deleted projects
    const finalFilter = addSoftDeleteFilter(filter, isSuperAdmin, true)

    // Build sort
    const sort: any = {}
    sort[validatedParams.sortBy] = validatedParams.sortOrder === 'asc' ? 1 : -1

    // Execute parallel queries with automatic connection management and caching
    const [projectsRaw, total, stats] = await Promise.all([
      executeGenericDbQuery(async () => {
        return await Project.find(finalFilter)
          .populate('client', 'name email status')
          .populate('departments', 'name status')
          .populate('creator', 'name email')
          .populate({
            path: 'tasks',
            populate: [
              { path: 'assignee', select: 'name email' },
              { path: 'department', select: 'name' },
              { path: 'creator', select: 'name email' }
            ]
          })
          .populate('taskCount')
          .sort(sort)
          .skip((validatedParams.page - 1) * validatedParams.limit)
          .limit(validatedParams.limit)
          .lean()
      }, `projects-list-${JSON.stringify({ filter, sort, page: validatedParams.page, limit: validatedParams.limit })}`, 60000), // 1-minute cache

      executeGenericDbQuery(async () => {
        return await Project.countDocuments(finalFilter)
      }, `projects-count-${JSON.stringify(finalFilter)}`, 60000), // 1-minute cache

      executeGenericDbQuery(async () => {
        const pipeline = [
          { $match: finalFilter },
          {
            $group: {
              _id: null,
              totalProjects: { $sum: 1 },
              pendingProjects: { $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] } },
              activeProjects: { $sum: { $cond: [{ $eq: ["$status", "active"] }, 1, 0] } },
              completedProjects: { $sum: { $cond: [{ $eq: ["$status", "completed"] }, 1, 0] } },
              approvedProjects: { $sum: { $cond: [{ $eq: ["$status", "approved"] }, 1, 0] } },
              inactiveProjects: { $sum: { $cond: [{ $eq: ["$status", "inactive"] }, 1, 0] } },

              lowPriorityProjects: { $sum: { $cond: [{ $eq: ["$priority", "low"] }, 1, 0] } },
              mediumPriorityProjects: { $sum: { $cond: [{ $eq: ["$priority", "medium"] }, 1, 0] } },
              highPriorityProjects: { $sum: { $cond: [{ $eq: ["$priority", "high"] }, 1, 0] } },
              urgentPriorityProjects: { $sum: { $cond: [{ $eq: ["$priority", "urgent"] }, 1, 0] } },

              totalBudget: { $sum: "$budget" },
              averageBudget: { $avg: "$budget" }
            }
          }
        ]

        const result = await Project.aggregate(pipeline)
        return result[0] || {
          totalProjects: 0,
          pendingProjects: 0,
          activeProjects: 0,
          completedProjects: 0,
          approvedProjects: 0,
          inactiveProjects: 0,
          lowPriorityProjects: 0,
          mediumPriorityProjects: 0,
          highPriorityProjects: 0,
          urgentPriorityProjects: 0,
          totalBudget: 0,
          averageBudget: 0
        }
      }, `projects-stats-${JSON.stringify(filter)}`, 300000) // 5-minute cache for stats
    ])

    // Transform projects to group tasks by departments
    const projects = projectsRaw.map((project: any) => {
      if (!project.tasks || !Array.isArray(project.tasks)) {
        return {
          ...project,
          departmentTasks: {}
        }
      }

      // Group tasks by department
      const departmentTasks: { [key: string]: any } = {}
      
      // Initialize department structure from project departments OR from tasks if departments not assigned
      if (project.departments && Array.isArray(project.departments) && project.departments.length > 0) {
        // Use project departments if available
        project.departments.forEach((dept: any) => {
          departmentTasks[dept._id.toString()] = {
            departmentId: dept._id,
            departmentName: dept.name,
            tasks: [],
            taskCount: 0,
            subTaskCount: 0
          }
        })
      } else if (project.tasks && Array.isArray(project.tasks) && project.tasks.length > 0) {
        // If no departments assigned, infer from tasks
        const uniqueDepartments = new Map()
        project.tasks.forEach((task: any) => {
          if (task.department && task.departmentId) {
            uniqueDepartments.set(task.departmentId.toString(), {
              departmentId: task.departmentId,
              departmentName: task.department.name,
              tasks: [],
              taskCount: 0,
              subTaskCount: 0
            })
          }
        })
        uniqueDepartments.forEach((value, key) => {
          departmentTasks[key] = value
        })
      }

      // Process tasks - first add main tasks
      const mainTasks = project.tasks.filter((task: any) => task.type === 'task')
      const subTasks = project.tasks.filter((task: any) => task.type === 'sub-task')

      mainTasks.forEach((task: any) => {
        const deptId = task.departmentId?.toString()
        if (deptId) {
          // Ensure department exists in departmentTasks
          if (!departmentTasks[deptId] && task.department) {
            departmentTasks[deptId] = {
              departmentId: task.departmentId,
              departmentName: task.department.name,
              tasks: [],
              taskCount: 0,
              subTaskCount: 0
            }
          }

          if (departmentTasks[deptId]) {
            // Find sub-tasks for this main task
            const taskSubTasks = subTasks.filter((subTask: any) => 
              subTask.parentTaskId?.toString() === task._id.toString()
            )

            departmentTasks[deptId].tasks.push({
              ...task,
              subTasks: taskSubTasks
            })
            departmentTasks[deptId].taskCount++
            departmentTasks[deptId].subTaskCount += taskSubTasks.length
          }
        }
      })

      // Convert departmentTasks object to array for easier frontend consumption
      const departmentTasksArray = Object.values(departmentTasks)

      return {
        ...project,
        departmentTasks: departmentTasksArray,
        // Remove departments and tasks arrays from response (keep only departmentIds and departmentTasks)
        departments: undefined,
        tasks: undefined
      }
    })

    console.log('Projects fetched and transformed:', projects)

    return NextResponse.json({
      success: true,
      data: {
        projects,
        pagination: {
          page: validatedParams.page,
          limit: validatedParams.limit,
          total,
          pages: Math.ceil(total / validatedParams.limit)
        },
        stats
      },
      message: 'Projects retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching projects:', error)

    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch projects'
    }, { status: 500 })
  }
}

// POST /api/projects - Create new project
export async function POST(request: NextRequest) {
  try {
    // Security & Authentication - Support team can create projects
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'projects', 'create')

    // Parse & validate request body
    const body = await request.json()

    // First validate with form schema (which accepts strings)
    const formData = createProjectFormSchema.parse(body)

    // Then convert to proper API format
    const validatedData = {
      ...formData,
      startDate: formData.startDate ? new Date(formData.startDate) : undefined,
      endDate: formData.endDate ? new Date(formData.endDate) : undefined,
      budget: formData.budget ? formData.budget : undefined,
      createdBy: user.id,
    }

    // Create project with automatic connection management
    const project = await executeGenericDbQuery(async () => {
      // Verify client exists and is qualified
      const client = await User.findOne({
        _id: validatedData.clientId,
        isClient: true,
        // status: 'qualified'
      })

      // if (!client) {
      //   throw new Error('Client not found or not qualified')
      // }

      // Create the project
      const newProject = new Project({
        ...validatedData,
        createdBy: user.id,
        status: 'pending' // All projects start as pending
      })

      return await newProject.save()
    })

    // Clear relevant cache patterns after creation
    clearCache('projects')

    return NextResponse.json({
      success: true,
      data: project,
      message: 'Project created successfully'
    }, { status: 201 })

  } catch (error: any) {
    console.error('Error creating project:', error)

    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Validation failed',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to create project'
    }, { status: 500 })
  }
}