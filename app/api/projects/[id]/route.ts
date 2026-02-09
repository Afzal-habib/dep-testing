import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Project from "@/models/Project"
import Department from "@/models/Department"
import { updateProjectSchema, updateProjectFormSchema, projectIdSchema, categorizeDepartmentsSchema } from "@/lib/validations/project"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { performSoftDelete, addSoftDeleteFilter } from "@/lib/utils/soft-delete"
import mongoose from 'mongoose'

interface RouteParams {
  params: Promise<{ id: string }>
}

// Helper function to transform project tasks by department
function transformProjectTasksByDepartment(project: any) {
  if (!project.tasks || !Array.isArray(project.tasks)) {
    project.departmentTasks = []
    return project
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

  project.departmentTasks = departmentTasksArray
  
  // Don't delete departments and tasks here - let caller handle it
  
  return project
}

// Helper function to organize team members by departments


// GET /api/projects/[id] - Get project by ID
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'projects', 'read')
    
    const resolvedParams = await params
    const validatedParams = projectIdSchema.parse({ id: resolvedParams.id })

    // Clear cache for this project to ensure fresh data
    clearCache(`project-${validatedParams.id}`)

    // Fetch project WITHOUT caching to debug
    const project: any = await executeGenericDbQuery(async () => {
      // Department-based filtering for non-support users
      const filter: any = { 
        _id: validatedParams.id,
        status: { $ne: 'inactive' }
      }

      // If user is not in support/admin, filter by their department
      if (user.departmentId && !['support', 'admin'].includes(user.department?.name?.toLowerCase())) {
        filter.departmentIds = user.departmentId
      }

      // Apply soft delete filtering
      addSoftDeleteFilter(filter, isSuperAdmin)

      const projectData = await Project.findOne(filter)
        .populate('client', 'name email phone status address')
        .populate('departments', 'name status description')
        .populate('creator', 'name email')
        .populate('approver', 'name email')
        .populate({
          path: 'tasks',
          populate: [
            { path: 'assignee', select: 'name email' },
            { path: 'department', select: 'name' },
            { path: 'creator', select: 'name email' }
          ]
        })
        .populate('taskCount')

      return projectData?.toObject ? projectData.toObject() : projectData
    }) // Remove caching temporarily

    if (!project) {
      return NextResponse.json({
        success: false,
        error: 'Project not found or access denied'
      }, { status: 404 })
    }

    // Debug logging
    console.log('🔍 Project data before transformation:', {
      projectId: project._id,
      hasTasks: !!project.tasks,
      tasksLength: project.tasks?.length || 0,
      hasDepartments: !!project.departments,
      departmentsLength: project.departments?.length || 0,
      taskSample: project.tasks?.slice(0, 2) || []
    })

    // Transform project to group tasks by departments (using the same logic as list endpoint)
    if (!project.tasks || !Array.isArray(project.tasks)) {
      project.departmentTasks = []
      console.log('📝 No tasks found, setting empty array')
    } else {
      console.log('📝 Processing tasks:', project.tasks.length)
      
      // Group tasks by department
      const departmentTasks: { [key: string]: any } = {}
      
      // Initialize department structure from project departments OR from tasks if departments not assigned
      if (project.departments && Array.isArray(project.departments) && project.departments.length > 0) {
        console.log('📝 Using project departments:', project.departments.length)
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
        console.log('📝 Inferring departments from tasks')
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
        console.log('📝 Inferred departments:', Object.keys(departmentTasks))
      }

      // Process tasks - first add main tasks
      const mainTasks = project.tasks.filter((task: any) => task.type === 'task')
      const subTasks = project.tasks.filter((task: any) => task.type === 'sub-task')
      
      console.log('📝 Main tasks:', mainTasks.length, 'Sub tasks:', subTasks.length)

      mainTasks.forEach((task: any) => {
        const deptId = task.departmentId?.toString()
        console.log('📝 Processing task:', task.title, 'Department ID:', deptId)
        
        if (deptId) {
          // Ensure department exists in departmentTasks
          if (!departmentTasks[deptId] && task.department) {
            console.log('📝 Creating department entry for:', task.department.name)
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
            
            console.log('📝 Added task to department:', task.department?.name, 'New count:', departmentTasks[deptId].taskCount)
          }
        }
      })

      // Convert departmentTasks object to array for easier frontend consumption
      const departmentTasksArray = Object.values(departmentTasks)
      
      console.log('📝 Final departmentTasks array:', departmentTasksArray.length, departmentTasksArray)

      project.departmentTasks = departmentTasksArray
      
      // Remove departments and tasks arrays from response (keep only departmentIds and departmentTasks)
      delete project.departments
      delete project.tasks
    }
    
    // Calculate overall project progress based on completed tasks
    const totalTasks = project.departmentTasks?.reduce((total: number, dept: any) => total + dept.taskCount + dept.subTaskCount, 0) || 0
    const completedTasks = project.departmentTasks?.reduce((total: number, dept: any) => {
      const deptCompleted = dept.tasks?.reduce((deptTotal: number, task: any) => {
        // Count main task as completed if status is completed
        const mainCompleted = task.status === 'completed' ? 1 : 0
        // Count sub-tasks completed
        const subCompleted = task.subTasks?.filter((sub: any) => sub.status === 'completed').length || 0
        return deptTotal + mainCompleted + subCompleted
      }, 0) || 0
      return total + deptCompleted
    }, 0) || 0
    
    project.progress = {
      overall: totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0,
      totalTasks,
      completedTasks
    }

    // Calculate quality metrics
    const now = new Date()
    const endDate = project.endDate ? new Date(project.endDate) : null
    const isOnTime = endDate ? endDate >= now : true // If no end date, consider on time
    const budgetBreakdown = project.budgetBreakdown || {}
    const totalAllocated = Object.values(budgetBreakdown).reduce((sum: number, val: any) => sum + (val || 0), 0)
    const isWithinBudget = project.budget ? totalAllocated <= project.budget : true

    project.qualityMetrics = {
      ...project.qualityMetrics,
      onTimeDelivery: isOnTime,
      withinBudget: isWithinBudget
    }

    // Calculate budget health
    const budgetUtilization = project.budget && project.budget > 0 ? Math.round((totalAllocated / project.budget) * 100) : 0
    project.budgetHealth = budgetUtilization <= 100 ? 'good' : budgetUtilization <= 110 ? 'warning' : 'critical'

    // Calculate timeline health
    let timelineHealth = 'good'
    if (endDate) {
      const daysRemaining = Math.ceil((endDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
      const progress = project.progress.overall
      // If progress is low but time is running out, it's critical
      if (daysRemaining < 7 && progress < 50) timelineHealth = 'critical'
      else if (daysRemaining < 14 && progress < 75) timelineHealth = 'warning'
      else if (daysRemaining < 0) timelineHealth = 'critical' // Overdue
    }
    project.timelineHealth = timelineHealth
    

    return NextResponse.json({
      success: true,
      data: project,
      message: 'Project retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching project:', error)

    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid project ID',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch project'
    }, { status: 500 })
  }
}

// PUT /api/projects/[id] - Update project
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'projects', 'update')

    // Resolve params (Next.js passes params as a Promise in RouteParams)
    const resolvedParams = await params
    const validatedParams = projectIdSchema.parse({ id: resolvedParams.id })
    const body = await request.json()
    
    // Handle special operations
    if (body.operation === 'categorize') {
      return handleCategorizeDepartments(validatedParams.id, body, user)
    }
    
    if (body.operation === 'approve') {
      return handleApproveProject(validatedParams.id, user)
    }
    
    // Regular update operation
    // First validate with form schema (which accepts strings)
    console.log('📥 Received request body:', JSON.stringify(body, null, 2));
    
    let formData;
    try {
      formData = updateProjectFormSchema.parse(body);
    } catch (error: any) {
      console.error('❌ Validation error details:', error);
      console.error('❌ Validation error message:', error.message);
      console.error('❌ Validation error issues:', error.errors || error.issues);
      return NextResponse.json({ 
        error: 'Validation failed', 
        message: error.errors?.[0]?.message || error.issues?.[0]?.message || 'Invalid data format',
        details: error.errors || error.issues || [],
        receivedData: body
      }, { status: 400 });
    }
    
    // Convert form data to proper API format
    const validatedData = {
      ...formData,
      budget: formData.budget ? formData.budget : 0,
      startDate: formData.startDate ? new Date(formData.startDate as string) : undefined,
      endDate: formData.endDate ? new Date(formData.endDate as string) : undefined,

        
      // Transform nested objects with string-to-number conversion
      budgetBreakdown: formData.budgetBreakdown ? {
        development: formData.budgetBreakdown.development || undefined,
        design: formData.budgetBreakdown.design || undefined,
        testing: formData.budgetBreakdown.testing || undefined,
        deployment: formData.budgetBreakdown.deployment || undefined,
        maintenance: formData.budgetBreakdown.maintenance || undefined,
        contingency: formData.budgetBreakdown.contingency || undefined,
      } : undefined,
      
      resources: formData.resources ? {
        ...formData.resources,
        estimatedHours: formData.resources.estimatedHours ? formData.resources.estimatedHours : undefined,
        actualHours: formData.resources.actualHours ? formData.resources.actualHours : undefined,
      } : undefined,

      
    };

    // Update project with automatic connection management
    const updatedProject = await executeGenericDbQuery(async () => {
      // Find existing project with proper filtering
      const filter: any = { 
        _id: validatedParams.id,
        status: { $ne: 'inactive' }
      }

      // If user is not in support/admin, filter by their department
      if (user.departmentId && !['support', 'admin'].includes(user.department?.name?.toLowerCase())) {
        filter.departmentIds = user.departmentId
      }

      // Apply soft delete filtering
      addSoftDeleteFilter(filter, isSuperAdmin)

      const existingProject = await Project.findOne(filter)
      
      if (!existingProject) {
        throw new Error('Project not found or access denied')
      }

      // Status change validations
      if (validatedData.status && validatedData.status !== existingProject.status) {
        // Only support can change status to approved
        // if (validatedData.status === 'approved' && !['support', 'admin'].includes(user.department?.name?.toLowerCase())) {
        //   throw new Error('Only support team can approve projects')
        // }  

        // Set approval fields
        if (validatedData.status === 'approved') {
          (validatedData as any).approvedBy = user.id
          ;(validatedData as any).approvedAt = new Date()
        }
      }

      // Update the project
      const updated = await Project.findByIdAndUpdate(
        validatedParams.id,
        { 
          $set: validatedData,
          updatedAt: new Date()
        },
        { 
          new: true,
          runValidators: true
        }
      )
      .populate('client', 'name email phone status')
      .populate('departments', 'name status description')
      .populate('creator', 'name email')
      .populate('approver', 'name email')
      .populate({
        path: 'tasks',
        populate: [
          { path: 'assignee', select: 'name email' },
          { path: 'department', select: 'name' },
          { path: 'creator', select: 'name email' },
          { path: 'parentTask', select: 'title' }
        ]
      })
      .populate('taskCount')

      return updated?.toObject ? updated.toObject() : updated
    })

    if (!updatedProject) {
      return NextResponse.json({
        success: false,
        error: 'Project not found'
      }, { status: 404 })
    }

    // Transform project to group tasks by departments
    transformProjectTasksByDepartment(updatedProject)
    
    // Remove departments and tasks arrays from response (keep only departmentIds and departmentTasks)
    delete updatedProject.departments
    delete updatedProject.tasks

    // Clear relevant cache patterns after update
    clearCache('projects')
    clearCache(`project-${validatedParams.id}`)

    return NextResponse.json({
      success: true,
      data: updatedProject,
      message: 'Project updated successfully'
    })

  } catch (error: any) {
    console.error('Error updating project:', error)

    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Validation failed',
        message: error.errors?.[0]?.message || 'Invalid data format',
        details: error.errors
      }, { status: 400 })
    }

    if (error.name === 'ValidationError') {
      return NextResponse.json({
        success: false,
        error: 'Database validation failed',
        message: error.message,
        details: error.errors
      }, { status: 400 })
    }

    if (error.message.includes('not found') || error.message.includes('access denied')) {
      return NextResponse.json({
        success: false,
        error: error.message
      }, { status: 404 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to update project'
    }, { status: 500 })
  }
}

// PATCH /api/projects/[id] - Update project (alias for PUT)
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  return PUT(request, { params });
}

// Helper function to handle department categorization
async function handleCategorizeDepartments(projectId: string, body: any, user: any) {
  try {
    let validatedData: any
    try {
      validatedData = categorizeDepartmentsSchema.parse({
        departmentIds: body.departmentIds
      })
    } catch (validationErr: any) {
      console.error('Validation failed for categorize payload:', validationErr)
      return NextResponse.json({
        success: false,
        error: 'Validation failed',
        message: validationErr.errors?.[0]?.message || 'Invalid categorize payload',
        details: validationErr.errors || validationErr.issues || []
      }, { status: 400 })
    }

    const updatedProject = await executeGenericDbQuery(async () => {
      console.log("requested users 471",user);
      // Only support team can categorize projects
      // if (user.role == 'super_admin' || !['support', 'admin'].includes(user.department?.name?.toLowerCase())) {
      //   throw Object.assign(new Error('Only support team can categorize projects'), { statusCode: 403 })
      // }

      const existingProject = await Project.findById(projectId)
      
      if (!existingProject) {
        throw Object.assign(new Error('Project not found'), { statusCode: 404 })
      }

      // Verify all departments exist and are active
      const departments = await Department.find({
        _id: { $in: validatedData.departmentIds },
        status: 'active'
      })

      if (departments.length !== validatedData.departmentIds.length) {
        const notFoundIds = validatedData.departmentIds.filter(
          (id: string) => !departments.some((d: any) => d._id.toString() === id.toString())
        )
        const inactiveDepts = await Department.find({
          _id: { $in: notFoundIds },
          status: { $ne: 'active' }
        })
        const message = inactiveDepts.length > 0 
          ? `${inactiveDepts.length} selected department(s) are inactive. Please select only active departments.`
          : 'One or more selected departments were not found in the system.'
        throw Object.assign(new Error(message), { statusCode: 400 })
      }

      // Update project with departments
      const updatedProject = await Project.findByIdAndUpdate(
        projectId,
        { 
          departmentIds: validatedData.departmentIds,
          status: 'pending', // Set to pending for approval
          updatedAt: new Date()
        },
        { 
          new: true,
          runValidators: true
        }
      )
      .populate('client', 'name email')
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

      return updatedProject?.toObject ? updatedProject.toObject() : updatedProject
    })

    // Transform project to group tasks by departments
    if (updatedProject) {
      transformProjectTasksByDepartment(updatedProject)
      // Remove departments and tasks arrays from response (keep only departmentIds and departmentTasks)
      delete updatedProject.departments
      delete updatedProject.tasks
    }

    // Clear cache
    clearCache('projects')
    clearCache(`project-${projectId}`)

    return NextResponse.json({
      success: true,
      data: updatedProject,
      message: 'Project categorized successfully and set to pending approval'
    })

  } catch (error: any) {
    console.error('Error categorizing project:', error)
    if (error?.statusCode && typeof error.statusCode === 'number') {
      return NextResponse.json({ success: false, error: error.message }, { status: error.statusCode })
    }
    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Validation failed',
        message: error.errors?.[0]?.message || 'Invalid data',
        details: error.errors
      }, { status: 400 })
    }
    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to categorize project'
    }, { status: 500 })
  }
}

// Helper function to handle project approval
async function handleApproveProject(projectId: string, user: any) {
  try {
    const updatedProject = await executeGenericDbQuery(async () => {
      // Only managers and support can approve projects
      // if (!['support', 'admin'].includes(user.department?.name?.toLowerCase()) && user.role !== 'manager') {
      //   throw new Error('Only managers and support team can approve projects')
      // }

      const existingProject = await Project.findById(projectId);
      
      if (!existingProject) {
        throw new Error('Project not found')
      }
      console.log('Existing project: 417', existingProject);

      if (existingProject.status !== 'pending' && existingProject.status !== 'active') {
        throw new Error('Only pending or active projects can be approved');
      }
      
      if (existingProject.departmentIds.length === 0) {
        throw new Error('Project must be categorized before approval')
      }

      // Approve the project
      const approvedProject = await Project.findByIdAndUpdate(
        projectId,
        { 
          status: 'approved',
          approvedBy: user.id,
          approvedAt: new Date(),
          updatedAt: new Date()
        },
        { 
          new: true,
          runValidators: true
        }
      )
      .populate('client', 'name email')
      .populate('departments', 'name status')
      .populate('creator', 'name email')
      .populate('approver', 'name email')
      .populate({
        path: 'tasks',
        populate: [
          { path: 'assignee', select: 'name email' },
          { path: 'department', select: 'name' },
          { path: 'creator', select: 'name email' }
        ]
      })
      .populate('taskCount')

      return approvedProject?.toObject ? approvedProject.toObject() : approvedProject
    })

    // Transform project to group tasks by departments
    if (updatedProject) {
      transformProjectTasksByDepartment(updatedProject)
      // Remove departments and tasks arrays from response (keep only departmentIds and departmentTasks)
      delete updatedProject.departments
      delete updatedProject.tasks
    }

    // Clear cache
    clearCache('projects')
    clearCache(`project-${projectId}`)

    return NextResponse.json({
      success: true,
      data: updatedProject,
      message: 'Project approved successfully'
    })

  } catch (error: any) {
    console.error('Error approving project:', error)

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to approve project'
    }, { status: 500 })
  }
}

// DELETE /api/projects/[id] - Soft delete project
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'projects', 'delete')

    // Validate project ID
    const resolvedParams = await params
    const validatedParams = projectIdSchema.parse({ id: resolvedParams.id })

    // Check if project exists and user has access (same filtering as GET)
    const existingProject = await executeGenericDbQuery(async () => {
      const filter: any = {
        _id: validatedParams.id,
        status: { $ne: 'inactive' }
      }

      // If user is not in support/admin, filter by their department
      if (user.departmentId && !['support', 'admin'].includes(user.department?.name?.toLowerCase())) {
        filter.departmentIds = user.departmentId
      }

      // Apply soft delete filtering (exclude deleted projects like departments)
      addSoftDeleteFilter(filter, false)

      return await Project.findOne(filter)
    })

    if (!existingProject) {
      return NextResponse.json({
        success: false,
        error: 'Project not found or access denied'
      }, { status: 404 })
    }

    // Perform soft delete using the generic utility
    const deleteResult = await performSoftDelete('project', validatedParams.id, userEmail)

    if (!deleteResult.success) {
      return NextResponse.json({
        success: false,
        error: deleteResult.message
      }, { status: 400 })
    }

    return NextResponse.json({
      success: true,
      message: deleteResult.message,
      data: deleteResult.data
    })

  } catch (error: any) {
    console.error('Error deleting project:', error)

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to delete project'
    }, { status: 500 })
  }
}