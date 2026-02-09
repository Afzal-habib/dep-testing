import { executeGenericDbQuery } from '@/lib/mongodb'
import User from '@/models/User'
import Department from '@/models/Department'

export type ChannelType = 'dm' | 'group' | 'department' | 'department-category' | 'multi-category' | 'project' | 'client-support'
export type DepartmentCategory = 'sales' | 'support' | 'it' | 'management'

interface ChannelCreationParams {
  type: ChannelType
  creator_id: string
  name?: string
  
  // For department channels
  department_id?: string
  
  // For category channels
  category?: DepartmentCategory
  categories?: DepartmentCategory[] // For multi-category
  
  // For project channels
  project_id?: string
  
  // For DM/group channels
  channel_members?: string[]
  
  // For client support
  client_id?: string
  
  is_private?: boolean
}

/**
 * Get all users for a department
 */
export async function getDepartmentUsers(departmentId: string): Promise<string[]> {
  const users = await executeGenericDbQuery(async () => {
    return await User.find({ 
      department: departmentId,
      status: 'active',
      isDeleted: false
    }).select('_id').lean()
  })
  
  return users.map((u: any) => u._id.toString())
}

/**
 * Get all users with a specific department category
 */
export async function getCategoryUsers(category: DepartmentCategory): Promise<string[]> {
  // First get all departments with this category
  const departments = await executeGenericDbQuery(async () => {
    return await Department.find({ 
      category: category,
      isDeleted: false
    }).select('_id').lean()
  })
  
  const departmentIds = departments.map((d: any) => d._id.toString())
  
  if (departmentIds.length === 0) {
    return []
  }
  
  // Then get all users in these departments
  const users = await executeGenericDbQuery(async () => {
    return await User.find({
      department: { $in: departmentIds },
      status: 'active',
      isDeleted: false
    }).select('_id').lean()
  })
  
  return users.map((u: any) => u._id.toString())
}

/**
 * Get all users with any of the specified categories
 */
export async function getMultiCategoryUsers(categories: DepartmentCategory[]): Promise<string[]> {
  if (categories.length === 0) {
    return []
  }
  
  const departments = await executeGenericDbQuery(async () => {
    return await Department.find({ 
      category: { $in: categories },
      isDeleted: false
    }).select('_id').lean()
  })
  
  const departmentIds = departments.map((d: any) => d._id.toString())
  
  if (departmentIds.length === 0) {
    return []
  }
  
  const users = await executeGenericDbQuery(async () => {
    return await User.find({
      department: { $in: departmentIds },
      status: 'active',
      isDeleted: false
    }).select('_id').lean()
  })
  
  return users.map((u: any) => u._id.toString())
}

/**
 * Get all project collaborators (users assigned to any task in project)
 */
export async function getProjectCollaborators(projectId: string): Promise<string[]> {
  const Project = (await import('@/models/Project')).default
  const Task = (await import('@/models/Task')).default
  
  // Get project to add client
  const project: any = await executeGenericDbQuery(async () => {
    return await Project.findById(projectId)
      .select('clientId')
      .lean()
  })
  
  const collaborators = new Set<string>()
  
  // Add client if exists
  if (project?.clientId) {
    collaborators.add(project.clientId.toString())
  }
  
  // Get all tasks for this project and collect assignees
  const tasks = await executeGenericDbQuery(async () => {
    return await Task.find({
      projectId: projectId,
      isDeleted: false
    }).select('assigneeId').lean()
  })
  
  // Add all unique assignees
  tasks.forEach((task: any) => {
    if (task.assigneeId) {
      collaborators.add(task.assigneeId.toString())
    }
  })
  
  return Array.from(collaborators)
}

/**
 * Get support team users (users in support and management categories)
 */
export async function getSupportTeamUsers(): Promise<string[]> {
  const supportUsers = await getCategoryUsers('support')
  const managementUsers = await getCategoryUsers('management')
  return [...supportUsers, ...managementUsers]
}

/**
 * Main function to get channel members based on channel type
 */
export async function getChannelMembers(params: ChannelCreationParams): Promise<string[]> {
  const members = new Set<string>()
  
  // Always include creator
  members.add(params.creator_id)
  
  switch (params.type) {
    case 'dm':
    case 'group':
      // Direct channel_members
      if (params.channel_members) {
        params.channel_members.forEach(p => members.add(p))
      }
      break
      
    case 'department':
      // All users in department
      if (params.department_id) {
        const deptUsers = await getDepartmentUsers(params.department_id)
        deptUsers.forEach(u => members.add(u))
      }
      break
      
    case 'department-category':
      // All users with this category
      if (params.category) {
        const categoryUsers = await getCategoryUsers(params.category)
        categoryUsers.forEach(u => members.add(u))
      }
      break
      
    case 'multi-category':
      // All users with any of these categories
      if (params.categories && params.categories.length > 0) {
        const multiCategoryUsers = await getMultiCategoryUsers(params.categories)
        multiCategoryUsers.forEach(u => members.add(u))
      }
      break
      
    case 'project':
      // All project collaborators
      if (params.project_id) {
        const collaborators = await getProjectCollaborators(params.project_id)
        collaborators.forEach(u => members.add(u))
      }
      break
      
    case 'client-support':
      // Client + support and management team users
      if (params.client_id) {
        members.add(params.client_id)
        const supportTeam = await getSupportTeamUsers()
        supportTeam.forEach(u => members.add(u))
      }
      break
  }
  
  return Array.from(members)
}

/**
 * Generate channel name based on type
 */
export async function generateChannelName(params: ChannelCreationParams): Promise<string> {
  if (params.name) return params.name
  
  switch (params.type) {
    case 'dm':
      return 'Direct Message'
      
    case 'group':
      return 'Group Channel'
      
    case 'department':
      if (params.department_id) {
        const dept: any = await executeGenericDbQuery(async () => {
          return await Department.findById(params.department_id)
            .select('name')
            .lean()
        })
        return `${dept?.name || 'Department'} Channel`
      }
      return 'Department Channel'
      
    case 'department-category':
      return `${params.category?.toUpperCase() || 'Category'} Team Channel`
      
    case 'multi-category':
      if (params.categories && params.categories.length > 0) {
        const cats = params.categories.map(c => c.toUpperCase()).join(' + ')
        return `${cats} Teams Channel`
      }
      return 'Multi-Category Channel'
      
    case 'project':
      if (params.project_id) {
        const Project = (await import('@/models/Project')).default
        const project: any = await executeGenericDbQuery(async () => {
          return await Project.findById(params.project_id)
            .select('name')
            .lean()
        })
        return `Project: ${project?.name || 'Unknown'}`
      }
      return 'Project Channel'
      
    case 'client-support':
      if (params.client_id) {
        const client: any = await executeGenericDbQuery(async () => {
          return await User.findById(params.client_id)
            .select('name')
            .lean()
        })
        return `Support: ${client?.name || 'Client'}`
      }
      return 'Client Support'
      
    default:
      return 'New Channel'
  }
}
