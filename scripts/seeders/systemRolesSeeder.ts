// Load environment variables
import { config } from 'dotenv'
import path from 'path'

// Load .env.local file
config({ path: path.resolve(process.cwd(), '.env.local') })

import connectDB from "../lib/mongodb"
import Role from "../../models/Role"
import Department from "../../models/Department"
import SystemPermission from "../../models/SystemPermission"
import { PERMISSIONS } from "../../lib/constants/permissions"

// Helper function to create permission objects from centralized permissions
const createPermissionSet = (permissionList: Array<{
  permission: any,
  actions: string[],
  conditions?: Record<string, boolean>
}>) => {
  return permissionList.map(({ permission, actions, conditions = {} }) => ({
    resource: permission.resource,
    actions,
    conditions
  }))
}

/**
 * ========================================
 * SYSTEM ROLES WITH CENTRALIZED PERMISSIONS
 * ========================================
 * Perfect symmetry with the main application!
 * 
 * ✅ Uses the same PERMISSIONS from lib/constants/permissions.ts
 * ✅ No hardcoded permission objects
 * ✅ Consistent with API and frontend systems
 * ✅ Easy to maintain and update
 * ✅ Type-safe permission references
 * ========================================
 */
const systemRoles = [
  {
    name: "super_admin",
    displayName: "Super Administrator",
    description: "Full system access with all permissions - Cannot be modified or deleted",
    hierarchyLevel: 10,
    isSystemRole: true, // Changed to department role
    isImmutable: true,
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.USERS_READ, actions: ["create", "read", "update", "delete", "assign"] },
      { permission: PERMISSIONS.DEPARTMENTS_READ, actions: ["create", "read", "update", "delete", "assign"] },
      { permission: PERMISSIONS.ROLES_READ, actions: ["create", "read", "update", "delete", "assign"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read", "update", "delete", "assign"] },
      { permission: PERMISSIONS.SYSTEM_READ, actions: ["create", "read", "update", "delete", "manage", "configure", "audit", "archive", "export", "import"], conditions: { unrestricted: true } },
      { permission: PERMISSIONS.AUDIT_LOGS_READ, actions: ["read", "export", "archive"] },
      { permission: PERMISSIONS.REPORTS_READ, actions: ["create", "read", "update", "delete", "export"] },
      { permission: PERMISSIONS.DASHBOARD_READ, actions: ["read"] },
      { permission: PERMISSIONS.SETTINGS_READ, actions: ["create", "read", "update", "delete"] },
      { permission: PERMISSIONS.BACKUP_READ, actions: ["create", "read", "export", "import"] },
      { permission: PERMISSIONS.PERMISSIONS_READ, actions: ["create", "read", "update", "delete", "assign"] },
      { permission: { resource: 'leads' }, actions: ["create", "read", "update", "delete", "assign"] },
      { permission: { resource: 'projects' }, actions: ["create", "read", "update", "delete", "assign"] },
      { permission: { resource: 'tasks' }, actions: ["create", "read", "update", "delete", "assign"] },
      { permission: { resource: 'proposals' }, actions: ["create", "read", "update", "delete", "assign"] },
      { permission: { resource: 'email' }, actions: ["create", "read", "update", "delete"], conditions: { unrestricted: true } },
      { permission: { resource: 'upload' }, actions: ["create", "read", "update", "delete"], conditions: { unrestricted: true } },
      { permission: { resource: 'client-portal' }, actions: ["create", "read", "update"], conditions: { unrestricted: true } },
    ])
  },
  {
    name: "hr_manager",
    displayName: "HR Manager",
    description: "Human Resources management with user and department oversight",
    hierarchyLevel: 8,
    isSystemRole: true, // Changed to department role
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.USERS_READ, actions: ["create", "read", "update", "assign"], conditions: { subordinates: true } },
      { permission: PERMISSIONS.DEPARTMENTS_READ, actions: ["read", "update"] },
      { permission: PERMISSIONS.ROLES_READ, actions: ["read", "assign"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read", "update", "assign"] },
      { permission: PERMISSIONS.REPORTS_READ, actions: ["create", "read", "export"] },
      { permission: PERMISSIONS.DASHBOARD_READ, actions: ["read"] },
      { permission: PERMISSIONS.AUDIT_LOGS_READ, actions: ["read"] },
    ])
  },
  {
    name: "department_head",
    displayName: "Department Head",
    description: "Department leadership with team management and reporting",
    hierarchyLevel: 7,
    isSystemRole: false,
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.USERS_READ, actions: ["read", "update"], conditions: { department: true } },
      { permission: PERMISSIONS.DEPARTMENTS_READ, actions: ["read"] },
      { permission: PERMISSIONS.ROLES_READ, actions: ["read"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read", "update", "assign"] },
      { permission: PERMISSIONS.REPORTS_READ, actions: ["create", "read", "export"] },
      { permission: PERMISSIONS.DASHBOARD_READ, actions: ["read"] },
    ])
  },
  {
    name: "team_lead",
    displayName: "Team Lead",
    description: "Team leadership with project oversight and team coordination",
    hierarchyLevel: 6,
    isSystemRole: false,
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.USERS_READ, actions: ["read"], conditions: { own: true, department: true } },
      { permission: PERMISSIONS.DEPARTMENTS_READ, actions: ["read"] },
      { permission: PERMISSIONS.ROLES_READ, actions: ["read"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read", "update", "assign"] },
      { permission: PERMISSIONS.REPORTS_READ, actions: ["read", "export"] },
      { permission: PERMISSIONS.DASHBOARD_READ, actions: ["read"] },
    ])
  },
   {
    name: "team_member",
    displayName: "Team Member",
    description: "Team member with project tasks and collaboration capabilities",
    hierarchyLevel: 5,
    isSystemRole: false,
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.USERS_READ, actions: ["read"], conditions: { own: true, department: true } },
      { permission: PERMISSIONS.DEPARTMENTS_READ, actions: ["read"] },
      { permission: PERMISSIONS.ROLES_READ, actions: ["read"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read", "update", "assign"] },
      { permission: PERMISSIONS.REPORTS_READ, actions: ["read", "export"] },
      { permission: PERMISSIONS.DASHBOARD_READ, actions: ["read"] },
    ])
  },
  {
    name: "sales_manager",
    displayName: "Sales Manager",
    description: "Sales leadership with project oversight and team coordination",
    hierarchyLevel: 6,
    isSystemRole: false,
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.USERS_READ, actions: ["read"], conditions: { own: true, department: true } },
      { permission: PERMISSIONS.DEPARTMENTS_READ, actions: ["read"] },
      { permission: PERMISSIONS.ROLES_READ, actions: ["read"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read", "update", "assign"] },
      { permission: PERMISSIONS.REPORTS_READ, actions: ["read", "export"] },
      { permission: PERMISSIONS.DASHBOARD_READ, actions: ["read"] },
    ])
  },
  {
    name: "sales_closer",
    displayName: "Sales Closer",
    description: "Sales closing with project oversight and team coordination",
    hierarchyLevel: 6,
    isSystemRole: false,
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.USERS_READ, actions: ["read"], conditions: { own: true, department: true } },
      { permission: PERMISSIONS.DEPARTMENTS_READ, actions: ["read"] },
      { permission: PERMISSIONS.ROLES_READ, actions: ["read"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read", "update", "assign"] },
      { permission: PERMISSIONS.REPORTS_READ, actions: ["read", "export"] },
      { permission: PERMISSIONS.DASHBOARD_READ, actions: ["read"] },
    ])
  },
  {
    name: "sales_agent",
    displayName: "Sales Agent",
    description: "Sales agent with project oversight and team coordination",
    hierarchyLevel: 6,
    isSystemRole: false,
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.USERS_READ, actions: ["read"], conditions: { own: true, department: true } },
      { permission: PERMISSIONS.DEPARTMENTS_READ, actions: ["read"] },
      { permission: PERMISSIONS.ROLES_READ, actions: ["read"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read", "update", "assign"] },
      { permission: PERMISSIONS.REPORTS_READ, actions: ["read", "export"] },
      { permission: PERMISSIONS.DASHBOARD_READ, actions: ["read"] },
    ])
  },
  {
    name: "accountant",
    displayName: "Accountant",
    description: "Financial management and accounting operations",
    hierarchyLevel: 5,
    isSystemRole: false,
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.USERS_READ, actions: ["read"], conditions: { own: true, department: true } },
      { permission: PERMISSIONS.DEPARTMENTS_READ, actions: ["read"] },
      { permission: PERMISSIONS.ROLES_READ, actions: ["read"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read", "update", "assign"] },
      { permission: PERMISSIONS.REPORTS_READ, actions: ["read", "export"] },
      { permission: PERMISSIONS.DASHBOARD_READ, actions: ["read"] },
    ])
  },
  {
    name: "client",
    displayName: "Client",
    description: "External client with limited access to client portal",
    hierarchyLevel: 1,
    isSystemRole: false,
    permissions: createPermissionSet([
      { permission: PERMISSIONS.PROFILE_READ, actions: ["read", "update"], conditions: { own: true } },
      { permission: PERMISSIONS.CLIENT_PORTAL_READ, actions: ["read"] },
      { permission: PERMISSIONS.COMMUNICATIONS_READ, actions: ["create", "read"], conditions: { own: true } },
    ])
  },
]

export async function seedSystemRoles() {
  try {
    console.log('🌱 Starting system roles seeding...')

    await connectDB()

    // Verify system permissions exist
    const systemPermissions = await SystemPermission.find({ status: 'active' }).lean()
    if (systemPermissions.length === 0) {
      throw new Error('System permissions must be seeded first. Run systemPermissionsSeeder seeder.')
    }

    console.log(`📋 Found ${systemPermissions.length} system permissions`)

    // Get all departments for department-specific roles
    const departments = await Department.find({ status: 'active' }).lean() as unknown as Array<{
      _id: string;
      name: string;
      category: 'sales' | 'support' | 'it' | 'management';
    }>
    if (departments.length === 0) {
      throw new Error('Departments must be seeded first. Run department seeder.')
    }

    console.log(`🏢 Found ${departments.length} departments`)

    // Get existing roles (both system and department roles)
    const existingRoles = await Role.find({}).lean()

    let created = 0
    let updated = 0
    let skipped = 0

    // Separate system roles from department roles
    const systemRoleTemplates = systemRoles.filter(role => role.isSystemRole)
    const departmentRoleTemplates = systemRoles.filter(role => !role.isSystemRole)

    console.log(`📋 Processing ${systemRoleTemplates.length} system role templates and ${departmentRoleTemplates.length} department role templates`)

    // Process system roles first (these don't need departments, except for specific ones)
    for (const roleData of systemRoleTemplates) {
      const existingRole = existingRoles.find(r => r.name === roleData.name && r.isSystemRole)

      if (existingRole) {
        // Skip updating super_admin role if it already exists and is marked immutable
        if (roleData.name === 'super_admin' && existingRole.metadata?.isImmutable) {
          skipped++
          console.log(`🔒 Skipped immutable role: ${roleData.name} (protected from modification)`)
          continue
        }

        // Check if permissions have changed
        const hasChanges =
          existingRole.displayName !== roleData.displayName ||
          existingRole.description !== roleData.description ||
          JSON.stringify(existingRole.permissions) !== JSON.stringify(roleData.permissions)

        if (hasChanges) {
          await Role.findByIdAndUpdate(existingRole._id, {
            displayName: roleData.displayName,
            description: roleData.description,
            permissions: roleData.permissions,
            hierarchyLevel: roleData.hierarchyLevel,
            'metadata.updatedBy': 'system_seeder',
            'metadata.isImmutable': roleData.isImmutable || false
          })
          updated++
          console.log(`📝 Updated system role: ${roleData.name}`)
        } else {
          skipped++
          console.log(`⏭️  Skipped system role (no changes): ${roleData.name}`)
        }
      } else {
        // Assign departments to specific system roles
        let departmentId = null
        if (roleData.name === 'super_admin') {
          const systemDept = departments.find(d => d.name === 'System')
          departmentId = systemDept?._id || null
        } else if (roleData.name === 'hr_manager') {
          const hrDept = departments.find(d => d.name === 'HR')
          departmentId = hrDept?._id || null
        }

        // Create new system role
        const role = new Role({
          ...roleData,
          department: departmentId, // Assign department for specific system roles
          status: 'active',
          metadata: {
            createdBy: 'system_seeder',
            isImmutable: roleData.isImmutable || false
          }
        })
        await role.save()
        created++
        console.log(`✅ Created system role: ${roleData.name}${departmentId ? ` (assigned to ${departments.find(d => d._id.toString() === departmentId?.toString())?.name})` : ''}`)
      }
    }

    // Define which roles to create for each department by name
    const departmentRolesMap: Record<string, string[]> = {
      'Web Development': ['team_lead', 'team_member'],
      'Graphics': ['team_lead', 'team_member'],
      'SEO': ['team_lead', 'team_member'],
      'GMB': ['team_lead', 'team_member'], // IT category
      'Sales': ['team_lead', 'sales_manager', 'sales_closer', 'sales_agent'],
      'Social Media': ['department_head', 'team_lead','team_member'],
      'Support': ['department_head', 'team_lead', 'team_member'],
      'Accounting': ['accountant'],
      'General': ['client']
    }

    // Process department roles - create appropriate roles for each department based on name
    for (const department of departments) {
      const rolesToCreate = departmentRolesMap[department.name] || []
      
      for (const roleName of rolesToCreate) {
        const roleTemplate = departmentRoleTemplates.find(rt => rt.name === roleName)
        if (!roleTemplate) continue

        const existingDeptRole = existingRoles.find(r => r.name === roleName && r.department?.toString() === department._id.toString() && !r.isSystemRole)

        if (existingDeptRole) {
          // Check if permissions have changed for department role
          const hasChanges =
            existingDeptRole.displayName !== roleTemplate.displayName ||
            existingDeptRole.description !== roleTemplate.description ||
            JSON.stringify(existingDeptRole.permissions) !== JSON.stringify(roleTemplate.permissions)

          if (hasChanges) {
            await Role.findByIdAndUpdate(existingDeptRole._id, {
              displayName: roleTemplate.displayName,
              description: roleTemplate.description,
              permissions: roleTemplate.permissions,
              hierarchyLevel: roleTemplate.hierarchyLevel,
              'metadata.updatedBy': 'system_seeder'
            })
            updated++
            console.log(`📝 Updated department role: ${roleName} (${department.name})`)
          } else {
            skipped++
            console.log(`⏭️  Skipped department role (no changes): ${roleName} (${department.name})`)
          }
        } else {
          // Create new department role
          const role = new Role({
            name: roleName,
            displayName: roleTemplate.displayName,
            description: roleTemplate.description,
            department: department._id,
            permissions: roleTemplate.permissions,
            hierarchyLevel: roleTemplate.hierarchyLevel,
            isSystemRole: false,
            status: 'active',
            metadata: {
              createdBy: 'system_seeder'
            }
          })
          await role.save()
          created++
          console.log(`✅ Created department role: ${roleName} (${department.name})`)
        }
      }
    }

    // ========================================
    // ENSURE ALL ROLES HAVE COMMUNICATION PERMISSIONS
    // ========================================
    console.log('\n📡 Ensuring all roles have communication permissions...')

    const allRoles = await Role.find({ status: 'active' }).lean()
    let communicationUpdated = 0

    for (const role of allRoles) {
      const hasCommunicationPermission = role.permissions.some((p: any) =>
        p.resource === PERMISSIONS.COMMUNICATIONS_READ.resource
      )

      if (!hasCommunicationPermission) {
        // Determine communication permissions based on hierarchy level
        let communicationActions: string[]
        if (role.hierarchyLevel >= 6) {
          // High-level roles: full communication access
          communicationActions = ["create", "read", "update", "assign"]
        } else if (role.hierarchyLevel >= 2) {
          // Mid-level roles: read and update
          communicationActions = ["read", "update"]
        } else {
          // Low-level roles: read-only
          communicationActions = ["read"]
        }

        const communicationPermission = {
          resource: PERMISSIONS.COMMUNICATIONS_READ.resource,
          actions: communicationActions,
          conditions: {}
        }

        // Add communication permission to the role
        await Role.findByIdAndUpdate(role._id, {
          $push: { permissions: communicationPermission },
          'metadata.updatedBy': 'system_seeder',
          'metadata.lastCommunicationUpdate': new Date()
        })

        communicationUpdated++
        console.log(`📡 Added communication permissions to role: ${role.name} (${communicationActions.join(', ')})`)
      }
    }

    if (communicationUpdated > 0) {
      console.log(`✅ Added communication permissions to ${communicationUpdated} roles`)
    } else {
      console.log('✅ All roles already have communication permissions')
    }

    // Summary
    console.log('\n📊 Roles Seeding Summary:')
    console.log(`✅ Created: ${created}`)
    console.log(`📝 Updated: ${updated}`)
    console.log(`⏭️  Skipped: ${skipped}`)
    console.log(`📊 Total Roles: ${created + updated + skipped}`)

    // Get role statistics
    const [systemStats, departmentStats] = await Promise.all([
      Role.aggregate([
        { $match: { isSystemRole: true, status: 'active' } },
        {
          $group: {
            _id: null,
            totalRoles: { $sum: 1 },
            avgHierarchy: { $avg: '$hierarchyLevel' },
            maxHierarchy: { $max: '$hierarchyLevel' },
            minHierarchy: { $min: '$hierarchyLevel' }
          }
        }
      ]),
      Role.aggregate([
        { $match: { isSystemRole: false, status: 'active' } },
        {
          $group: {
            _id: null,
            totalRoles: { $sum: 1 },
            avgHierarchy: { $avg: '$hierarchyLevel' },
            maxHierarchy: { $max: '$hierarchyLevel' },
            minHierarchy: { $min: '$hierarchyLevel' }
          }
        }
      ])
    ])

    console.log('\n📋 Role Statistics:')
    if (systemStats.length > 0) {
      const stats = systemStats[0]
      console.log(`   System Roles: ${stats.totalRoles}`)
      console.log(`   System Hierarchy Range: ${stats.minHierarchy} - ${stats.maxHierarchy}`)
    }

    if (departmentStats.length > 0) {
      const stats = departmentStats[0]
      console.log(`   Department Roles: ${stats.totalRoles}`)
      console.log(`   Department Hierarchy Range: ${stats.minHierarchy} - ${stats.maxHierarchy}`)
    }

    // List all system roles
    const allSystemRoles = await Role.find({ isSystemRole: true, status: 'active' })
      .select('name displayName hierarchyLevel')
      .sort({ hierarchyLevel: -1 })
      .lean()

    console.log('\n🎭 Available System Roles:')
    allSystemRoles.forEach(role => {
      console.log(`   ${role.displayName} (Level ${role.hierarchyLevel})`)
    })

    // List department roles grouped by department
    const departmentRoles = await Role.find({ isSystemRole: false, status: 'active' })
      .populate('department', 'name')
      .select('name displayName hierarchyLevel department')
      .sort({ 'department.name': 1, hierarchyLevel: -1 })
      .lean()

    if (departmentRoles.length > 0) {
      console.log('\n🏢 Available Department Roles:')
      const rolesByDept = departmentRoles.reduce((acc: any, role: any) => {
        const deptName = role.department?.name || 'Unknown'
        if (!acc[deptName]) acc[deptName] = []
        acc[deptName].push(role)
        return acc
      }, {})

      Object.entries(rolesByDept).forEach(([deptName, roles]) => {
        console.log(`   ${deptName} Department:`)
        const roleList = roles as any[]
        roleList.forEach(role => {
          console.log(`     - ${role.displayName} (Level ${role.hierarchyLevel})`)
        })
      })
    }

    console.log('\n🎉 System and department roles seeding completed successfully!')
    return {
      success: true,
      created,
      updated,
      skipped,
      total: created + updated + skipped,
      systemRoles: allSystemRoles,
      departmentRoles: departmentRoles
    }

  } catch (error: any) {
    console.error('❌ Error seeding system roles:', error)
    throw error
  }
}

// Run directly if called as script
if (require.main === module) {
  seedSystemRoles()
    .then(() => {
      console.log('System roles seeding completed!')
      process.exit(0)
    })
    .catch((error) => {
      console.error('System roles seeding failed:', error)
      process.exit(1)
    })
}

export default seedSystemRoles