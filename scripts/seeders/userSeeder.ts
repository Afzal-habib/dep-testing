import { connectToDatabase, disconnectFromDatabase } from '../migrations/migrationUtils'
import User from '../../models/User'
import Role from '../../models/Role'
import Department from '../../models/Department'

export interface IUserSeed {
  name: string
  email: string
  password: string
  departmentName: string
  roleName?: string
  phone?: string
  status: 'active' | 'inactive' | 'archived'
  twoFactorEnabled?: boolean
  company?: string
  website?: string
}

export const userSeeds: IUserSeed[] = [
  // Super Admin
  {
    name: 'Super Administrator',
    email: 'superadmin@gmail.com',
    password: 'SuperAdmin@123',
    departmentName: 'System',
    roleName: 'super_admin',
    phone: '1234567801',
    status: 'active',
    twoFactorEnabled: false
  },
  {
    name: 'Super Administrator Test',
    email: 'adminali@gmail.com',
    password: 'AdminAli@123',
    departmentName: 'System',
    roleName: 'super_admin',
    phone: '1234567801',
    status: 'active',
    twoFactorEnabled: false
  },
  // Super Admin
  {
    name: 'Super Administrator Depllc',
    email: 'crmdepllc@gmail.com',
    password: 'Depllc@123',
    departmentName: 'System',
    roleName: 'super_admin',
    phone: '1234567801',
    status: 'active',
    twoFactorEnabled: true
  },


  // HR Manager
  {
    name: 'Lisa Johnson',
    email: 'lisa.johnson@company.com',
    password: 'HRManager@123',
    departmentName: 'HR',
    roleName: 'hr_manager',
    phone: '1234567803',
    status: 'active',
    twoFactorEnabled: true
  },

  // Department Leads
  {
    name: 'Mike',
    email: 'mike.developer@company.com',
    password: 'DeptHead@123',
    departmentName: 'Web Development',
    roleName: 'team_lead',
    phone: '1234567804',
    status: 'active',
    twoFactorEnabled: true
  },
  {
    name: 'Anna',
    email: 'anna.designer@company.com',
    password: 'DeptHead@123',
    departmentName: 'Graphics',
    roleName: 'team_lead',
    phone: '1234567805',
    status: 'active',
    twoFactorEnabled: true
  },
  {
    name: 'David',
    email: 'david.seo@company.com',
    password: 'DeptHead@123',
    departmentName: 'SEO',
    roleName: 'team_lead',
    phone: '1234567806',
    status: 'active',
    twoFactorEnabled: true
  },
  {
    name: 'Robert',
    email: 'robert.sales@company.com',
    password: 'DeptHead@123',
    departmentName: 'Sales',
    roleName: 'team_lead',
    phone: '1234567807',
    status: 'active',
    twoFactorEnabled: true
  },
  {
    name: 'Emma',
    email: 'emma.support@company.com',
    password: 'DeptHead@123',
    departmentName: 'Support',
    roleName: 'team_lead',
    phone: '1234567808',
    status: 'active',
    twoFactorEnabled: true
  },

  // Team members
  {
    name: 'Tom',
    email: 'tom.weblead@company.com',
    password: 'TeamLead@123',
    departmentName: 'Web Development',
    roleName: 'team_member',
    phone: '1234567809',
    status: 'active',
    twoFactorEnabled: true
  },
  {
    name: 'Testing user',
    email: 'bc230202687maf@vu.edu.pk',
    password: 'Test@123',
    departmentName: 'Graphics',
    roleName: 'super_admin',
    phone: '1234567801',
    status: 'active',
    twoFactorEnabled: false
  },
  {
    name: 'Mark',
    email: 'mark.sociallead@company.com',
    password: 'TeamLead@123',
    departmentName: 'Social Media',
    roleName: 'team_member',
    phone: '1234567811',
    status: 'active', 
    twoFactorEnabled: true
  },

  // Clients
  {
    name: 'ABC Company',
    email: 'client@gmail.com',
    password: 'Client@123',
    departmentName: 'General',
    roleName: 'client',
    phone: '1234567829',
    status: 'active',
    company: 'ABC Company',
    website: 'https://www.abccompany.com',
    twoFactorEnabled: false
  },
  {
    name: 'XYZ Corporation',
    email: 'info@xyzcorp.com',
    password: 'Client@123',
    departmentName: 'General',
    roleName: 'client',
    phone: '1234567830',
    status: 'active',
    company: 'XYZ Corporation',
    website: 'https://www.xyzcorp.com',
    twoFactorEnabled: false
  }
]

async function seedUsers() {
  try {
    await connectToDatabase()
    console.log('🌱 Starting user seeding...')

    // Get existing users to check for duplicates
    const existingUsers = await User.find({}).select('email').lean()
    const existingEmails = new Set(existingUsers.map(u => u.email.toLowerCase()))

    console.log(`📋 Found ${existingUsers.length} existing users in database`)

    // Get all roles (both system and department roles)
    const allRoles = await Role.find({ status: 'active' })
    const systemRoles = allRoles.filter(role => role.isSystemRole)
    const departmentRoles = allRoles.filter(role => !role.isSystemRole)

    // Create role maps
    const systemRoleMap = new Map(systemRoles.map(role => [role.name, role]))

    // Get all departments
    const allDepartments = await Department.find({ status: 'active' })
    const departmentMap = new Map(allDepartments.map(dept => [dept.name, dept]))

    if (allRoles.length === 0 || allDepartments.length === 0) {
      throw new Error('Roles and departments must be seeded first. Run role and department seeders.')
    }

    console.log(`📋 Found ${systemRoles.length} system roles and ${departmentRoles.length} department roles`)

    // Helper function to find the correct role for a user
    const findRoleForUser = (userData: IUserSeed) => {
      const targetRoleName = userData.roleName || 'client'
      const departmentDoc = departmentMap.get(userData.departmentName)

      if (!departmentDoc) {
        throw new Error(`Department '${userData.departmentName}' not found for user ${userData.email}`)
      }

      // Check if it's a system role first
      if (systemRoleMap.has(targetRoleName)) {
        const systemRole = systemRoleMap.get(targetRoleName)!
        // For system roles with departments (super_admin, hr_manager), use the role's department
        // For other system roles, use the user's department
        let assignedDepartment = departmentDoc
        if (systemRole.department) {
          // Find the department name from the department ID
          for (const [deptName, dept] of departmentMap.entries()) {
            if (dept._id.toString() === systemRole.department.toString()) {
              assignedDepartment = dept
              break
            }
          }
        }

        return {
          role: systemRole,
          department: assignedDepartment
        }
      }

      // Special case for client role - always use General department
      if (targetRoleName === 'client') {
        const clientRole = departmentRoles.find(role => role.name === 'client')
        if (clientRole) {
          return {
            role: clientRole,
            department: departmentMap.get('General') || departmentDoc
          }
        }
      }

      // For department roles, find by role name and department
      const departmentRole = departmentRoles.find(role =>
        role.name === targetRoleName &&
        role.department.toString() === departmentDoc._id.toString()
      )

      if (departmentRole) {
        return {
          role: departmentRole,
          department: departmentDoc
        }
      }

      // Fallback: try to find a client role for this department
      const clientRole = departmentRoles.find(role =>
        role.name === 'client' &&
        role.department.toString() === departmentDoc._id.toString()
      )

      if (clientRole) {
        console.warn(`⚠️  Role '${targetRoleName}' not found for user ${userData.email}, using 'client' role`)
        return {
          role: clientRole,
          department: departmentDoc
        }
      }

      // Final fallback: use any client role
      const anyClientRole = departmentRoles.find(role => role.name === 'client')
      if (anyClientRole) {
        console.warn(`⚠️  No specific role found for user ${userData.email}, using 'client' role from another department`)
        return {
          role: anyClientRole,
          department: departmentMap.get('General') || departmentDoc
        }
      }

      throw new Error(`No suitable role found for user ${userData.email} with role '${targetRoleName}' in department '${userData.departmentName}'`)
    }

    // Create users with proper role and department mapping
    const usersToCreate = userSeeds.map(userData => {
      const { role: finalRole, department: finalDepartment } = findRoleForUser(userData)

      const isClientUser = finalRole.name === 'client'

      return {
        name: userData.name,
        email: userData.email,
        password: userData.password,
        role: finalRole._id,
        department: isClientUser ? undefined : finalDepartment._id, // Clients don't need department
        phone: userData.phone || '',
        status: 'active',
        emailVerified: true,
        phoneVerified: false,
        twoFactorEnabled: userData.twoFactorEnabled,
        isClient: isClientUser,
        // Client-specific fields
        ...(isClientUser && {
          company: userData.company || (userData.name.includes('@') ? userData.name.split('@')[1] : 'Client Company'),
          website: userData.website || (userData.email.includes('@') ? `https://www.${userData.email.split('@')[1]}` : 'https://www.clientcompany.com'),
          clientStatus: 'qualified' as const,
        }),
        permissions: [],
        metadata: {
          tags: ['seeded'],
          createdBy: 'system_seeder',
          isSuperAdmin: userData.roleName === 'super_admin',
          roleHierarchy: finalRole.hierarchyLevel
        }
      }
    })

    // Create or update users to prevent duplicates
    const createdUsers = []
    let created = 0
    let updated = 0
    let skipped = 0

    for (const userData of usersToCreate) {
      const emailLower = userData.email.toLowerCase()

      if (existingEmails.has(emailLower)) {
        // Update existing user
        const existingUser = await User.findOne({ email: emailLower })
        if (existingUser) {
          // Only update if there are meaningful changes
          const hasChanges =
            existingUser.name !== userData.name ||
            existingUser.role?.toString() !== userData.role.toString() ||
            existingUser.department?.toString() !== userData.department?.toString() ||
            existingUser.status !== userData.status ||
            existingUser.twoFactorEnabled !== userData.twoFactorEnabled

          if (hasChanges) {
            await User.findByIdAndUpdate(existingUser._id, {
              name: userData.name,
              role: userData.role,
              department: userData.department,
              phone: userData.phone,
              status: userData.status,
              emailVerified: userData.emailVerified,
              phoneVerified: userData.phoneVerified,
              twoFactorEnabled: userData.twoFactorEnabled,
              permissions: userData.permissions,
              'metadata.updatedBy': 'system_seeder',
              'metadata.tags': userData.metadata.tags
            })
            createdUsers.push(existingUser)
            updated++
            console.log(`📝 Updated user: ${userData.email}`)
          } else {
            createdUsers.push(existingUser)
            skipped++
            console.log(`⏭️  Skipped user (no changes): ${userData.email}`)
          }
        }
      } else {
        // Create new user
        try {
          const newUser = await User.create(userData)
          createdUsers.push(newUser)
          created++
          console.log(`✅ Created user: ${userData.email}`)
        } catch (error: any) {
          if (error.code === 11000) {
            // Duplicate key error - user already exists
            console.warn(`⚠️  User already exists: ${userData.email}`)
            skipped++
          } else {
            throw error
          }
        }
      }
    }

    console.log(`\n📊 User Seeding Summary:`)
    console.log(`✅ Created: ${created}`)
    console.log(`📝 Updated: ${updated}`)
    console.log(`⏭️  Skipped: ${skipped}`)
    console.log(`📊 Total Users: ${createdUsers.length}`)

    // Group users by role and department for summary
    const roleStats = new Map()
    const departmentStats = new Map()

    for (const user of createdUsers) {
      const userRole = allRoles.find(r => r._id.toString() === user.role.toString())
      const userDept = user.department ? allDepartments.find(d => d._id.toString() === user.department?.toString()) : null

      if (userRole) {
        roleStats.set(userRole.displayName, (roleStats.get(userRole.displayName) || 0) + 1)
      }
      if (userDept && userDept.name) {
        departmentStats.set(userDept.name, (departmentStats.get(userDept.name) || 0) + 1)
      }
    }

    console.log('\n👥 Users by Role:')
    for (const [roleName, count] of roleStats) {
      console.log(`   ${roleName}: ${count} users`)
    }

    console.log('\n🏢 Users by Department:')
    for (const [deptName, count] of departmentStats) {
      console.log(`   ${deptName}: ${count} users`)
    }

    console.log('\n✨ User seeding completed successfully')
    console.log('\n🔐 Sample Login Credentials:')
    console.log('   Super Admin: superadmin@gmail.com / SuperAdmin@123')
    console.log('   Project Manager: john.smith@company.com / ProjectManager@123')
    console.log('   HR Manager: lisa.johnson@company.com / HRManager@123')
    console.log('   Department Head: mike.developer@company.com / DeptHead@123')
    console.log('   Team Lead: tom.weblead@company.com / TeamLead@123')
    console.log('   Senior Executive: alex.seniordev@company.com / SeniorExec@123')
    console.log('   Executive: paul.webexec@company.com / Executive@123')
    console.log('   Junior Executive: steve.juniordev@company.com / JuniorExec@123')
    console.log('   Intern: james.webintern@company.com / Intern@123')
    console.log('   Client: contact@abccompany.com / Client@123')

    // Verify users were actually saved to database
    const verifyCount = await User.countDocuments()
    console.log(`\n🔍 Verification: ${verifyCount} users in database`)

    if (verifyCount !== createdUsers.length) {
      console.warn(`⚠️  Warning: Expected ${createdUsers.length} users but found ${verifyCount} in database`)
    }

    return {
      success: true,
      created: createdUsers.length,
      roleStats: Object.fromEntries(roleStats),
      departmentStats: Object.fromEntries(departmentStats)
    }

  } catch (error) {
    console.error('❌ Error seeding users:', error)
    throw error
  }
}

// Run directly if called as script
if (require.main === module) {
  seedUsers()
    .then(() => {
      console.log('User seeding completed!')
      process.exit(0)
    })
    .catch((error) => {
      console.error('User seeding failed:', error)
      process.exit(1)
    })
}

export default seedUsers