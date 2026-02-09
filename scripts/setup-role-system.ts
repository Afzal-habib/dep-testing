// Load environment variables
import { config } from 'dotenv'
import path from 'path'

// Load .env.local file 
config({ path: path.resolve(process.cwd(), '.env.local') })

import connectDB from "../lib/mongodb"
import seedDepartments from "./seeders/departmentSeeder"
import seedUsers from "./seeders/userSeeder"
import seedSystemPermissions from './seeders/systemPermissionsSeeder'
import seedSystemRoles from './seeders/systemRolesSeeder'

export async function setupDynamicRoleSystem() {
  try {
    console.log('🚀 Starting Dynamic Role and Permission System Setup...')
    console.log('=' .repeat(60))
    
    await connectDB()
    console.log('📡 Database connected successfully')

    // Step 1: Seed System Permissions
    console.log('\n🔧 STEP 1: Setting up System Permissions')
    console.log('-' .repeat(40))
    const permissionsResult = await seedSystemPermissions()
    console.log(`✅ Permissions setup complete: ${permissionsResult.total} permissions configured`)

    // Step 2: Seed System Roles
    console.log('\n🎭 STEP 2: Setting up System Roles')
    console.log('-' .repeat(40))
    const systemRolesResult = await seedSystemRoles()
    console.log(`✅ System roles setup complete: ${systemRolesResult.total} roles configured`)

    // Step 3: Seed Business Departments
    console.log('\n🏢 STEP 3: Setting up Business Departments')
    console.log('-' .repeat(40))
    const departmentsResult = await seedDepartments()
    console.log(`✅ Departments setup complete: ${departmentsResult.total} departments configured`)

    // Step 4: Seed Users with Roles and Departments
    console.log('\n👥 STEP 4: Creating Users with Role Assignments')
    console.log('-' .repeat(40))
    const usersResult = await seedUsers()
    console.log(`✅ Users creation complete: ${usersResult.created} users created`)

    // Final Summary
    console.log('\n' + '=' .repeat(60))
    console.log('🎉 DYNAMIC ROLE SYSTEM SETUP COMPLETE!')
    console.log('=' .repeat(60))
    
    console.log('\n📊 COMPREHENSIVE SETUP SUMMARY:')
    console.log(`   🔧 System Permissions: ${permissionsResult.total}`)
    console.log(`     - Created: ${permissionsResult.created}`)
    console.log(`     - Updated: ${permissionsResult.updated}`)
    console.log(`     - Categories: ${permissionsResult.categoryStats.length}`)
    
    console.log(`\n   🎭 System Roles: ${systemRolesResult.total}`)
    console.log(`     - Created: ${systemRolesResult.created}`)
    console.log(`     - Updated: ${systemRolesResult.updated}`)
    console.log(`     - Hierarchy Levels: 1-10`)
    
    console.log(`\n   🏢 Business Departments: ${departmentsResult.total}`)
    console.log(`     - Created: ${departmentsResult.created}`)
    console.log(`     - Updated: ${departmentsResult.updated}`)
    
    console.log(`\n   👥 Users: ${usersResult.created}`)
    console.log(`     - Across all roles and departments`)
    console.log(`     - Role distribution: Multiple users per role`)

    console.log('\n📋 PERMISSION CATEGORIES:')
    permissionsResult.categoryStats.forEach((cat: any) => {
      console.log(`     ${cat._id}: ${cat.count} permissions (${cat.coreCount} core)`)
    })

    console.log('\n🎭 ROLE HIERARCHY:')
    if (systemRolesResult.systemRoles) {
      systemRolesResult.systemRoles.forEach((role: any) => {
        console.log(`     ${role.displayName} (Level ${role.hierarchyLevel})`)
      })
    }

    console.log('\n🏢 BUSINESS DEPARTMENTS:')
    if (departmentsResult.departments) {
      departmentsResult.departments.forEach((dept: any) => {
        console.log(`     ${dept.name}`)
      })
    }

    console.log('\n👥 USER DISTRIBUTION:')
    if (usersResult.roleStats) {
      Object.entries(usersResult.roleStats).forEach(([role, count]) => {
        console.log(`     ${role}: ${count} users`)
      })
    }

    console.log('\n🏢 DEPARTMENT DISTRIBUTION:')
    if (usersResult.departmentStats) {
      Object.entries(usersResult.departmentStats).forEach(([dept, count]) => {
        console.log(`     ${dept}: ${count} users`)
      })
    }

    console.log('\n✨ NEXT STEPS:')
    console.log('   1. ✅ System permissions are configured')
    console.log('   2. ✅ Hierarchical roles are available (10 levels)')
    console.log('   3. ✅ Business departments are structured')
    console.log('   4. ✅ Users are distributed across roles/departments')
    console.log('   5. 🔄 Frontend integration with new role system')
    console.log('   6. 🔄 Test role-based access controls')
    console.log('   7. 🔄 Configure department-specific workflows')

    console.log('\n🛠️  API ENDPOINTS AVAILABLE:')
    console.log('   - GET    /api/roles                    (List roles)')
    console.log('   - POST   /api/roles                    (Create role)')
    console.log('   - GET    /api/roles/[id]               (Get role)')
    console.log('   - PUT    /api/roles/[id]               (Update role)')
    console.log('   - DELETE /api/roles/[id]               (Delete role)')
    console.log('   - GET    /api/departments              (List departments)')
    console.log('   - GET    /api/departments/[id]/roles   (Department roles)')
    console.log('   - GET    /api/systemPermissionsSeeder       (Available permissions)')
    console.log('   - GET    /api/users                    (List users)')

    console.log('\n🔐 SECURITY FEATURES:')
    console.log('   ✅ Hierarchical role-based access control')
    console.log('   ✅ Permission-based actions (10+ resources)')
    console.log('   ✅ Department-scoped operations')
    console.log('   ✅ Superadmin protection (superadmin@gmail.com)')
    console.log('   ✅ API permission validation')
    console.log('   ✅ Audit trail and logging')
    console.log('   ✅ Rate limiting and validation')

    console.log('\n🔑 AUTHENTICATION CREDENTIALS:')
    console.log('   Super Admin: superadmin@gmail.com / SuperAdmin@123')
    console.log('   Project Manager: john.smith@company.com / ProjectManager@123')
    console.log('   HR Manager: lisa.johnson@company.com / HRManager@123')
    console.log('   Department Head: mike.developer@company.com / DeptHead@123')
    console.log('   Team Lead: tom.weblead@company.com / TeamLead@123')
    console.log('   + 27 more users across all departments and roles')

    console.log('\n' + '=' .repeat(60))

    return {
      success: true,
      permissions: permissionsResult,
      systemRoles: systemRolesResult,
      departments: departmentsResult,
      users: usersResult,
      timestamp: new Date().toISOString()
    }

  } catch (error: any) {
    console.error('\n❌ SETUP FAILED!')
    console.error('=' .repeat(40))
    console.error('Error:', error.message)
    console.error('Stack:', error.stack)
    console.error('=' .repeat(40))
    throw error
  }
}

// Run directly if called as script
if (require.main === module) {
  setupDynamicRoleSystem()
    .then((result) => {
      console.log('\n🏁 Setup script completed successfully!')
      process.exit(0)
    })
    .catch((error) => {
      console.error('\n💥 Setup script failed!')
      console.error(error)
      process.exit(1)
    })
}

export default setupDynamicRoleSystem