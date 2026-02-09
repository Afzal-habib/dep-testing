import seedSystemPermissions from './systemPermissionsSeeder'
import seedDepartments from './departmentSeeder'
import seedSystemRoles from './systemRolesSeeder'
import seedUsers from './userSeeder'
import seedLeads from './leadSeeder'
import seedProjects from './projectSeeder'


async function runSeeders() {
  try {
    console.log('🚀 Starting comprehensive database seeding...')
    console.log('=' .repeat(60))
    
    // Step 1: Seed System Permissions (Foundation)
    console.log('\n🔧 STEP 1: Seeding System Permissions')
    console.log('-' .repeat(40))
    await seedSystemPermissions()

    // Step 2: Seed System Roles (Based on permissions)
    console.log('\n🎭 STEP 2: Seeding System Roles')
    console.log('-' .repeat(40))
    await seedSystemRoles()

    // Step 3: Seed Departments (Required for users)
    console.log('\n🏢 STEP 3: Seeding Departments')
    console.log('-' .repeat(40))
    await seedDepartments()

    // Step 4: Seed Users (Final step with roles and departments)
    console.log('\n👥 STEP 4: Seeding Users')
    console.log('-' .repeat(40))
    await seedUsers()

    // Step 5: Seed Leads (Business flow starts here)
    console.log('\n📋 STEP 5: Seeding Leads')
    console.log('-' .repeat(40))
    await seedLeads()

    // Step 6: Seed Projects (Based on qualified leads/clients)
    console.log('\n📁 STEP 6: Seeding Projects')
    console.log('-' .repeat(40))
    await seedProjects()
  //  in future taskSeeder will be uncommented to seed tasks as well
    // // Step 7: Seed Tasks (Based on projects and departments)
    // console.log('\n✅ STEP 7: Seeding Tasks')
    // console.log('-' .repeat(40))
    // await seedTasks()

    // console.log('\n' + '=' .repeat(60))
    // console.log('🎉 COMPREHENSIVE DATABASE SEEDING COMPLETE!')
    // console.log('=' .repeat(60))
    
    console.log('\n📊 SEEDING SUMMARY:')
    console.log('   ✅ System Permissions: Configured')
    console.log('   ✅ System Roles: 10 hierarchical roles created')
    console.log('   ✅ Departments: 10 business departments created')
    console.log('   ✅ Users: 32+ users across all roles and departments')
    console.log('   ✅ Leads: 50+ leads with qualification flow')
    console.log('   ✅ Projects: Projects created from qualified clients')
    // console.log('   ✅ Tasks: Tasks and sub-tasks assigned to departments')

    console.log('\n🎭 ROLE HIERARCHY (High to Low):')
    console.log('   1. Super Administrator (Level 10)')
    console.log('   2. Project Manager (Level 9)')
    console.log('   3. HR Manager (Level 8)')
    console.log('   4. Department Head (Level 7)')
    console.log('   5. Team Lead (Level 6)')
    console.log('   6. Senior Executive (Level 5)')
    console.log('   7. Executive (Level 4)')
    console.log('   8. Junior Executive (Level 3)')
    console.log('   9. Intern (Level 2)')
    console.log('   10. Client (Level 1)')

    console.log('\n🏢 BUSINESS DEPARTMENTS:')
    console.log('   • System (Admin/Management)')
    console.log('   • Web Development')
    console.log('   • Graphics')
    console.log('   • SEO (On-Page + Off-Page)')
    console.log('   • Sales')
    console.log('   • Support')
    console.log('   • GMB (Google My Business)')
    console.log('   • Social Media')
    console.log('   • HR')
    console.log('   • Accounting')

    console.log('\n🔐 AUTHENTICATION CREDENTIALS:')
    console.log('   Super Admin: superadmin@gmail.com / SuperAdmin@123')
    console.log('   Project Manager: john.smith@company.com / ProjectManager@123')
    console.log('   HR Manager: lisa.johnson@company.com / HRManager@123')
    console.log('   Department Head: mike.developer@company.com / DeptHead@123')
    console.log('   (+ 28 more users with role-specific credentials)')

    console.log('\n✨ System ready for production use!')
    console.log('✨ Database seeding completed successfully')
    process.exit(0)
  } catch (error) {
    console.error('\n❌ Error during seeding:', error)
    console.error('💡 Make sure MongoDB is running and accessible')
    process.exit(1)
  }
}

export { runSeeders }

// Only run if this file is executed directly (not imported)
if (require.main === module) {
  runSeeders()
}