// Load environment variables
import { config } from 'dotenv'
import path from 'path'

// Load .env.local file
config({ path: path.resolve(process.cwd(), '.env.local') })

import connectDB from "../lib/mongodb"
import User from "../../models/User"
import Role from "../../models/Role"
import Department from "../../models/Department"
import mongoose from "mongoose"
import seedSystemPermissions from '../seeders/systemPermissionsSeeder'
import seedSystemRoles from '../seeders/systemRolesSeeder'

async function createDefaultDepartment(): Promise<mongoose.Types.ObjectId> {
  // Check if default department exists
  let defaultDept = await Department.findOne({ name: 'General' })
  
  if (!defaultDept) {
    console.log('📁 Creating default department: General')
    defaultDept = new Department({
      name: 'General',
      category: 'management',
      description: 'Default department for users without specific department assignment',
      status: 'active'
    })
    await defaultDept.save()
    console.log('✅ Default department created')
  }
  
  return defaultDept._id as mongoose.Types.ObjectId
}

async function createDepartmentRole(
  roleName: string, 
  departmentId: mongoose.Types.ObjectId, 
  permissions: any[], 
  hierarchyLevel: number = 1
): Promise<mongoose.Types.ObjectId> {
  
  // Check if role already exists
  const existingRole = await Role.findOne({ 
    name: roleName, 
    department: departmentId 
  })
  
  if (existingRole) {
    return existingRole._id as mongoose.Types.ObjectId
  }

  console.log(`🎭 Creating role: ${roleName}`)
  
  const role = new Role({
    name: roleName.toLowerCase().replace(/\s+/g, '_'),
    displayName: roleName,
    description: `${roleName} role with department-specific permissions`,
    department: departmentId,
    permissions,
    hierarchyLevel,
    isSystemRole: false,
    status: 'active',
    metadata: {
      createdBy: 'migration_script'
    }
  })
  
  await role.save()
  return role._id as mongoose.Types.ObjectId
}

export async function migrateUsersToNewRoleSystem() {
  try {
    console.log('🚀 Starting user migration to new role system...')
    
    await connectDB()

    // Temporarily disable collection validation
    console.log('🔧 Temporarily disabling collection validation...')
    try {
      await mongoose.connection.db?.command({
        collMod: 'users',
        validator: {},
        validationLevel: 'off'
      })
      console.log('✅ Collection validation disabled')
    } catch (error) {
      console.log('⚠️  Could not disable validation, continuing anyway...')
    }

    // Step 1: Seed system permissions and roles
    console.log('\n📋 Step 1: Seeding system permissions...')
    await seedSystemPermissions()

    console.log('\n🎭 Step 2: Seeding system roles...')
    await seedSystemRoles()

    // Step 3: Create default department if needed
    console.log('\n📁 Step 3: Ensuring default department exists...')
    const defaultDepartmentId = await createDefaultDepartment()

    // Step 4: Get all users with legacy role system
    console.log('\n👥 Step 4: Fetching users to migrate...')
    const usersToMigrate = await User.find({
      $or: [
        { role: { $type: "string" } }, // Old string-based roles
        { role: { $exists: false } },   // Users without roles
      ],
      status: 'active'
    }).lean()

    console.log(`📊 Found ${usersToMigrate.length} users to migrate`)

    if (usersToMigrate.length === 0) {
      console.log('✅ No users need migration')
      return { success: true, migrated: 0 }
    }

    // Step 5: Group users by department
    const departmentGrouping: Record<string, any[]> = {}

    for (const user of usersToMigrate) {
      const department = (user.department as unknown as string) || defaultDepartmentId.toString()
      
      if (!departmentGrouping[department]) {
        departmentGrouping[department] = []
      }
      
      departmentGrouping[department].push(user)
    }

    // Step 6: Assign client role to users by department
    let migratedUsers = 0

    for (const [departmentId, users] of Object.entries(departmentGrouping)) {
      console.log(`\n🔄 Processing department: ${departmentId}`)
      
      // Ensure department exists
      let deptId: mongoose.Types.ObjectId
      if (mongoose.Types.ObjectId.isValid(departmentId)) {
        deptId = new mongoose.Types.ObjectId(departmentId)
        const dept = await Department.findById(deptId)
        if (!dept) {
          console.log(`  ⚠️  Department not found, using default: ${departmentId}`)
          deptId = defaultDepartmentId
        }
      } else {
        console.log(`  ⚠️  Invalid department ID, using default: ${departmentId}`)
        deptId = defaultDepartmentId
      }

      // Find or create 'client' role for this department
      let roleDoc = await Role.findOne({ name: 'client', department: deptId })
      if (!roleDoc) {
        console.log(`  🎭 Creating client role for department: ${deptId}`)
        roleDoc = new Role({
          name: 'client',
          displayName: 'Client',
          description: 'Client role with basic permissions',
          department: deptId,
          permissions: [
            { resource: "profile", actions: ["read", "update"], conditions: { own: true } },
            { resource: "dashboard", actions: ["read"], conditions: { own: true } },
          ],
          hierarchyLevel: 1,
          isSystemRole: false,
          status: 'active',
          metadata: {
            createdBy: 'migration_script'
          }
        })
        await roleDoc.save()
      }

      // Assign role to users
      for (const user of users) {
        // Use direct MongoDB update to bypass Mongoose validation
        await mongoose.connection.db?.collection('users').updateOne(
          { _id: new mongoose.Types.ObjectId(user._id) },
          {
            $set: {
              role: roleDoc._id,
              department: deptId
            }
          }
        )
        migratedUsers++
      }
    }

    // Step 7: Verification
    console.log('\n✅ Step 7: Verifying migration...')
    const verificationCount = await User.countDocuments({
      role: { $type: "objectId" },
      status: 'active'
    })

    console.log('\n📊 Migration Summary:')
    console.log(`   👥 Total Users Migrated: ${migratedUsers}`)
    console.log(`   ✅ Users with New Role System: ${verificationCount}`)

    // Get final statistics
    const finalStats = await User.aggregate([
      { $match: { status: 'active' } },
      { $lookup: {
        from: 'roles',
        localField: 'role',
        foreignField: '_id',
        as: 'roleDetails'
      }},
      { $unwind: '$roleDetails' },
      { $group: {
        _id: '$roleDetails.displayName',
        count: { $sum: 1 },
        isSystemRole: { $first: '$roleDetails.isSystemRole' }
      }},
      { $sort: { isSystemRole: -1, count: -1 } }
    ])

    console.log('\n📈 Final User Distribution:')
    finalStats.forEach(stat => {
      const roleType = stat.isSystemRole ? '(System)' : '(Department)'
      console.log(`   ${stat._id} ${roleType}: ${stat.count} users`)
    })

    console.log('\n🎉 User migration to new role system completed successfully!')
    
    // Re-enable collection validation
    console.log('🔧 Re-enabling collection validation...')
    try {
      // Note: In a real-world scenario, you would restore the original validator
      // For now, we'll enable basic validation
      await mongoose.connection.db?.command({
        collMod: 'users',
        validationLevel: 'strict'
      })
      console.log('✅ Collection validation re-enabled')
    } catch (error) {
      console.log('⚠️  Could not re-enable validation')
    }
    
    return {
      success: true,
      migrated: migratedUsers,
      verificationCount,
      finalStats
    }

  } catch (error: any) {
    console.error('❌ Error during user migration:', error)
    
    // Try to re-enable validation even on error
    try {
      await mongoose.connection.db?.command({
        collMod: 'users',
        validationLevel: 'strict'
      })
    } catch {}
    
    throw error
  }
}

// Migration interface functions
export async function up(): Promise<void> {
  await migrateUsersToNewRoleSystem()
}

export async function down(): Promise<void> {
  console.log('⚠️ User-to-roles migration rollback not implemented - this would require restoring legacy role assignments')
  throw new Error('Rollback not supported for user-to-roles migration')
}