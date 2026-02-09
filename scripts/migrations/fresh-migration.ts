import dotenv from 'dotenv'
import mongoose from 'mongoose'
import  seedDepartments from '../seeders/departmentSeeder'
import connectDB from '../lib/mongodb'
import Department from '../../models/Department'
import User from '../../models/User'
import Role from '../../models/Role'
import seedSystemPermissions from '../seeders/systemPermissionsSeeder'
import seedSystemRoles from '../seeders/systemRolesSeeder'

// Load environment variables
dotenv.config({ path: '.env.local' })

export async function freshMigration() {
  try {
    console.log('🚀 Starting fresh migration to new role system...')
    
    // Connect to database - it's already connected via the import
    console.log('📡 Database connected successfully')

    // Step 1: Backup existing users
    console.log('\n💾 Step 1: Backing up existing users...')
    const legacyUsers = await mongoose.connection.db?.collection('users').find({}).toArray() as any[]
    console.log(`📊 Found ${legacyUsers?.length || 0} users to migrate`)

    // Step 2: Setup permissions first
    console.log('\n📋 Step 2: Setting up system permissions...')
    await seedSystemPermissions()

    // Step 3: Setup departments
    console.log('\n📁 Step 3: Setting up departments...')
    await seedDepartments()

    // Step 4: Setup roles (now that departments exist)
    console.log('\n🎭 Step 4: Setting up system and department roles...')
    await seedSystemRoles()

    // Step 5: Ensure default department (backup)
    console.log('\n📁 Step 5: Ensuring default department exists...')
    let defaultDepartment = await Department.findOne({ name: 'General' })
    if (!defaultDepartment) {
      defaultDepartment = await Department.create({
        name: 'General',
        category: 'management',
        description: 'Default department for users without specific department assignment',  
        status: 'active',
        metadata: {
          isDefault: true,
          createdBy: 'system',
          notes: 'Auto-created during role system migration'
        }
      })
      console.log('✅ Default department created')
    } else {
      console.log('✅ Default department exists')
    }

    // Step 6: Get system role
    const superAdminRole = await Role.findOne({ name: 'super_admin', isSystemRole: true, status: 'active' })
    if (!superAdminRole) {
      throw new Error('Super admin role not found')
    }

    // Step 7: Drop and recreate users collection
    console.log('\n🗑️  Step 7: Dropping existing users collection...')
    await mongoose.connection.db?.collection('users').drop()
    console.log('✅ Users collection dropped')

    // Step 8: Create new users collection with new schema
    console.log('\n📝 Step 8: Creating users with new schema...')
    
    let migratedCount = 0
    
    if (legacyUsers && legacyUsers.length > 0) {
      for (const legacyUser of legacyUsers) {
        try {
          // Map department
          let departmentId = defaultDepartment._id
          if (legacyUser.department && legacyUser.department !== 'Administration') {
            const dept = await Department.findOne({ name: legacyUser.department })
            if (dept) {
              departmentId = dept._id
            }
          }

          // Assign super admin role to all users in fresh migration
          let roleId = superAdminRole._id

          const newUser = new User({
            name: legacyUser.name,
            email: legacyUser.email,
            password: legacyUser.password,
            role: roleId,
            department: departmentId,
            avatar: legacyUser.avatar || '',
            phone: legacyUser.phone || '',
            status: legacyUser.status || 'active',
            emailVerified: legacyUser.emailVerified || false,
            phoneVerified: legacyUser.phoneVerified || false,
            twoFactorEnabled: legacyUser.twoFactorEnabled || false,
            permissions: legacyUser.permissions || [],
            metadata: legacyUser.metadata || {
              tags: []
            },
            createdAt: legacyUser.createdAt,
            updatedAt: new Date(),
            passwordChangedAt: legacyUser.passwordChangedAt
          })

          await newUser.save()
          migratedCount++
          
          console.log(`✅ Migrated user: ${legacyUser.email} (${legacyUser.role} -> ${legacyUser.role === 'admin' ? 'super_admin' : legacyUser.role})`)
        } catch (error) {
          console.error(`❌ Failed to migrate user ${legacyUser.email}:`, error)
        }
      }
    }

    console.log(`\n🎉 Fresh migration completed successfully!`)
    console.log(`📊 Migrated ${migratedCount} users`)
    
    return {
      success: true,
      migrated: migratedCount,
      total: legacyUsers?.length || 0
    }

  } catch (error: any) {
    console.error('❌ Error during fresh migration:', error)
    throw error
  }
}

// Migration interface functions
export async function up(): Promise<void> {
  await freshMigration()
}

export async function down(): Promise<void> {
  console.log('⚠️ Fresh migration rollback not implemented - this would require careful data restoration')
  throw new Error('Rollback not supported for fresh migration')
}