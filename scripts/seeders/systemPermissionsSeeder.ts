// Load environment variables
import { config } from 'dotenv'
import path from 'path'

// Load .env.local file
config({ path: path.resolve(process.cwd(), '.env.local') })

import connectDB from "../lib/mongodb"
import SystemPermission from "../../models/SystemPermission"
import { getAllComprehensivePermissions } from "../../lib/constants/permissions"

// Generate system permissions from centralized definitions
const getSystemPermissionsFromCentralized = () => {
  return getAllComprehensivePermissions().map(permission => ({
    resource: permission.resource,
    displayName: permission.displayName || permission.resource,
    description: permission.description || `Manage ${permission.resource}`,
    category: permission.category,
    availableActions: permission.availableActions || [],
    isCore: permission.isCore || false,
    status: 'active' as const
  }))
}

export async function seedSystemPermissions() {
  try {
    console.log('🌱 Starting system permissions seeding...')
    
    await connectDB()

    // Get permissions from centralized definitions
    const systemPermissions = getSystemPermissionsFromCentralized()
    console.log(`📋 Found ${systemPermissions.length} permissions in centralized definitions`)

    // Get existing permissions
    const existingPermissions = await SystemPermission.find({}).lean()
    const existingResources = new Set(existingPermissions.map(p => p.resource))

    let created = 0
    let updated = 0
    let skipped = 0

    for (const permissionData of systemPermissions) {
      if (existingResources.has(permissionData.resource)) {
        // Update existing permission
        const existing = existingPermissions.find(p => p.resource === permissionData.resource)
        if (existing) {
          // Only update if there are meaningful changes
          const hasChanges = 
            existing.displayName !== permissionData.displayName ||
            existing.description !== permissionData.description ||
            JSON.stringify(existing.availableActions) !== JSON.stringify(permissionData.availableActions)

          if (hasChanges) {
            await SystemPermission.findByIdAndUpdate(existing._id, {
              ...permissionData,
              'metadata.updatedBy': 'system_seeder',
              'metadata.version': '2.0.0'
            })
            updated++
            console.log(`📝 Updated permission: ${permissionData.resource}`)
          } else {
            skipped++
            console.log(`⏭️  Skipped permission (no changes): ${permissionData.resource}`)
          }
        }
      } else {
        // Create new permission
        const permission = new SystemPermission({
          ...permissionData,
          metadata: {
            createdBy: 'system_seeder',
            version: '1.0.0'
          }
        })
        await permission.save()
        created++
        console.log(`✅ Created permission: ${permissionData.resource}`)
      }
    }

    // Summary
    console.log('\n📊 System Permissions Seeding Summary:')
    console.log(`✅ Created: ${created}`)
    console.log(`📝 Updated: ${updated}`)
    console.log(`⏭️  Skipped: ${skipped}`)
    console.log(`📊 Total Permissions: ${created + updated + skipped}`)

    // Get category statistics
    const categoryStats = await SystemPermission.aggregate([
      { $match: { status: 'active' } },
      { $group: {
        _id: '$category',
        count: { $sum: 1 },
        coreCount: { $sum: { $cond: ['$isCore', 1, 0] } }
      }},
      { $sort: { _id: 1 } }
    ])

    console.log('\n📋 Permissions by Category:')
    categoryStats.forEach(stat => {
      console.log(`   ${stat._id}: ${stat.count} (${stat.coreCount} core)`)
    })

    console.log('\n🎉 System permissions seeding completed successfully!')
    return {
      success: true,
      created,
      updated,
      skipped,
      total: created + updated + skipped,
      categoryStats
    }

  } catch (error: any) {
    console.error('❌ Error seeding system permissions:', error)
    throw error
  }
}

// Run directly if called as script
if (require.main === module) {
  seedSystemPermissions()
    .then(() => {
      console.log('Seeding completed!')
      process.exit(0)
    })
    .catch((error) => {
      console.error('Seeding failed:', error)
      process.exit(1)
    })
}

export default seedSystemPermissions