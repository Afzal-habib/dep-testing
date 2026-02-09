/**
 * Script to initialize default system settings
 * Run this to set up initial theme and system configurations
 */

import connectDB from '../lib/mongodb'
import Settings from '../models/Settings'

async function initializeSettings() {
  try {
    console.log('🔧 Initializing system settings...')
    
    await connectDB()
    
    // Default settings to create
    const defaultSettings = [
      {
        key: 'theme_variant',
        value: 'default',
        description: 'Current active theme variant for the system',
        category: 'appearance',
        isPublic: true
      },
      {
        key: 'system_name',
        value: 'DIGI ERA PRO CRM',
        description: 'System name displayed throughout the application',
        category: 'general',
        isPublic: true
      },
      {
        key: 'maintenance_mode',
        value: false,
        description: 'Enable maintenance mode to prevent user access',
        category: 'system', 
        isPublic: false
      },
      {
        key: 'max_login_attempts',
        value: 5,
        description: 'Maximum number of failed login attempts before account lockout',
        category: 'security',
        isPublic: false
      },
      {
        key: 'session_timeout',
        value: 3600, // 1 hour in seconds
        description: 'Session timeout duration in seconds',
        category: 'security',
        isPublic: false
      },
      {
        key: 'password_min_length',
        value: 8,
        description: 'Minimum password length requirement',
        category: 'security',
        isPublic: false
      },
      {
        key: 'enable_email_notifications',
        value: true,
        description: 'Enable system-wide email notifications',
        category: 'notifications',
        isPublic: false
      },
      {
        key: 'backup_frequency',
        value: 'daily',
        description: 'Automated backup frequency (daily, weekly, monthly)',
        category: 'system',
        isPublic: false
      }
    ]

    const systemUser = 'system@depllc.com'
    let createdCount = 0
    let updatedCount = 0

    for (const settingData of defaultSettings) {
      try {
        const existingSetting = await Settings.findOne({ key: settingData.key })
        
        if (existingSetting) {
          // Update existing setting but preserve user-modified values
          if (settingData.key === 'theme_variant' && existingSetting.value) {
            console.log(`⏭️ Skipping ${settingData.key} - already configured`)
            continue
          }
          
          await Settings.findOneAndUpdate(
            { key: settingData.key },
            {
              description: settingData.description,
              category: settingData.category,
              isPublic: settingData.isPublic,
              'metadata.updatedBy': systemUser,
              'metadata.updatedAt': new Date()
            }
          )
          updatedCount++
          console.log(`✅ Updated setting: ${settingData.key}`)
        } else {
          // Create new setting
          const newSetting = new Settings({
            ...settingData,
            metadata: {
              createdBy: systemUser,
              updatedBy: systemUser,
              createdAt: new Date(),
              updatedAt: new Date()
            }
          })
          
          await newSetting.save()
          createdCount++
          console.log(`🆕 Created setting: ${settingData.key}`)
        }
      } catch (error: any) {
        if (error.code === 11000) {
          console.log(`⚠️ Setting ${settingData.key} already exists`)
        } else {
          console.error(`❌ Error processing setting ${settingData.key}:`, error.message)
        }
      }
    }

    console.log('\n📊 Settings initialization completed:')
    console.log(`   • Created: ${createdCount} settings`)
    console.log(`   • Updated: ${updatedCount} settings`)
    console.log(`   • Total processed: ${defaultSettings.length} settings`)
    
    // Verify theme setting
    const themeSetting = await Settings.findOne({ key: 'theme_variant' })
    if (themeSetting) {
      console.log(`\n🎨 Active theme: ${themeSetting.value}`)
    }

    console.log('\n✨ System settings initialization complete!')
    
  } catch (error) {
    console.error('❌ Error initializing settings:', error)
    process.exit(1)
  }
}

// Run the initialization if this script is called directly
if (require.main === module) {
  initializeSettings()
    .then(() => {
      console.log('🎉 Initialization script completed successfully')
      process.exit(0)
    })
    .catch((error) => {
      console.error('💥 Initialization script failed:', error)
      process.exit(1)
    })
}

export default initializeSettings