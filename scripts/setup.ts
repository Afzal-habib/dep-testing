#!/usr/bin/env node

/**
 * Master Setup Script for CRM System
 *
 * This script handles the complete setup process:
 * 1. Model registration and validation
 * 2. Database migrations
 * 3. Data seeding
 *
 * Run with: npm run setup or npx ts-node scripts/setup.ts
 */

import * as dotenv from 'dotenv'
import mongoose from 'mongoose'
import { registerModels } from '../lib/models'
import { validateAllModels, modelRegistry } from '../lib/modelRegistry'
import { runAllMigrations, generateMigrations, getMigrationStatus, migrationManager } from '../lib/genericMigration'
import { runAllSeeders, generateSeeders, getSeederStatus, validateSeeders, seedingManager } from '../lib/genericSeeding'
import connectDB, { executeGenericDbQuery } from '../lib/mongodb'

// Load environment variables
dotenv.config({ path: '.env.local' })

interface SetupOptions {
  migrate?: boolean
  seed?: boolean
  reset?: boolean
  all?: boolean
  migrateNew?: boolean
  seedSingle?: boolean
  skipMigrations?: boolean
  skipSeeders?: boolean
  generateOnly?: boolean
  force?: boolean
  modelName?: string
}

class CRMSetupManager {
  private options: SetupOptions

  constructor(options: SetupOptions = {}) {
    this.options = options
  }

  /**
   * Run the setup process based on options
   */
  async runSetup(): Promise<void> {
    console.log('🚀 CRM Database Setup')
    console.log('=' .repeat(40))

    try {
      // Connect to database
      console.log('\n📡 Connecting to database...')
      await connectDB()
      console.log('✅ Database connected successfully')

      // Register and validate models
      console.log('\n📋 Registering models...')
      await registerModels()

      // Handle different modes
      if (this.options.all) {
        await this.runFullSetup()
      } else if (this.options.reset) {
        await this.resetDatabase()
      } else if (this.options.migrate) {
        await this.runMigrationsOnly()
      } else if (this.options.seed) {
        await this.runSeedersOnly()
      } else if (this.options.migrateNew) {
        await this.migrateNewModels()
      } else if (this.options.seedSingle) {
        await this.seedSingleModel()
      } else if (this.options.generateOnly) {
        await this.generateFilesOnly()
      } else {
        // Default to full setup if no specific option
        await this.runFullSetup()
      }

      console.log('\n' + '=' .repeat(40))
      console.log('🎉 Operation completed successfully!')
      console.log('=' .repeat(40))

    } catch (error) {
      console.error('\n❌ Setup failed:', error)
      console.error('\n💡 Troubleshooting tips:')
      console.error('   • Make sure MongoDB is running')
      console.error('   • Check your .env.local file has correct MONGODB_URI')
      console.error('   • Ensure all dependencies are installed')
      process.exit(1)
    } finally {
      await mongoose.connection.close()
    }
  }

  /**
   * Run full setup (migrate + seed)
   */
  private async runFullSetup(): Promise<void> {
    console.log('\n🗄️  Running migrations...')
    await this.setupMigrations()

    console.log('\n🌱 Running seeders...')
    await this.setupSeeders()

    console.log('\n✅ Final validation...')
    await this.finalValidation()
  }

  /**
   * Reset database (drop all collections and rerun migrations/seeders)
   */
  private async resetDatabase(): Promise<void> {
    console.log('\n🔄 Resetting database...')

    // Drop all collections except system collections
    const db = mongoose.connection.db
    if (db) {
      const collections = await db.listCollections().toArray()
      for (const collection of collections) {
        if (!collection.name.startsWith('system.')) {
          console.log(`🗑️  Dropping collection: ${collection.name}`)
          await db.dropCollection(collection.name)
        }
      }
    }

    // Clear migration tracking
    try {
      const MigrationModel = mongoose.models.Migration ||
        mongoose.model('Migration', new mongoose.Schema({
          fileName: { type: String, required: true, unique: true },
          appliedAt: { type: Date, default: Date.now }
        }))
      await MigrationModel.deleteMany({})
      console.log('🗑️  Cleared migration tracking')
    } catch (error) {
      console.warn('⚠️  Could not clear migration tracking:', error)
    }

    console.log('\n🗄️  Running migrations...')
    await this.setupMigrations()

    console.log('\n🌱 Running seeders...')
    await this.setupSeeders()

    console.log('\n✅ Database reset and setup completed!')
  }

  /**
   * Run migrations only
   */
  private async runMigrationsOnly(): Promise<void> {
    console.log('\n🗄️  Running migrations...')
    await this.setupMigrations()
  }

  /**
   * Run seeders only
   */
  private async runSeedersOnly(): Promise<void> {
    console.log('\n🌱 Running seeders...')
    await this.setupSeeders()
  }

  /**
   * Migrate new models only (models without existing migrations)
   */
  private async migrateNewModels(): Promise<void> {
    console.log('\n🆕 Migrating new models...')

    const models = modelRegistry.getAllModels()
    const appliedMigrations = await this.getAppliedMigrations()
    const newModels: string[] = []

    for (const modelName of Array.from(models.keys())) {
      const migrationFile = `${Date.now()}_${modelName.toLowerCase()}_migration.ts`
      if (!appliedMigrations.some(m => m.includes(modelName.toLowerCase()))) {
        newModels.push(modelName)
      }
    }

    if (newModels.length === 0) {
      console.log('✅ No new models to migrate')
      return
    }

    console.log(`📋 Found ${newModels.length} new models:`, newModels)

    // Generate and run migrations for new models
    await migrationManager.generateModelMigrations()
    await migrationManager.runMigrations()
  }

  /**
   * Seed a single model
   */
  private async seedSingleModel(): Promise<void> {
    if (!this.options.modelName) {
      console.error('❌ Model name required for single seeding. Use: --seed-single ModelName')
      process.exit(1)
    }

    const modelName = this.options.modelName
    console.log(`\n🌱 Seeding single model: ${modelName}...`)

    try {
      await seedingManager.runSeeder(modelName)
    } catch (error) {
      console.error(`❌ Failed to seed ${modelName}:`, error)
      throw error
    }
  }

  /**
   * Generate files only
   */
  private async generateFilesOnly(): Promise<void> {
    console.log('\n📝 Generating migration and seeder files...')

    console.log('Generating migrations...')
    await migrationManager.generateModelMigrations()

    console.log('Generating seeders...')
    await seedingManager.generateModelSeeders()

    console.log('✅ Files generated successfully!')
  }

  /**
   * Get list of applied migrations
   */
  private async getAppliedMigrations(): Promise<string[]> {
    try {
      const MigrationModel = mongoose.models.Migration ||
        mongoose.model('Migration', new mongoose.Schema({
          fileName: { type: String, required: true, unique: true },
          appliedAt: { type: Date, default: Date.now }
        }))

      const applied = await (MigrationModel as any).find({}, 'fileName')
      return applied.map((m: any) => m.fileName)
    } catch (error) {
      console.warn('⚠️  Could not retrieve applied migrations:', error)
      return []
    }
  }

  /**
   * Setup database migrations
   */
  private async setupMigrations(): Promise<void> {
    if (this.options.generateOnly) {
      console.log('📝 Generating migration files...')
      await generateMigrations()
      console.log('✅ Migration files generated')
      return
    }

    // Check migration status
    const status = await getMigrationStatus()
    console.log(`📊 Migration Status: ${status.pending} pending, ${status.applied} applied`)

    if (status.pending > 0) {
      console.log('⏳ Running migrations...')
      await runAllMigrations()

      // Verify migrations
      const finalStatus = await getMigrationStatus()
      if (finalStatus.pending > 0) {
        throw new Error(`${finalStatus.pending} migrations failed to apply`)
      }

      console.log('✅ All migrations completed successfully')
    } else {
      console.log('✅ No pending migrations')
    }
  }

  /**
   * Setup data seeders
   */
  private async setupSeeders(): Promise<void> {
    if (this.options.generateOnly) {
      console.log('📝 Generating seeder files...')
      await generateSeeders()
      console.log('✅ Seeder files generated')
      return
    }

    // For full setup, use comprehensive seeding with correct order
    if (this.options.all || this.options.reset) {
      console.log('🚀 Running comprehensive database seeding...')
      try {
        const { runSeeders } = await import('../scripts/seeders/index')
        await runSeeders()
        console.log('✅ Comprehensive seeding completed successfully')
      } catch (error) {
        console.error('❌ Comprehensive seeding failed:', error)
        throw error
      }
      return
    }

    // For individual seeding, use generic seeding system
    const status = await getSeederStatus()
    console.log(`📊 Seeder Status: ${status.available.length} available, ${status.models.length} total models`)

    if (status.available.length > 0) {
      console.log('⏳ Running seeders...')
      await runAllSeeders()
      console.log('✅ All seeders completed successfully')
    } else {
      console.log('⚠️  No seeders available. Run with --generate-only to create them.')
    }
  }

  /**
   * Final validation of the setup
   */
  private async finalValidation(): Promise<void> {
    // Validate seeders
    const seederValidation = await validateSeeders()
    if (!seederValidation.valid) {
      console.warn('⚠️  Seeder validation warnings:')
      seederValidation.errors.forEach(error =>
        console.warn(`   • ${error.model}: ${error.error}`)
      )
    }

    // Basic database connectivity test
    try {
      const mongoose = require('mongoose')
      const db = mongoose.connection.db
      if (db) {
        const stats = await db.stats()
        console.log(`✅ Database validation passed (${stats.collections} collections)`)
      }
    } catch (error) {
      console.warn('⚠️  Database validation warning:', error)
    }

    console.log('✅ Setup validation completed')
  }

  /**
   * Get setup status
   */
  async getStatus(): Promise<{
    models: { valid: boolean; errors: string[] }
    migrations: any
    seeders: any
  }> {
    await connectDB()

    try {
      const models = validateAllModels()
      const migrations = await getMigrationStatus()
      const seeders = await getSeederStatus()

      return {
        models,
        migrations,
        seeders
      }
    } finally {
      await mongoose.connection.close()
    }
  }
}

// CLI Interface
async function main() {
  const args = process.argv.slice(2)
  const options: SetupOptions = {}

  // Parse command line arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    switch (arg) {
      case '--migrate':
        options.migrate = true
        break
      case '--seed':
        options.seed = true
        break
      case '--reset':
        options.reset = true
        break
      case '--all':
        options.all = true
        break
      case '--migrate-new':
        options.migrateNew = true
        break
      case '--seed-single':
        options.seedSingle = true
        if (args[i + 1] && !args[i + 1].startsWith('--')) {
          options.modelName = args[i + 1]
          i++ // Skip next arg as it's the model name
        }
        break
      case '--skip-migrations':
        options.skipMigrations = true
        break
      case '--skip-seeders':
        options.skipSeeders = true
        break
      case '--generate-only':
        options.generateOnly = true
        break
      case '--force':
        options.force = true
        break
      case '--help':
      case '-h':
        showHelp()
        return
      case '--status':
        await showStatus()
        return
      default:
        console.error(`Unknown option: ${arg}`)
        showHelp()
        process.exit(1)
    }
  }

  const setup = new CRMSetupManager(options)
  await setup.runSetup()
}

function showHelp() {
  console.log(`
CRM System Setup Script

Usage: npm run setup [options]

Options:
  --skip-migrations    Skip running database migrations
  --skip-seeders       Skip running data seeders
  --generate-only      Only generate migration/seeder files, don't run them
  --force              Force operations (use with caution)
  --status             Show current setup status
  --help, -h           Show this help message

Examples:
  npm run setup                          # Full setup
  npm run setup --generate-only          # Generate files only
  npm run setup --skip-seeders           # Setup without seeding
  npm run setup --status                 # Check current status
`)
}

async function showStatus() {
  try {
    const setup = new CRMSetupManager()
    const status = await setup.getStatus()

    console.log('📊 CRM Setup Status')
    console.log('=' .repeat(30))

    console.log('\n📋 Models:')
    if (status.models.valid) {
      console.log('   ✅ All models valid')
    } else {
      console.log('   ❌ Model validation errors:')
      status.models.errors.forEach(error => console.log(`      • ${error}`))
    }

    console.log('\n🗄️  Migrations:')
    console.log(`   📊 Total: ${status.migrations.total}`)
    console.log(`   ✅ Applied: ${status.migrations.applied}`)
    console.log(`   ⏳ Pending: ${status.migrations.pending}`)

    console.log('\n🌱 Seeders:')
    console.log(`   📊 Available: ${status.seeders.available.length}`)
    console.log(`   📊 Total Models: ${status.seeders.models.length}`)

    if (status.seeders.available.length > 0) {
      console.log('   📝 Available seeders:')
      status.seeders.available.forEach((seeder: string) => console.log(`      • ${seeder}`))
    }

  } catch (error) {
    console.error('❌ Failed to get status:', error)
    process.exit(1)
  }
}

// Run the setup if this script is called directly
if (require.main === module) {
  main().catch((error) => {
    console.error('❌ Setup script failed:', error)
    process.exit(1)
  })
}

export default CRMSetupManager