import mongoose from 'mongoose'
import { promises as fs } from 'fs'
import * as path from 'path'
import { modelRegistry, ModelDefinition } from './modelRegistry'

export interface MigrationStep {
  version: string
  description: string
  up: (db: mongoose.Connection) => Promise<void>
  down: (db: mongoose.Connection) => Promise<void>
}

export interface ModelMigration {
  modelName: string
  steps: MigrationStep[]
}

export class GenericMigrationManager {
  private static instance: GenericMigrationManager
  private migrationsDir: string
  private appliedMigrations: Set<string> = new Set()

  private constructor() {
    this.migrationsDir = path.join(process.cwd(), 'scripts', 'migrations')
  }

  public static getInstance(): GenericMigrationManager {
    if (!GenericMigrationManager.instance) {
      GenericMigrationManager.instance = new GenericMigrationManager()
    }
    return GenericMigrationManager.instance
  }

  /**
   * Generate migration files for all models
   */
  public async generateModelMigrations(): Promise<void> {
    console.log('🔧 Generating migrations for all models...')

    const models = modelRegistry.getAllModels()

    for (const [modelName, modelDef] of Array.from(models)) {
      await this.generateMigrationForModel(modelDef)
    }

    console.log('✅ Migration files generated for all models')
  }

  /**
   * Generate migration for a specific model
   */
  private async generateMigrationForModel(modelDef: ModelDefinition): Promise<void> {
    const migrationFileName = `${Date.now()}_${modelDef.name.toLowerCase()}_migration.ts`
    const migrationPath = path.join(this.migrationsDir, migrationFileName)

    const migrationContent = this.generateMigrationTemplate(modelDef)

    await fs.writeFile(migrationPath, migrationContent, 'utf-8')
    console.log(`📝 Generated migration: ${migrationFileName}`)
  }

  /**
   * Generate migration template for a model
   */
  private generateMigrationTemplate(modelDef: ModelDefinition): string {
    const { name, schema } = modelDef

    return `import mongoose from 'mongoose'
import { MigrationStep } from '@/lib/genericMigration'

const migration: MigrationStep = {
  version: '${modelDef.version}',
  description: 'Initial migration for ${name} model',

  up: async (db: mongoose.Connection) => {
    console.log('⬆️  Running migration up for ${name}...')

    // Create collection if it doesn't exist
    const collections = await db.listCollections({ name: '${name.toLowerCase()}s' }).toArray()
    if (collections.length === 0) {
      console.log('📁 Creating collection: ${name.toLowerCase()}s')

      // Define indexes based on schema
      const indexes = []

      // Add indexes from schema paths
      ${this.generateIndexCreationCode(schema)}

      // Create collection with indexes
      await db.createCollection('${name.toLowerCase()}s')

      // Create indexes
      for (const index of indexes) {
        try {
          await db.collection('${name.toLowerCase()}s').createIndex(index.key, index.options)
          console.log('✅ Created index:', index.name || 'unnamed')
        } catch (error) {
          console.warn('⚠️  Index creation failed:', error)
        }
      }
    }

    console.log('✅ Migration up completed for ${name}')
  },

  down: async (db: mongoose.Connection) => {
    console.log('⬇️  Running migration down for ${name}...')

    // Drop collection
    try {
      await db.dropCollection('${name.toLowerCase()}s')
      console.log('🗑️  Dropped collection: ${name.toLowerCase()}s')
    } catch (error) {
      console.warn('⚠️  Collection drop failed (may not exist):', error)
    }

    console.log('✅ Migration down completed for ${name}')
  }
}

export const up = migration.up
export const down = migration.down
`
  }

  /**
   * Generate index creation code from schema
   */
  private generateIndexCreationCode(schema: mongoose.Schema): string {
    let indexCode = ''

    schema.eachPath((pathname, schematype) => {
      if (schematype.options?.index) {
        const indexOptions = schematype.options.index
        const indexName = typeof indexOptions === 'object' && indexOptions.name
          ? indexOptions.name
          : `${pathname}_index`

        indexCode += `      indexes.push({
        key: { ${pathname}: 1 },
        options: {
          name: '${indexName}',
          unique: ${schematype.options?.unique || false},
          sparse: ${schematype.options?.sparse || false}
        }
      })\n`
      }
    })

    // Add compound indexes if defined
    const schemaIndexes = schema.indexes()
    if (schemaIndexes && schemaIndexes.length > 0) {
      for (const [indexDef, options] of schemaIndexes) {
        indexCode += `      indexes.push({
        key: ${JSON.stringify(indexDef)},
        options: ${JSON.stringify(options)}
      })\n`
      }
    }

    return indexCode || '      // No indexes defined'
  }

  /**
   * Run all pending migrations
   */
  public async runMigrations(): Promise<void> {
    console.log('🚀 Running all pending migrations...')

    // Models are registered when imported
    const migrationFiles = await this.getMigrationFiles()
    const appliedMigrations = await this.getAppliedMigrations()

    const pendingMigrations = migrationFiles.filter(file =>
      !appliedMigrations.includes(file)
    )

    if (pendingMigrations.length === 0) {
      console.log('✨ No pending migrations')
      return
    }

    console.log(`📋 Found ${pendingMigrations.length} pending migrations`)

    const db = mongoose.connection

    for (const migrationFile of pendingMigrations) {
      try {
        console.log(`⏳ Running migration: ${migrationFile}`)

        const migrationPath = path.join(this.migrationsDir, migrationFile)
        const migration = require(migrationPath)

        if (migration.up) {
          await migration.up(db)
        }

        await this.markMigrationAsApplied(migrationFile)
        console.log(`✅ Migration completed: ${migrationFile}`)

      } catch (error) {
        console.error(`❌ Error in migration ${migrationFile}:`, error)
        throw error
      }
    }

    console.log('🎉 All migrations completed successfully')
  }

  /**
   * Rollback last migration
   */
  public async rollbackLastMigration(): Promise<void> {
    console.log('🔄 Rolling back last migration...')

    const appliedMigrations = await this.getAppliedMigrations()

    if (appliedMigrations.length === 0) {
      console.log('⚠️  No migrations to rollback')
      return
    }

    const lastMigration = appliedMigrations[appliedMigrations.length - 1]
    console.log(`📋 Rolling back: ${lastMigration}`)

    const db = mongoose.connection

    try {
      const migrationPath = path.join(this.migrationsDir, lastMigration)
      const migration = require(migrationPath)

      if (migration.down) {
        await migration.down(db)
      }

      await this.unmarkMigrationAsApplied(lastMigration)
      console.log(`✅ Rollback completed: ${lastMigration}`)

    } catch (error) {
      console.error(`❌ Error rolling back migration ${lastMigration}:`, error)
      throw error
    }
  }

  /**
   * Get all migration files
   */
  private async getMigrationFiles(): Promise<string[]> {
    try {
      const files = await fs.readdir(this.migrationsDir)
      return files.filter(file =>
        file.endsWith('.ts') &&
        !file.includes('migrationUtils') &&
        !file.includes('index') &&
        !file.includes('genericMigration')
      ).sort()
    } catch (error) {
      console.warn('⚠️  Migrations directory not found, creating it...')
      await fs.mkdir(this.migrationsDir, { recursive: true })
      return []
    }
  }

  /**
   * Get applied migrations from database
   */
  private async getAppliedMigrations(): Promise<string[]> {
    try {
      const MigrationSchema = new mongoose.Schema({
        fileName: { type: String, required: true, unique: true },
        appliedAt: { type: Date, default: Date.now }
      })
      const MigrationModel = mongoose.models.Migration || mongoose.model('Migration', MigrationSchema)

      const migrations = await (MigrationModel as any).find().sort({ appliedAt: 1 })
      return migrations.map((m: any) => m.fileName)
    } catch (error) {
      console.warn('⚠️  Could not get applied migrations:', error)
      return []
    }
  }

  /**
   * Mark migration as applied
   */
  private async markMigrationAsApplied(fileName: string): Promise<void> {
    const MigrationSchema = new mongoose.Schema({
      fileName: { type: String, required: true, unique: true },
      appliedAt: { type: Date, default: Date.now }
    })
    const MigrationModel = mongoose.models.Migration || mongoose.model('Migration', MigrationSchema)

    await (MigrationModel as any).create({ fileName })
  }

  /**
   * Unmark migration as applied
   */
  private async unmarkMigrationAsApplied(fileName: string): Promise<void> {
    const MigrationSchema = new mongoose.Schema({
      fileName: { type: String, required: true, unique: true },
      appliedAt: { type: Date, default: Date.now }
    })
    const MigrationModel = mongoose.models.Migration || mongoose.model('Migration', MigrationSchema)

    await MigrationModel.deleteOne({ fileName })
  }

  /**
   * Get migration status
   */
  public async getMigrationStatus(): Promise<{
    total: number
    applied: number
    pending: number
    migrations: Array<{ file: string; applied: boolean }>
  }> {
    const migrationFiles = await this.getMigrationFiles()
    const appliedMigrations = await this.getAppliedMigrations()

    const migrations = migrationFiles.map(file => ({
      file,
      applied: appliedMigrations.includes(file)
    }))

    return {
      total: migrationFiles.length,
      applied: appliedMigrations.length,
      pending: migrationFiles.length - appliedMigrations.length,
      migrations
    }
  }
}

// Export singleton instance
export const migrationManager = GenericMigrationManager.getInstance()

// Convenience functions
export async function runAllMigrations(): Promise<void> {
  await migrationManager.runMigrations()
}

export async function generateMigrations(): Promise<void> {
  await migrationManager.generateModelMigrations()
}

export async function rollbackMigration(): Promise<void> {
  await migrationManager.rollbackLastMigration()
}

export async function getMigrationStatus() {
  return await migrationManager.getMigrationStatus()
}