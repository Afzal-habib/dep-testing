import mongoose from 'mongoose'
import { promises as fs } from 'fs'
import * as path from 'path'
import { modelRegistry, ModelDefinition } from './modelRegistry'

export interface SeedData {
  model: string
  data: any[]
  dependencies?: string[]
  priority?: number
}

export interface SeederDefinition {
  name: string
  description: string
  seeds: SeedData[]
  version: string
}

export class GenericSeedingManager {
  private static instance: GenericSeedingManager
  private seedersDir: string
  private appliedSeeders: Set<string> = new Set()

  private constructor() {
    this.seedersDir = path.join(process.cwd(), 'scripts', 'seeders')
  }

  public static getInstance(): GenericSeedingManager {
    if (!GenericSeedingManager.instance) {
      GenericSeedingManager.instance = new GenericSeedingManager()
    }
    return GenericSeedingManager.instance
  }

  /**
   * Generate seeders for all models
   */
  public async generateModelSeeders(): Promise<void> {
    console.log('🌱 Generating seeders for all models...')

    const models = modelRegistry.getAllModels()

    for (const [modelName, modelDef] of Array.from(models)) {
      await this.generateSeederForModel(modelDef)
    }

    console.log('✅ Seeder files generated for all models')
  }

  /**
   * Generate seeder for a specific model
   */
  private async generateSeederForModel(modelDef: ModelDefinition): Promise<void> {
    const seederFileName = `${modelDef.name.toLowerCase()}Seeder.ts`
    const seederPath = path.join(this.seedersDir, seederFileName)

    // Check if seeder already exists
    try {
      await fs.access(seederPath)
      console.log(`⏭️  Seeder already exists: ${seederFileName}`)
      return
    } catch {
      // File doesn't exist, create it
    }

    const seederContent = this.generateSeederTemplate(modelDef)

    await fs.writeFile(seederPath, seederContent, 'utf-8')
    console.log(`📝 Generated seeder: ${seederFileName}`)
  }

  /**
   * Generate seeder template for a model
   */
  private generateSeederTemplate(modelDef: ModelDefinition): string {
    const { name } = modelDef

    return `import mongoose from 'mongoose'
import { connectDB } from '@/lib/mongodb'

export interface I${name}Seed {
  // Define seed data interface based on your model
  [key: string]: any
}

const ${name.toLowerCase()}Seeds: I${name}Seed[] = [
  // Add your seed data here
  // Example:
  // {
  //   name: 'Sample ${name}',
  //   status: 'active',
  //   // ... other fields
  // }
]

export async function seed${name}(): Promise<{
  success: boolean
  created: number
  updated: number
  skipped: number
  total: number
}> {
  try {
    console.log('🌱 Starting ${name} seeding...')

    await connectDB()

    const ${name}Model = mongoose.models.${name} || mongoose.model('${name}')
    let created = 0
    let updated = 0
    let skipped = 0

    for (const seedData of ${name.toLowerCase()}Seeds) {
      try {
        // Check if record already exists (customize based on your unique fields)
        const existingRecord = await ${name}Model.findOne({
          // Add your unique identifier check here
          // Example: name: seedData.name
        })

        if (existingRecord) {
          // Update existing record
          await ${name}Model.findByIdAndUpdate(existingRecord._id, seedData, {
            new: true,
            runValidators: true
          })
          updated++
        } else {
          // Create new record
          await ${name}Model.create(seedData)
          created++
        }
      } catch (error) {
        console.warn(\`⚠️  Error seeding ${name} record:\`, error)
        skipped++
      }
    }

    const total = created + updated + skipped

    console.log(\`📊 ${name} Seeding Summary:\`)
    console.log(\`   ✅ Created: \${created}\`)
    console.log(\`   📝 Updated: \${updated}\`)
    console.log(\`   ⏭️  Skipped: \${skipped}\`)
    console.log(\`   📊 Total: \${total}\`)

    console.log(\`🎉 ${name} seeding completed successfully!\`)

    return {
      success: true,
      created,
      updated,
      skipped,
      total
    }

  } catch (error: any) {
    console.error(\`❌ Error seeding ${name}:\`, error)
    throw error
  }
}

// Run directly if called as script
if (require.main === module) {
  seed${name}()
    .then((result) => {
      console.log('Seeding result:', result)
      process.exit(0)
    })
    .catch((error) => {
      console.error('Seeding failed:', error)
      process.exit(1)
    })
}

export default seed${name}
`
  }

  /**
   * Run all seeders in dependency order
   */
  public async runAllSeeders(): Promise<void> {
    console.log('🚀 Running all seeders...')

    // Models are registered when imported
    // Get models in dependency order
    const models = modelRegistry.getModelsByDependencyOrder()

    console.log('📋 Seeding models in dependency order:')
    models.forEach((model, index) => {
      console.log(`   ${index + 1}. ${model.name}`)
    })

    let totalCreated = 0
    let totalUpdated = 0
    let totalSkipped = 0

    // Run seeders for each model
    for (const modelDef of models) {
      try {
        const seederPath = path.join(this.seedersDir, `${modelDef.name.toLowerCase()}Seeder.ts`)

        // Check if seeder exists
        try {
          await fs.access(seederPath)
        } catch {
          console.log(`⏭️  No seeder found for ${modelDef.name}, skipping...`)
          continue
        }

        console.log(`🌱 Running seeder for ${modelDef.name}...`)

        const seeder = require(seederPath)
        const seederFunction = seeder[`seed${modelDef.name}`] || seeder.default

        if (typeof seederFunction === 'function') {
          const result = await seederFunction()

          if (result && typeof result === 'object') {
            totalCreated += result.created || 0
            totalUpdated += result.updated || 0
            totalSkipped += result.skipped || 0
          }
        } else {
          console.warn(`⚠️  Invalid seeder function for ${modelDef.name}`)
        }

      } catch (error) {
        console.error(`❌ Error running seeder for ${modelDef.name}:`, error)
        // Continue with other seeders
      }
    }

    console.log(`\n🎉 All seeders completed!`)
    console.log(`📊 Overall Seeding Summary:`)
    console.log(`   ✅ Total Created: ${totalCreated}`)
    console.log(`   📝 Total Updated: ${totalUpdated}`)
    console.log(`   ⏭️  Total Skipped: ${totalSkipped}`)
    console.log(`   📊 Grand Total: ${totalCreated + totalUpdated + totalSkipped}`)
  }

  /**
   * Run a specific seeder
   */
  public async runSeeder(modelName: string): Promise<void> {
    console.log(`🌱 Running seeder for ${modelName}...`)

    const seederPath = path.join(this.seedersDir, `${modelName.toLowerCase()}Seeder.ts`)

    try {
      await fs.access(seederPath)
    } catch {
      throw new Error(`Seeder not found: ${modelName}Seeder.ts`)
    }

    const seeder = require(seederPath)
    const seederFunction = seeder[`seed${modelName}`] || seeder.default

    if (typeof seederFunction === 'function') {
      const result = await seederFunction()
      console.log(`✅ Seeder completed for ${modelName}:`, result)
    } else {
      throw new Error(`Invalid seeder function for ${modelName}`)
    }
  }

  /**
   * Get seeder status
   */
  public async getSeederStatus(): Promise<{
    available: string[]
    models: string[]
  }> {
    const models = Array.from(modelRegistry.getAllModels().keys())

    let available: string[] = []

    for (const modelName of models) {
      const seederPath = path.join(this.seedersDir, `${modelName.toLowerCase()}Seeder.ts`)
      try {
        await fs.access(seederPath)
        available.push(modelName)
      } catch {
        // Seeder doesn't exist
      }
    }

    return {
      available,
      models
    }
  }

  /**
   * Validate seed data
   */
  public async validateSeedData(): Promise<{
    valid: boolean
    errors: Array<{ model: string; error: string }>
  }> {
    const errors: Array<{ model: string; error: string }> = []
    const models = modelRegistry.getAllModels()

    for (const [modelName, modelDef] of Array.from(models)) {
      try {
        const seederPath = path.join(this.seedersDir, `${modelName.toLowerCase()}Seeder.ts`)

        try {
          await fs.access(seederPath)
          const seeder = require(seederPath)

          // Basic validation - check if seeder function exists
          const seederFunction = seeder[`seed${modelName}`] || seeder.default
          if (typeof seederFunction !== 'function') {
            errors.push({
              model: modelName,
              error: 'Seeder function not found or invalid'
            })
          }
        } catch {
          // Seeder doesn't exist - not an error
        }

      } catch (error) {
        errors.push({
          model: modelName,
          error: `Validation error: ${error}`
        })
      }
    }

    return {
      valid: errors.length === 0,
      errors
    }
  }
}

// Export singleton instance
export const seedingManager = GenericSeedingManager.getInstance()

// Convenience functions
export async function runAllSeeders(): Promise<void> {
  await seedingManager.runAllSeeders()
}

export async function runSeeder(modelName: string): Promise<void> {
  await seedingManager.runSeeder(modelName)
}

export async function generateSeeders(): Promise<void> {
  await seedingManager.generateModelSeeders()
}

export async function getSeederStatus() {
  return await seedingManager.getSeederStatus()
}

export async function validateSeeders() {
  return await seedingManager.validateSeedData()
}