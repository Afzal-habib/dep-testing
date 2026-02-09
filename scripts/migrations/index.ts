import path from 'path'
import dotenv from 'dotenv'
import {
  connectToDatabase,
  disconnectFromDatabase,
  getMigrationFiles,
  getAppliedMigrations,
  markMigrationAsApplied
} from './migrationUtils'

// Load environment variables
dotenv.config()

async function runMigrations() {
  try {
    await connectToDatabase()

    const migrationFiles = await getMigrationFiles()
    const appliedMigrations = await getAppliedMigrations()

    const pendingMigrations = migrationFiles.filter(file => !appliedMigrations.includes(file))

    if (pendingMigrations.length === 0) {
      console.log('✨ No pending migrations')
      await disconnectFromDatabase()
      return
    }

    console.log(`🚀 Running ${pendingMigrations.length} migrations...`)

    for (const migrationFile of pendingMigrations) {
      const migrationPath = path.join(process.cwd(), 'scripts', 'migrations', migrationFile)
      const migration = require(migrationPath)

      try {
        console.log(`⏳ Running migration: ${migrationFile}`)
        await migration.up()
        await markMigrationAsApplied(migrationFile)
        console.log(`✅ Migration completed: ${migrationFile}`)
      } catch (error) {
        console.error(`❌ Error in migration ${migrationFile}:`, error)
        process.exit(1)
      }
    }

    console.log('✨ All migrations completed successfully')
    await disconnectFromDatabase()
  } catch (error) {
    console.error('❌ Migration error:', error)
    process.exit(1)
  }
}


runMigrations()