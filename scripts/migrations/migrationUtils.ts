import mongoose from 'mongoose'
import { promises as fs } from 'fs'
import path from 'path'
import dotenv from 'dotenv'

// Load environment variables from .env.local
dotenv.config({ path: '.env.local' })

export interface MigrationDoc extends mongoose.Document {
  fileName: string
  appliedAt: Date
}

const MigrationSchema = new mongoose.Schema({
  fileName: { type: String, required: true, unique: true },
  appliedAt: { type: Date, default: Date.now }
})

export const Migration = mongoose.models.Migration || mongoose.model('Migration', MigrationSchema)

export async function connectToDatabase() {
  const MONGODB_URI = process.env.MONGODB_URI
  if (!MONGODB_URI) {
    throw new Error('Please define the MONGODB_URI environment variable')
  }

  try {
    await mongoose.connect(MONGODB_URI)
    console.log('✅ Connected to MongoDB for migration')
  } catch (error) {
    console.error('❌ MongoDB connection error:', error)
    process.exit(1)
  }
}

export async function getMigrationFiles(): Promise<string[]> {
  const migrationsDir = path.join(process.cwd(), 'scripts', 'migrations')
  const files = await fs.readdir(migrationsDir)
  return files.filter(file => 
    file.endsWith('.ts') && 
    !file.includes('migrationUtils') && 
    !file.includes('index')
  ).sort()
}

export async function markMigrationAsApplied(fileName: string) {
  await Migration.create({ fileName })
  console.log(`✅ Marked migration ${fileName} as applied`)
}

export async function getAppliedMigrations(): Promise<string[]> {
  const migrations = await Migration.find().sort({ appliedAt: 1 })
  return migrations.map(migration => migration.fileName)
}

export async function disconnectFromDatabase() {
  await mongoose.disconnect()
  console.log('✅ Disconnected from MongoDB')
}