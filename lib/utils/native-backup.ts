import fs from 'fs/promises'
import path from 'path'
import { MongoClient } from 'mongodb'
import { BackupConfig, ManualBackupRequest, RestoreRequest } from '@/lib/validations/backup'

// Native MongoDB backup using JavaScript API
export class NativeBackupService {
  private connectionUri: string
  private databaseName: string

  constructor() {
    this.connectionUri = process.env.MONGODB_URI!
    if (!this.connectionUri) {
      throw new Error('MONGODB_URI environment variable is not set')
    }

    // Extract database name from URI
    try {
      const url = new URL(this.connectionUri)
      this.databaseName = url.pathname.slice(1).split('?')[0]
    } catch (error) {
      throw new Error('Invalid MONGODB_URI format')
    }
  }

  // Get MongoDB client connection
  private async getClient(): Promise<MongoClient> {
    const client = new MongoClient(this.connectionUri)
    await client.connect()
    return client
  }

  // Get all collections in the database
  async getCollections(): Promise<string[]> {
    const client = await this.getClient()
    try {
      const db = client.db(this.databaseName)
      const collections = await db.listCollections().toArray()
      return collections.map(col => col.name)
    } finally {
      await client.close()
    }
  }

  // Export collection data to JSON
  private async exportCollectionData(client: MongoClient, collectionName: string): Promise<any[]> {
    const db = client.db(this.databaseName)
    const collection = db.collection(collectionName)

    // Get all documents from collection
    const documents = await collection.find({}).toArray()
    return documents
  }

  // Import collection data from JSON
  private async importCollectionData(
    client: MongoClient,
    collectionName: string,
    documents: any[],
    dropExisting: boolean = false
  ): Promise<void> {
    const db = client.db(this.databaseName)
    const collection = db.collection(collectionName)

    if (dropExisting) {
      await collection.deleteMany({})
    }

    if (documents.length > 0) {
      await collection.insertMany(documents)
    }
  }

  // Create backup using native JavaScript
  async createBackup(config: ManualBackupRequest): Promise<{
    success: boolean
    filePath?: string
    error?: string
    details?: any
  }> {
    try {
      const client = await this.getClient()

      try {
        // Generate backup info
        const timestamp = config.generateTimestamp ?
          new Date().toISOString().replace(/[:.]/g, '-') : ''
        const backupName = config.backupName || 'mongodb-backup'
        const fileName = timestamp ? `${backupName}_${timestamp}.json` : `${backupName}.json`
        const backupPath = path.resolve(config.destinationPath, fileName)

        // Ensure backup directory exists
        await fs.mkdir(path.dirname(backupPath), { recursive: true })

        // Get collections to backup
        const allCollections = await this.getCollections()
        const collectionsToBackup = config.includeTables && config.includeTables.length > 0
          ? config.includeTables.filter(name => allCollections.includes(name))
          : allCollections.filter(name => !config.excludeTables?.includes(name))

        // Create backup data structure
        const backupData = {
          metadata: {
            database: this.databaseName,
            timestamp: new Date().toISOString(),
            backupName: config.backupName,
            description: config.description,
            version: '1.0',
            collections: collectionsToBackup,
            compression: config.compression || 'none'
          },
          collections: {} as Record<keyof typeof collectionsToBackup, any[]>
        }

        // Export each collection
        let totalDocuments = 0
        for (const collectionName of collectionsToBackup) {
          try {
            console.log(`Backing up collection: ${collectionName}`)
            const documents = await this.exportCollectionData(client, collectionName)
            backupData.collections[collectionName as keyof typeof collectionsToBackup] = documents
            totalDocuments += documents.length
            console.log(`Collection ${collectionName}: ${documents.length} documents`)
          } catch (error: any) {
            console.warn(`Warning: Could not backup collection ${collectionName}:`, error.message)
            // Continue with other collections
          }
        }

        // Write backup file
        const backupJson = JSON.stringify(backupData, null, 2)
        await fs.writeFile(backupPath, backupJson, 'utf8')

        // Get file stats
        const stats = await fs.stat(backupPath)

        return {
          success: true,
          filePath: backupPath,
          details: {
            database: this.databaseName,
            collections: collectionsToBackup.length,
            totalDocuments,
            fileSize: this.formatFileSize(stats.size),
            backupPath,
            timestamp: new Date().toISOString()
          }
        }

      } finally {
        await client.close()
      }

    } catch (error: any) {
      console.error('Backup error:', error)
      return {
        success: false,
        error: error.message,
        details: { error: error.message }
      }
    }
  }

  // Restore from backup using native JavaScript
  async restoreBackup(config: RestoreRequest): Promise<{
    success: boolean
    error?: string
    details?: any
  }> {
    try {
      // Check if backup file exists
      try {
        await fs.access(config.backupPath)
      } catch {
        throw new Error('Backup file does not exist')
      }

      // Read backup file
      const backupContent = await fs.readFile(config.backupPath, 'utf8')
      const backupData = JSON.parse(backupContent)

      // Validate backup structure
      if (!backupData.metadata || !backupData.collections) {
        throw new Error('Invalid backup file structure')
      }

      // Dry run validation
      if (config.dryRun) {
        const collectionsCount = Object.keys(backupData.collections).length
        let totalDocuments = 0

        for (const [collectionName, documents] of Object.entries(backupData.collections)) {
          totalDocuments += (documents as any[]).length
        }

        return {
          success: true,
          details: {
            dryRun: true,
            sourceDatabase: backupData.metadata.database,
            targetDatabase: config.targetDatabase || this.databaseName,
            collectionsToRestore: collectionsCount,
            totalDocuments,
            backupTimestamp: backupData.metadata.timestamp,
            dropExisting: config.dropExisting
          }
        }
      }

      // Perform actual restore
      const client = await this.getClient()

      try {
        const targetDbName = config.targetDatabase || this.databaseName

        let restoredCollections = 0
        let totalDocuments = 0

        // Filter collections to restore
        const collectionsToRestore = config.restoreTables && config.restoreTables.length > 0
          ? Object.keys(backupData.collections).filter(name => config.restoreTables!.includes(name))
          : Object.keys(backupData.collections)

        // Restore each collection
        for (const collectionName of collectionsToRestore) {
          const documents = backupData.collections[collectionName]
          if (documents && Array.isArray(documents)) {
            console.log(`Restoring collection: ${collectionName} (${documents.length} documents)`)

            // Switch to target database if different
            const db = client.db(targetDbName)
            const collection = db.collection(collectionName)

            if (config.dropExisting) {
              await collection.deleteMany({})
            }

            if (documents.length > 0) {
              // Remove _id if it exists to avoid duplicate key errors
              const docsToInsert = documents.map(doc => {
                const { _id, ...docWithoutId } = doc
                return docWithoutId
              })

              await collection.insertMany(docsToInsert)
            }

            restoredCollections++
            totalDocuments += documents.length
          }
        }

        return {
          success: true,
          details: {
            sourceDatabase: backupData.metadata.database,
            targetDatabase: targetDbName,
            restoredCollections,
            totalDocuments,
            backupTimestamp: backupData.metadata.timestamp,
            dropExisting: config.dropExisting
          }
        }

      } finally {
        await client.close()
      }

    } catch (error: any) {
      console.error('Restore error:', error)
      return {
        success: false,
        error: error.message,
        details: { error: error.message }
      }
    }
  }

  // List available backups in directory
  async listBackups(backupDir: string): Promise<{
    success: boolean
    backups?: Array<{
      name: string
      path: string
      size: number
      createdAt: Date
      isDirectory: boolean
      metadata?: any
    }>
    error?: string
  }> {
    try {
      // Ensure backup directory exists
      try {
        await fs.mkdir(backupDir, { recursive: true })
      } catch {
        // Directory might already exist
      }

      const items = await fs.readdir(backupDir, { withFileTypes: true })
      const backups = []

      for (const item of items) {
        if (item.isFile() && item.name.endsWith('.json')) {
          const itemPath = path.join(backupDir, item.name)
          const stats = await fs.stat(itemPath)

          // Try to read backup metadata
          let metadata = null
          try {
            const content = await fs.readFile(itemPath, 'utf8')
            const backupData = JSON.parse(content)
            metadata = backupData.metadata
          } catch {
            // If can't read metadata, that's fine
          }

          backups.push({
            name: item.name,
            path: itemPath,
            size: stats.size,
            createdAt: stats.birthtime,
            isDirectory: false,
            metadata
          })
        }
      }

      // Sort by creation date (newest first)
      backups.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())

      return {
        success: true,
        backups
      }
    } catch (error: any) {
      return {
        success: false,
        error: `Failed to list backups: ${error.message}`
      }
    }
  }

  // Get database statistics
  async getDatabaseStats(): Promise<{
    success: boolean
    stats?: {
      database: string
      collections: number
      totalDocuments: number
      dataSize: string
      indexSize: string
    }
    error?: string
  }> {
    try {
      const client = await this.getClient()

      try {
        const db = client.db(this.databaseName)
        const stats = await db.stats()
        const collections = await this.getCollections()

        let totalDocuments = 0
        for (const collectionName of collections) {
          try {
            const collection = db.collection(collectionName)
            const count = await collection.countDocuments()
            totalDocuments += count
          } catch {
            // Skip collections we can't count
          }
        }

        return {
          success: true,
          stats: {
            database: this.databaseName,
            collections: collections.length,
            totalDocuments,
            dataSize: this.formatFileSize(stats.dataSize || 0),
            indexSize: this.formatFileSize(stats.indexSize || 0)
          }
        }
      } finally {
        await client.close()
      }
    } catch (error: any) {
      return {
        success: false,
        error: error.message
      }
    }
  }

  // Utility function to format file size
  private formatFileSize(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    if (bytes === 0) return '0 Bytes'
    const i = Math.floor(Math.log(bytes) / Math.log(1024))
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i]
  }
}

// Export utility functions for backward compatibility
export async function checkNativeBackupAvailable(): Promise<{
  available: boolean
  error?: string
  databaseInfo?: any
}> {
  try {
    const service = new NativeBackupService()
    const stats = await service.getDatabaseStats()

    return {
      available: stats.success,
      databaseInfo: stats.stats,
      error: stats.error
    }
  } catch (error: any) {
    return {
      available: false,
      error: error.message
    }
  }
}

export async function executeNativeBackup(config: ManualBackupRequest) {
  const service = new NativeBackupService()
  return await service.createBackup(config)
}

export async function executeNativeRestore(config: RestoreRequest) {
  const service = new NativeBackupService()
  return await service.restoreBackup(config)
}

export async function listNativeBackups(backupDir: string) {
  const service = new NativeBackupService()
  return await service.listBackups(backupDir)
}

export async function getNativeDatabaseStats() {
  const service = new NativeBackupService()
  return await service.getDatabaseStats()
}