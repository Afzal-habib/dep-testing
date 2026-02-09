import fs from 'fs/promises'
import path from 'path'

// Generate backup filename with timestamp
export function generateBackupFilename(name?: string, includeTimestamp: boolean = true): string {
  const timestamp = includeTimestamp ? new Date().toISOString().replace(/[:.]/g, '-') : ''
  const baseName = name || 'backup'
  
  return includeTimestamp ? `${baseName}_${timestamp}` : baseName
}

// Ensure backup directory exists
export async function ensureBackupDirectory(backupPath: string): Promise<void> {
  try {
    const dir = path.dirname(backupPath)
    await fs.mkdir(dir, { recursive: true })
  } catch (error: any) {
    throw new Error(`Failed to create backup directory: ${error.message}`)
  }
}

// Calculate directory size
export async function calculateDirectorySize(dirPath: string): Promise<number> {
  let totalSize = 0
  
  try {
    const items = await fs.readdir(dirPath, { withFileTypes: true })
    
    for (const item of items) {
      const itemPath = path.join(dirPath, item.name)
      if (item.isDirectory()) {
        totalSize += await calculateDirectorySize(itemPath)
      } else {
        const stats = await fs.stat(itemPath)
        totalSize += stats.size
      }
    }
  } catch (error) {
    // If we can't read a file/directory, skip it
  }
  
  return totalSize
}

// Format file size for display
export function formatFileSize(bytes: number): string {
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  if (bytes === 0) return '0 Bytes'
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i]
}