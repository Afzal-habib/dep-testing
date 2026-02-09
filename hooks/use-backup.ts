import { useState, useCallback } from 'react'
import { useToast } from '@/hooks/use-toast'

export interface BackupInfo {
  name: string
  path: string
  size: number
  formattedSize: string
  createdAt: Date
  isDirectory: boolean
}

export interface BackupServiceStatus {
  available: boolean
  error?: string
  databaseInfo?: {
    database: string
    collections: number
    totalDocuments: number
    dataSize: string
    indexSize: string
  }
}

export interface BackupConfig {
  destinationPath: string
  backupName?: string
  description?: string
  compression?: 'none' | 'gzip' | 'snappy'
  includeTables?: string[]
  excludeTables?: string[]
  retentionDays?: number
  includeIndexes?: boolean
  generateTimestamp?: boolean
}

export interface RestoreConfig {
  backupPath: string
  targetDatabase?: string
  dropExisting?: boolean
  restoreTables?: string[]
  dryRun?: boolean
}

interface UseBackupReturn {
  // State
  backups: BackupInfo[]
  serviceStatus: BackupServiceStatus | null
  loading: boolean
  error: string | null
  backupInProgress: boolean
  restoreInProgress: boolean
  
  // Actions
  fetchBackups: () => Promise<void>
  createBackup: (config: BackupConfig) => Promise<boolean>
  restoreBackup: (config: RestoreConfig) => Promise<boolean>
  checkService: () => Promise<void>
  
  // Helpers
  getBackupByName: (name: string) => BackupInfo | undefined
  isServiceAvailable: () => boolean
  formatFileSize: (bytes: number) => string
}

export function useBackup(): UseBackupReturn {
  const [backups, setBackups] = useState<BackupInfo[]>([])
  const [serviceStatus, setServiceStatus] = useState<BackupServiceStatus | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [backupInProgress, setBackupInProgress] = useState(false)
  const [restoreInProgress, setRestoreInProgress] = useState(false)
  const { toast } = useToast()

  // Fetch available backups and tools status
  const fetchBackups = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/settings/backup', {
        cache: 'no-cache',
        headers: {
          'Cache-Control': 'no-cache'
        }
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`)
      }

      setBackups(data.data.backups || [])
      setServiceStatus({
        available: data.data.nativeBackupAvailable,
        databaseInfo: data.data.databaseInfo
      })

      if (!data.data.nativeBackupAvailable) {
        setError('Database backup service is not available.')
      }
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to fetch backups'
      setError(errorMessage)
      console.error('Error fetching backups:', err)
      
      // Show toast for non-permission errors
      if (!errorMessage.includes('Access denied') && !errorMessage.includes('403')) {
        toast({
          title: "Error",
          description: errorMessage,
          variant: "destructive",
        })
      }
    } finally {
      setLoading(false)
    }
  }, [toast])

  // Create a new backup
  const createBackup = useCallback(async (config: BackupConfig): Promise<boolean> => {
    try {
      setBackupInProgress(true)
      setError(null)

      const response = await fetch('/api/settings/backup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(config),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`)
      }

      toast({
        title: "Success",
        description: "Backup created successfully",
      })

      // Refresh backups list
      await fetchBackups()

      return true
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to create backup'
      setError(errorMessage)
      console.error('Error creating backup:', err)
      
      toast({
        title: "Backup Failed",
        description: errorMessage,
        variant: "destructive",
      })
      
      return false
    } finally {
      setBackupInProgress(false)
    }
  }, [toast, fetchBackups])

  // Restore from backup
  const restoreBackup = useCallback(async (config: RestoreConfig): Promise<boolean> => {
    try {
      setRestoreInProgress(true)
      setError(null)

      const response = await fetch('/api/settings/backup', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(config),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`)
      }

      toast({
        title: "Success",
        description: config.dryRun ? 
          "Restore validation completed successfully" : 
          "Database restored successfully",
      })

      return true
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to restore backup'
      setError(errorMessage)
      console.error('Error restoring backup:', err)
      
      toast({
        title: "Restore Failed",
        description: errorMessage,
        variant: "destructive",
      })
      
      return false
    } finally {
      setRestoreInProgress(false)
    }
  }, [toast])

  // Check service availability only
  const checkService = useCallback(async () => {
    try {
      setError(null)

      const response = await fetch('/api/settings/backup?check_service=true', {
        cache: 'no-cache'
      })

      const data = await response.json()

      if (response.ok) {
        setServiceStatus({
          available: data.data.nativeBackupAvailable,
          databaseInfo: data.data.databaseInfo
        })
      }
    } catch (err: any) {
      console.error('Error checking service:', err)
      // Don't set error state for service check as it's non-critical
    }
  }, [])

  // Helper functions
  const getBackupByName = useCallback((name: string): BackupInfo | undefined => {
    return backups.find(backup => backup.name === name)
  }, [backups])

  const isServiceAvailable = useCallback((): boolean => {
    return !!(serviceStatus?.available)
  }, [serviceStatus])

  const formatFileSize = useCallback((bytes: number): string => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
    if (bytes === 0) return '0 Bytes'
    const i = Math.floor(Math.log(bytes) / Math.log(1024))
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i]
  }, [])

  return {
    // State
    backups,
    serviceStatus,
    loading,
    error,
    backupInProgress,
    restoreInProgress,
    
    // Actions
    fetchBackups,
    createBackup,
    restoreBackup,
    checkService,
    
    // Helpers
    getBackupByName,
    isServiceAvailable,
    formatFileSize
  }
}