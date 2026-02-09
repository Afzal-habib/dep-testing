import { z } from 'zod'
import path from 'path'

// Constants for backup validation
export const BACKUP_CONSTANTS = {
  PATH: {
    MIN_LENGTH: 3,
    MAX_LENGTH: 500
  },
  RETENTION: {
    MIN_DAYS: 1,
    MAX_DAYS: 365,
    DEFAULT: 30
  },
  COMPRESSION: {
    LEVELS: ['none', 'gzip', 'snappy'] as const,
    DEFAULT: 'gzip' as const
  }
} as const

// Path validation helper
const validatePath = (filePath: string) => {
  // Basic security checks
  if (filePath.includes('..') || filePath.includes('~')) {
    return false
  }
  
  // Check if path is absolute or relative but safe
  const resolved = path.resolve(filePath)
  return resolved.length > 0
}

// Base backup configuration schema
export const backupConfigSchema = z.object({
  destinationPath: z.string()
    .min(BACKUP_CONSTANTS.PATH.MIN_LENGTH, `Path must be at least ${BACKUP_CONSTANTS.PATH.MIN_LENGTH} characters`)
    .max(BACKUP_CONSTANTS.PATH.MAX_LENGTH, `Path must be at most ${BACKUP_CONSTANTS.PATH.MAX_LENGTH} characters`)
    .refine(validatePath, 'Invalid file path or contains unsafe characters'),
  
  includeTables: z.array(z.string())
    .optional()
    .default([]),
  
  excludeTables: z.array(z.string())
    .optional()
    .default([]),
  
  compression: z.enum(BACKUP_CONSTANTS.COMPRESSION.LEVELS)
    .default(BACKUP_CONSTANTS.COMPRESSION.DEFAULT),
  
  retentionDays: z.number()
    .int('Retention days must be a whole number')
    .min(BACKUP_CONSTANTS.RETENTION.MIN_DAYS, `Minimum retention is ${BACKUP_CONSTANTS.RETENTION.MIN_DAYS} day`)
    .max(BACKUP_CONSTANTS.RETENTION.MAX_DAYS, `Maximum retention is ${BACKUP_CONSTANTS.RETENTION.MAX_DAYS} days`)
    .default(BACKUP_CONSTANTS.RETENTION.DEFAULT),
  
  includeIndexes: z.boolean()
    .default(true),
  
  generateTimestamp: z.boolean()
    .default(true)
})

// Manual backup request schema
export const manualBackupSchema = backupConfigSchema.extend({
  backupName: z.string()
    .optional()
    .refine(name => !name || (name.length >= 1 && name.length <= 100), 'Backup name must be between 1 and 100 characters')
    .refine(name => !name || /^[a-zA-Z0-9_-]+$/.test(name), 'Backup name can only contain letters, numbers, hyphens, and underscores'),
  
  description: z.string()
    .optional()
    .refine(desc => !desc || desc.length <= 500, 'Description must be 500 characters or less')
})
// Form schemas
export const backupFormSchema = z.object({
  destinationPath: z.string()
    .min(1, 'Destination path is required')
    .refine(path => !path.includes('..'), 'Invalid path'),
  backupName: z.string()
    .transform(val => val === '' ? undefined : val)
    .optional()
    .refine(name => !name || /^[a-zA-Z0-9_-]+$/.test(name), 'Name can only contain letters, numbers, hyphens, and underscores'),
  description: z.string()
    .transform(val => val === '' ? undefined : val)
    .optional(),
  compression: z.enum(['gzip', 'none']),
  includeIndexes: z.boolean(),
  generateTimestamp: z.boolean(),
})

export const restoreFormSchema = z.object({
  backupPath: z.string().min(1, 'Backup path is required'),
  targetDatabase: z.string()
    .transform(val => val === '' ? undefined : val)
    .optional(),
  dropExisting: z.boolean(),
  dryRun: z.boolean(),
})

// Restore operation schema
export const restoreSchema = z.object({
  backupPath: z.string()
    .min(BACKUP_CONSTANTS.PATH.MIN_LENGTH, `Path must be at least ${BACKUP_CONSTANTS.PATH.MIN_LENGTH} characters`)
    .max(BACKUP_CONSTANTS.PATH.MAX_LENGTH, `Path must be at most ${BACKUP_CONSTANTS.PATH.MAX_LENGTH} characters`)
    .refine(validatePath, 'Invalid backup file path'),
  
  targetDatabase: z.string()
    .optional()
    .refine(db => !db || (db.length >= 1 && db.length <= 63), 'Database name must be between 1 and 63 characters')
    .refine(db => !db || /^[a-zA-Z0-9_-]+$/.test(db), 'Database name can only contain letters, numbers, hyphens, and underscores'), // If not provided, will restore to current database
  
  dropExisting: z.boolean()
    .default(false),
  
  restoreTables: z.array(z.string())
    .optional(),
  
  dryRun: z.boolean()
    .default(false)
})

// Backup job status schema
export const backupStatusSchema = z.object({
  jobId: z.string()
    .min(1, 'Job ID is required'),
  
  status: z.enum(['pending', 'running', 'completed', 'failed', 'cancelled']),
  
  progress: z.number()
    .min(0)
    .max(100)
    .optional(),
  
  message: z.string()
    .optional(),
  
  startedAt: z.date()
    .optional(),
  
  completedAt: z.date()
    .optional(),
  
  errorDetails: z.any()
    .optional()
})

// Scheduled backup schema
export const scheduledBackupSchema = backupConfigSchema.extend({
  enabled: z.boolean()
    .default(false),
  
  frequency: z.enum(['daily', 'weekly', 'monthly'])
    .default('weekly'),
  
  scheduleTime: z.string()
    .regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Time must be in HH:MM format')
    .default('02:00'),
  
  weekDay: z.number()
    .int()
    .min(0, 'Week day must be 0-6 (Sunday-Saturday)')
    .max(6, 'Week day must be 0-6 (Sunday-Saturday)')
    .optional(), // For weekly backups
  
  monthDay: z.number()
    .int()
    .min(1, 'Month day must be 1-28')
    .max(28, 'Month day must be 1-28')
    .optional(), // For monthly backups
  
  maxBackups: z.number()
    .int()
    .min(1, 'Must keep at least 1 backup')
    .max(100, 'Cannot keep more than 100 backups')
    .default(10)
})

// Backup list query schema
export const backupListQuerySchema = z.object({
  page: z.string()
    .transform(val => val ? parseInt(val, 10) : 1)
    .refine(val => val >= 1, 'Page must be at least 1')
    .default('1'),
  
  limit: z.string()
    .transform(val => val ? parseInt(val, 10) : 20)
    .refine(val => val >= 1 && val <= 100, 'Limit must be between 1 and 100')
    .default('20'),
  
  status: z.enum(['all', 'completed', 'failed', 'running'])
    .nullable()
    .transform(val => val || 'all')
    .default('all'),
  
  dateFrom: z.string()
    .optional()
    .nullable()
    .transform(val => val ? new Date(val) : undefined),
  
  dateTo: z.string()
    .optional()
    .nullable()
    .transform(val => val ? new Date(val) : undefined),
  
  sortBy: z.enum(['createdAt', 'name', 'size', 'status'])
    .nullable()
    .transform(val => val || 'createdAt')
    .default('createdAt'),
  
  sortOrder: z.enum(['asc', 'desc'])
    .nullable()
    .transform(val => val || 'desc')
    .default('desc')
})

// Type exports
export type BackupConfig = z.infer<typeof backupConfigSchema>
export type ManualBackupRequest = z.infer<typeof manualBackupSchema>
export type RestoreRequest = z.infer<typeof restoreSchema>
export type BackupStatus = z.infer<typeof backupStatusSchema>
export type ScheduledBackupConfig = z.infer<typeof scheduledBackupSchema>
export type BackupListQuery = z.infer<typeof backupListQuerySchema>

// Validation helpers
export const validateBackupPath = (filePath: string): boolean => {
  return backupConfigSchema.shape.destinationPath.safeParse(filePath).success
}

export const validateBackupName = (name: string): boolean => {
  return manualBackupSchema.shape.backupName.safeParse(name).success
}

export const isValidCompressionLevel = (level: string): level is typeof BACKUP_CONSTANTS.COMPRESSION.LEVELS[number] => {
  return BACKUP_CONSTANTS.COMPRESSION.LEVELS.includes(level as any)
}