import { z } from 'zod';

export const TIME_LOG_CONSTANTS = {
  DESCRIPTION: { MIN_LENGTH: 1, MAX_LENGTH: 500 },
  HOURS: { MIN: 0.01, MAX: 24 },
  LOG_TYPES: ['manual', 'timer'] as const,
  PAGINATION: { DEFAULT_PAGE: 1, DEFAULT_LIMIT: 20, MAX_LIMIT: 100, MIN_PAGE: 1 },
  SORT: { ALLOWED_FIELDS: ['date', 'hours', 'createdAt', 'updatedAt'] as const }
} as const;

// Common validation schemas
export const objectIdSchema = z.string().regex(
  /^[0-9a-fA-F]{24}$/,
  'Invalid ID format'
);

export const optionalObjectIdSchema = z.string()
  .optional()
  .refine(val => !val || val === '' || /^[0-9a-fA-F]{24}$/.test(val), {
    message: 'Invalid ID format'
  })
  .transform(val => !val || val.trim() === '' ? undefined : val.trim());

// Date validation
const dateSchema = z.string()
  .refine(val => !isNaN(Date.parse(val)), { message: 'Invalid date format' })
  .transform(val => new Date(val));

const optionalDateSchema = z.string()
  .optional()
  .refine(val => !val || !isNaN(Date.parse(val)), { message: 'Invalid date format' })
  .transform(val => val ? new Date(val) : undefined);

// Base time log schema
export const baseTimeLogSchema = z.object({
  taskId: objectIdSchema,
  
  projectId: objectIdSchema,
  
  userId: objectIdSchema,
  
  description: z.string()
    .min(TIME_LOG_CONSTANTS.DESCRIPTION.MIN_LENGTH, 'Description is required')
    .max(TIME_LOG_CONSTANTS.DESCRIPTION.MAX_LENGTH, 'Description too long')
    .transform(val => val.trim()),
  
  hours: z.number()
    .min(TIME_LOG_CONSTANTS.HOURS.MIN, `Hours must be at least ${TIME_LOG_CONSTANTS.HOURS.MIN}`)
    .max(TIME_LOG_CONSTANTS.HOURS.MAX, `Hours cannot exceed ${TIME_LOG_CONSTANTS.HOURS.MAX} per day`),
  
  date: dateSchema,
  
  startTime: optionalDateSchema,
  
  endTime: optionalDateSchema,
  
  logType: z.enum(TIME_LOG_CONSTANTS.LOG_TYPES).default('manual'),
});

// Create time log schema
export const createTimeLogSchema = baseTimeLogSchema
  .omit({ userId: true }) // User will be set from session
  .strict()
  .refine(data => {
    // If start and end times are provided, validate they're consistent
    if (data.startTime && data.endTime) {
      return data.startTime < data.endTime;
    }
    return true;
  }, { message: 'Start time must be before end time' })
  .refine(data => {
    // Date cannot be in the future
    return data.date <= new Date();
  }, { message: 'Date cannot be in the future' });

// Update time log schema
export const updateTimeLogSchema = z.object({
  description: z.string()
    .min(TIME_LOG_CONSTANTS.DESCRIPTION.MIN_LENGTH, 'Description is required')
    .max(TIME_LOG_CONSTANTS.DESCRIPTION.MAX_LENGTH, 'Description too long')
    .transform(val => val.trim())
    .optional(),
  
  hours: z.number()
    .min(TIME_LOG_CONSTANTS.HOURS.MIN, `Hours must be at least ${TIME_LOG_CONSTANTS.HOURS.MIN}`)
    .max(TIME_LOG_CONSTANTS.HOURS.MAX, `Hours cannot exceed ${TIME_LOG_CONSTANTS.HOURS.MAX} per day`)
    .optional(),
  
  date: dateSchema.optional(),
  
  startTime: optionalDateSchema,
  
  endTime: optionalDateSchema,
  
  isApproved: z.boolean().optional(),
}).strict()
  .refine(data => {
    // At least one field must be provided
    return Object.values(data).some(value => value !== undefined);
  }, { message: 'At least one field must be provided for update' })
  .refine(data => {
    // If start and end times are provided, validate they're consistent
    if (data.startTime && data.endTime) {
      return data.startTime < data.endTime;
    }
    return true;
  }, { message: 'Start time must be before end time' });

// Form schemas (frontend)
export const createTimeLogFormSchema = z.object({
  taskId: z.string().min(1, 'Task is required'),
  projectId: z.string().min(1, 'Project is required'),
  description: z.string()
    .min(TIME_LOG_CONSTANTS.DESCRIPTION.MIN_LENGTH, 'Description is required')
    .max(TIME_LOG_CONSTANTS.DESCRIPTION.MAX_LENGTH, 'Description too long')
    .transform(val => val.trim()),
  
  hours: z.string()
    .transform(val => parseFloat(val))
    .refine(val => !isNaN(val), { message: 'Hours must be a valid number' })
    .refine(val => val >= TIME_LOG_CONSTANTS.HOURS.MIN, { message: `Hours must be at least ${TIME_LOG_CONSTANTS.HOURS.MIN}` })
    .refine(val => val <= TIME_LOG_CONSTANTS.HOURS.MAX, { message: `Hours cannot exceed ${TIME_LOG_CONSTANTS.HOURS.MAX} per day` }),
  
  date: z.string().min(1, 'Date is required'),
  
  startTime: z.string().optional(),
  endTime: z.string().optional(),
  logType: z.enum(TIME_LOG_CONSTANTS.LOG_TYPES).default('manual'),
});

export const updateTimeLogFormSchema = z.object({
  description: z.string()
    .min(TIME_LOG_CONSTANTS.DESCRIPTION.MIN_LENGTH, 'Description is required')
    .max(TIME_LOG_CONSTANTS.DESCRIPTION.MAX_LENGTH, 'Description too long')
    .transform(val => val.trim())
    .optional(),
  
  hours: z.string()
    .optional()
    .transform(val => val ? parseFloat(val) : undefined)
    .refine(val => !val || !isNaN(val), { message: 'Hours must be a valid number' })
    .refine(val => !val || val >= TIME_LOG_CONSTANTS.HOURS.MIN, { message: `Hours must be at least ${TIME_LOG_CONSTANTS.HOURS.MIN}` })
    .refine(val => !val || val <= TIME_LOG_CONSTANTS.HOURS.MAX, { message: `Hours cannot exceed ${TIME_LOG_CONSTANTS.HOURS.MAX} per day` }),
  
  date: z.string().optional(),
  startTime: z.string().optional(),
  endTime: z.string().optional(),
});

// Query schema for fetching time logs
export const timeLogQuerySchema = z.object({
  taskId: optionalObjectIdSchema,
  projectId: optionalObjectIdSchema,
  userId: optionalObjectIdSchema,
  dateFrom: z.string().optional().refine(val => !val || !isNaN(Date.parse(val)), { message: 'Invalid date format' }),
  dateTo: z.string().optional().refine(val => !val || !isNaN(Date.parse(val)), { message: 'Invalid date format' }),
  isApproved: z.string().optional().transform(val => val === 'true' ? true : val === 'false' ? false : undefined),
  page: z.string().optional().transform(val => val ? parseInt(val, 10) : TIME_LOG_CONSTANTS.PAGINATION.DEFAULT_PAGE),
  limit: z.string().optional().transform(val => val ? parseInt(val, 10) : TIME_LOG_CONSTANTS.PAGINATION.DEFAULT_LIMIT),
  sortBy: z.enum(TIME_LOG_CONSTANTS.SORT.ALLOWED_FIELDS).optional().default('date'),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
});

// Time log ID validation
export const timeLogIdSchema = z.object({
  id: objectIdSchema,
});

// Bulk operations schema
export const bulkApproveTimeLogsSchema = z.object({
  timeLogIds: z.array(objectIdSchema).min(1, 'At least one time log must be selected'),
  isApproved: z.boolean(),
});

// Type exports
export type CreateTimeLogData = z.infer<typeof createTimeLogSchema>;
export type UpdateTimeLogData = z.infer<typeof updateTimeLogSchema>;
export type CreateTimeLogFormData = z.infer<typeof createTimeLogFormSchema>;
export type UpdateTimeLogFormData = z.infer<typeof updateTimeLogFormSchema>;
export type TimeLogQueryParams = z.infer<typeof timeLogQuerySchema>;
export type BulkApproveTimeLogsData = z.infer<typeof bulkApproveTimeLogsSchema>;

// Utility functions
export const formatHours = (hours: number): string => {
  return `${hours.toFixed(2)}h`;
};

export const calculateHoursFromTime = (startTime: string, endTime: string): number => {
  const start = new Date(startTime);
  const end = new Date(endTime);
  const diffMs = end.getTime() - start.getTime();
  return Math.round((diffMs / (1000 * 60 * 60)) * 100) / 100; // Round to 2 decimal places
};