import { z } from 'zod';

export const ANALYTICS_CONSTANTS = {
  DATE_RANGE: {
    VALUES: ['7d', '30d', '90d', '1y'] as const,
    DEFAULT: '30d' as const
  }
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

// Analytics query schema
export const analyticsQuerySchema = z.object({
  projectId: optionalObjectIdSchema,
  
  departmentId: optionalObjectIdSchema,
  
  userId: optionalObjectIdSchema,
  
  dateRange: z.string().optional()
    .refine(val => !val || val === '' || ANALYTICS_CONSTANTS.DATE_RANGE.VALUES.includes(val as any), {
      message: 'Invalid date range'
    })
    .transform(val => !val || val === '' ? ANALYTICS_CONSTANTS.DATE_RANGE.DEFAULT : val as typeof ANALYTICS_CONSTANTS.DATE_RANGE.VALUES[number]),
  
  includeCompleted: z.string().optional()
    .transform(val => val === 'true' || val === '' || val === undefined ? true : val === 'false' ? false : true),
  
  startDate: z.string().optional()
    .refine(val => !val || val === '' || !isNaN(Date.parse(val)), { message: 'Invalid start date format' })
    .transform(val => !val || val === '' ? undefined : val),
  
  endDate: z.string().optional()
    .refine(val => !val || val === '' || !isNaN(Date.parse(val)), { message: 'Invalid end date format' })
    .transform(val => !val || val === '' ? undefined : val),
});

// Analytics response interfaces
export interface ProjectAnalytics {
  totalProjects: number;
  activeProjects: number;
  completedProjects: number;
  onHoldProjects: number;
  averageProgress: number;
  totalBudget: number;
  totalSpent: number;
}

export interface TaskAnalytics {
  totalTasks: number;
  completedTasks: number;
  inProgressTasks: number;
  pendingTasks: number;
  overdueTasks: number;
  averageProgress: number;
}


export interface AnalyticsResponse {
  overview: ProjectAnalytics;
  tasks: TaskAnalytics;
  meta: {
    dateRange: string;
    startDate: string;
    endDate: string;
    projectId?: string;
    generatedAt: string;
    userRole?: string;
    userId?: string;
  };
}

// Type exports for easier use
export type AnalyticsQueryParams = z.infer<typeof analyticsQuerySchema>;
export type DateRangeType = typeof ANALYTICS_CONSTANTS.DATE_RANGE.VALUES[number];