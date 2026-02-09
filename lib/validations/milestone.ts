import { z } from 'zod';

export const MILESTONE_CONSTANTS = {
  TITLE: { MIN_LENGTH: 2, MAX_LENGTH: 200 },
  DESCRIPTION: { MAX_LENGTH: 1000 },
  STATUS: { 
    VALUES: ['pending', 'in-progress', 'completed', 'overdue'] as const, 
    DEFAULT: 'pending' as const 
  },
  PRIORITY: { 
    VALUES: ['low', 'medium', 'high', 'urgent'] as const, 
    DEFAULT: 'medium' as const 
  },
  PROGRESS: { MIN: 0, MAX: 100 },
  PAGINATION: { DEFAULT_PAGE: 1, DEFAULT_LIMIT: 20, MAX_LIMIT: 100, MIN_PAGE: 1 },
  SORT: { ALLOWED_FIELDS: ['title', 'status', 'priority', 'dueDate', 'progress', 'createdAt', 'updatedAt'] as const }
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

// Base milestone schema
export const baseMilestoneSchema = z.object({
  title: z.string()
    .min(MILESTONE_CONSTANTS.TITLE.MIN_LENGTH, `Title must be at least ${MILESTONE_CONSTANTS.TITLE.MIN_LENGTH} characters`)
    .max(MILESTONE_CONSTANTS.TITLE.MAX_LENGTH, `Title cannot exceed ${MILESTONE_CONSTANTS.TITLE.MAX_LENGTH} characters`)
    .transform(val => val.trim()),
  
  description: z.string()
    .max(MILESTONE_CONSTANTS.DESCRIPTION.MAX_LENGTH, `Description cannot exceed ${MILESTONE_CONSTANTS.DESCRIPTION.MAX_LENGTH} characters`)
    .transform(val => val.trim())
    .optional(),
  
  projectId: objectIdSchema,
  
  phaseId: optionalObjectIdSchema,
  
  dueDate: dateSchema,
  
  status: z.enum(MILESTONE_CONSTANTS.STATUS.VALUES).default(MILESTONE_CONSTANTS.STATUS.DEFAULT),
  
  priority: z.enum(MILESTONE_CONSTANTS.PRIORITY.VALUES).default(MILESTONE_CONSTANTS.PRIORITY.DEFAULT),
  
  progress: z.number()
    .min(MILESTONE_CONSTANTS.PROGRESS.MIN, `Progress cannot be less than ${MILESTONE_CONSTANTS.PROGRESS.MIN}`)
    .max(MILESTONE_CONSTANTS.PROGRESS.MAX, `Progress cannot exceed ${MILESTONE_CONSTANTS.PROGRESS.MAX}`)
    .default(0),
  
  assigneeId: optionalObjectIdSchema,
  
  linkedTaskIds: z.array(objectIdSchema).default([]),
  
  deliverables: z.array(z.string().max(500, 'Deliverable description too long')).default([]),
  
  successCriteria: z.array(z.string().max(500, 'Success criteria too long')).default([]),
  
  dependencies: z.array(objectIdSchema).default([]),
  
  budgetAllocation: z.number().min(0, 'Budget allocation cannot be negative').optional(),
  
  actualCost: z.number().min(0, 'Actual cost cannot be negative').optional(),
}).strict();

// Create milestone schema
export const createMilestoneSchema = baseMilestoneSchema.extend({
  projectId: objectIdSchema,
  phaseId: optionalObjectIdSchema,
  assigneeId: optionalObjectIdSchema,
}).strict()

// Update milestone schema
export const updateMilestoneSchema = z.object({
  title: z.string()
    .min(MILESTONE_CONSTANTS.TITLE.MIN_LENGTH, `Title must be at least ${MILESTONE_CONSTANTS.TITLE.MIN_LENGTH} characters`)
    .max(MILESTONE_CONSTANTS.TITLE.MAX_LENGTH, `Title cannot exceed ${MILESTONE_CONSTANTS.TITLE.MAX_LENGTH} characters`)
    .transform(val => val.trim())
    .optional(),
  
  description: z.string()
    .max(MILESTONE_CONSTANTS.DESCRIPTION.MAX_LENGTH, `Description cannot exceed ${MILESTONE_CONSTANTS.DESCRIPTION.MAX_LENGTH} characters`)
    .transform(val => val.trim())
    .optional(),
  
  phaseId: optionalObjectIdSchema,
  
  // dueDate: dateSchema.optional(),
  dueDate: optionalDateSchema,
  
  status: z.enum(MILESTONE_CONSTANTS.STATUS.VALUES).optional(),
  
  priority: z.enum(MILESTONE_CONSTANTS.PRIORITY.VALUES).optional(),
  
  progress: z.number()
    .min(MILESTONE_CONSTANTS.PROGRESS.MIN, `Progress cannot be less than ${MILESTONE_CONSTANTS.PROGRESS.MIN}`)
    .max(MILESTONE_CONSTANTS.PROGRESS.MAX, `Progress cannot exceed ${MILESTONE_CONSTANTS.PROGRESS.MAX}`)
    .optional(),
  
  assigneeId: optionalObjectIdSchema,
  
  linkedTaskIds: z.array(objectIdSchema).optional(),
  
  deliverables: z.array(z.string().max(500, 'Deliverable description too long')).optional(),
  
  successCriteria: z.array(z.string().max(500, 'Success criteria too long')).optional(),
  
  dependencies: z.array(objectIdSchema).optional(),
  
  budgetAllocation: z.number().min(0, 'Budget allocation cannot be negative').optional(),
  
  actualCost: z.number().min(0, 'Actual cost cannot be negative').optional(),
  
  completedDate: optionalDateSchema,
}).strict()
  .refine(data => {
    // At least one field must be provided
    return Object.values(data).some(value => value !== undefined);
  }, { message: 'At least one field must be provided for update' });

// Query schema for fetching milestones
export const milestoneQuerySchema = z.object({
  projectId: optionalObjectIdSchema,
  phaseId: optionalObjectIdSchema,
  assigneeId: optionalObjectIdSchema,
  status: z.string().optional()
    .refine(val => !val || val === '' || MILESTONE_CONSTANTS.STATUS.VALUES.includes(val as any), {
      message: 'Invalid status value'
    })
    .transform(val => !val || val === '' ? undefined : val as any),
  priority: z.string().optional()
    .refine(val => !val || val === '' || MILESTONE_CONSTANTS.PRIORITY.VALUES.includes(val as any), {
      message: 'Invalid priority value'
    })
    .transform(val => !val || val === '' ? undefined : val as any),
  dueDateFrom: z.string().optional()
    .refine(val => !val || val === '' || !isNaN(Date.parse(val)), { message: 'Invalid date format' })
    .transform(val => !val || val === '' ? undefined : val),
  dueDateTo: z.string().optional()
    .refine(val => !val || val === '' || !isNaN(Date.parse(val)), { message: 'Invalid date format' })
    .transform(val => !val || val === '' ? undefined : val),
  overdue: z.string().optional()
    .transform(val => val === 'true' ? true : val === 'false' ? false : undefined),
  page: z.string().optional()
    .transform(val => val && val !== '' ? parseInt(val, 10) : MILESTONE_CONSTANTS.PAGINATION.DEFAULT_PAGE)
    .refine(val => val >= MILESTONE_CONSTANTS.PAGINATION.MIN_PAGE, { message: 'Invalid page number' }),
  limit: z.string().optional()
    .transform(val => val && val !== '' ? parseInt(val, 10) : MILESTONE_CONSTANTS.PAGINATION.DEFAULT_LIMIT)
    .refine(val => val <= MILESTONE_CONSTANTS.PAGINATION.MAX_LIMIT, { message: 'Limit too high' }),
  sortBy: z.string().optional()
    .refine(val => !val || val === '' || MILESTONE_CONSTANTS.SORT.ALLOWED_FIELDS.includes(val as any), {
      message: 'Invalid sort field'
    })
    .transform(val => !val || val === '' ? 'dueDate' : val as any),
  sortOrder: z.string().optional()
    .refine(val => !val || val === '' || ['asc', 'desc'].includes(val), {
      message: 'Invalid sort order'
    })
    .transform(val => !val || val === '' ? 'asc' : val as 'asc' | 'desc'),
});

// Milestone ID validation
export const milestoneIdSchema = z.object({
  id: objectIdSchema,
});

// Form schemas (frontend)
export const createMilestoneFormSchema = z.object({
  title: z.string()
    .min(MILESTONE_CONSTANTS.TITLE.MIN_LENGTH, `Title must be at least ${MILESTONE_CONSTANTS.TITLE.MIN_LENGTH} characters`)
    .max(MILESTONE_CONSTANTS.TITLE.MAX_LENGTH, `Title cannot exceed ${MILESTONE_CONSTANTS.TITLE.MAX_LENGTH} characters`),
  
  description: z.string().optional(),
  
  projectId: z.string().min(1, 'Project is required'),
  
  phaseId: z.string().optional(),
  
  dueDate: z.string().min(1, 'Due date is required'),
  
  status: z.enum(MILESTONE_CONSTANTS.STATUS.VALUES).default('pending'),
  
  priority: z.enum(MILESTONE_CONSTANTS.PRIORITY.VALUES).default('medium'),
  
  progress: z.number().min(0).max(100).default(0),
  
  assigneeId: z.string().optional(),
  
  deliverables: z.array(z.string()).default([]),
  
  successCriteria: z.array(z.string()).default([]),
  
  budgetAllocation: z.string()
    .optional()
    .transform(val => {
      if (!val || val.trim() === '') return undefined;
      const num = parseFloat(val);
      return isNaN(num) ? undefined : num;
    })
    .refine(val => val === undefined || val >= 0, {
      message: 'Budget allocation cannot be negative'
    }),
});

export const updateMilestoneFormSchema = createMilestoneFormSchema.partial();

// Type exports
export type CreateMilestoneData = z.infer<typeof createMilestoneSchema>;
export type UpdateMilestoneData = z.infer<typeof updateMilestoneSchema>;
export type CreateMilestoneFormData = z.infer<typeof createMilestoneFormSchema>;
export type UpdateMilestoneFormData = z.infer<typeof updateMilestoneFormSchema>;
export type MilestoneQueryParams = z.infer<typeof milestoneQuerySchema>;

// Utility functions
export const formatMilestoneProgress = (progress: number): string => {
  return `${progress}%`;
};

export const getMilestoneStatusColor = (status: string): string => {
  const colors = {
    'pending': 'text-muted-foreground bg-muted',
    'in-progress': 'text-primary bg-primary/10',
    'completed': 'text-emerald-600 bg-emerald-100',
    'overdue': 'text-destructive bg-destructive/10'
  };
  return colors[status as keyof typeof colors] || colors.pending;
};

export const getMilestonePriorityColor = (priority: string): string => {
  const colors = {
    'low': 'text-blue-600 bg-blue-100',
    'medium': 'text-amber-600 bg-amber-100',
    'high': 'text-orange-600 bg-orange-100',
    'urgent': 'text-destructive bg-destructive/10'
  };
  return colors[priority as keyof typeof colors] || colors.medium;
};