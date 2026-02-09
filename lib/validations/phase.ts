import { z } from 'zod';

export const PHASE_CONSTANTS = {
  TITLE: { MIN_LENGTH: 2, MAX_LENGTH: 200 },
  DESCRIPTION: { MAX_LENGTH: 1000 },
  STATUS: { 
    VALUES: ['pending', 'planning', 'in-progress', 'on-hold', 'completed', 'cancelled'] as const, 
    DEFAULT: 'pending' as const 
  },
  ORDER: { MIN: 1 },
  PROGRESS: { MIN: 0, MAX: 100 },
  PAGINATION: { DEFAULT_PAGE: 1, DEFAULT_LIMIT: 20, MAX_LIMIT: 100, MIN_PAGE: 1 },
  SORT: { ALLOWED_FIELDS: ['title', 'status', 'order', 'startDate', 'endDate', 'progress', 'createdAt', 'updatedAt'] as const }
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

// Base phase schema
export const basePhaseSchema = z.object({
  title: z.string()
    .min(PHASE_CONSTANTS.TITLE.MIN_LENGTH, `Title must be at least ${PHASE_CONSTANTS.TITLE.MIN_LENGTH} characters`)
    .max(PHASE_CONSTANTS.TITLE.MAX_LENGTH, `Title cannot exceed ${PHASE_CONSTANTS.TITLE.MAX_LENGTH} characters`)
    .transform(val => val.trim()),
  
  description: z.string()
    .max(PHASE_CONSTANTS.DESCRIPTION.MAX_LENGTH, `Description cannot exceed ${PHASE_CONSTANTS.DESCRIPTION.MAX_LENGTH} characters`)
    .transform(val => val.trim())
    .optional(),
  
  projectId: objectIdSchema,
  
  order: z.number()
    .min(PHASE_CONSTANTS.ORDER.MIN, `Order must be at least ${PHASE_CONSTANTS.ORDER.MIN}`),
  
  startDate: dateSchema,
  
  endDate: dateSchema,
  
  status: z.enum(PHASE_CONSTANTS.STATUS.VALUES).default(PHASE_CONSTANTS.STATUS.DEFAULT),
  
  progress: z.number()
    .min(PHASE_CONSTANTS.PROGRESS.MIN, `Progress cannot be less than ${PHASE_CONSTANTS.PROGRESS.MIN}`)
    .max(PHASE_CONSTANTS.PROGRESS.MAX, `Progress cannot exceed ${PHASE_CONSTANTS.PROGRESS.MAX}`)
    .default(0),
  
  budgetAllocation: z.number().min(0, 'Budget allocation cannot be negative').optional(),
  
  actualCost: z.number().min(0, 'Actual cost cannot be negative').optional(),
  
  objectives: z.array(z.string().max(500, 'Objective description too long. Max 500 words allowed.')).default([]),
  
  deliverables: z.array(z.string().max(500, 'Deliverable description too long. Max 500 words allowed.')).default([]),
  
  resources: z.array(z.string().max(200, 'Resource description too long. Max 200 words allowed.')).default([]),
  
  risks: z.array(z.string().max(500, 'Risk description too long. Max 500 words allowed.')).default([]),
  
  dependencies: z.array(objectIdSchema).default([]),
  
  approvalRequired: z.boolean().default(false),
}).strict()
  .refine(data => {
    // End date must be after start date
    return data.endDate > data.startDate;
  }, { message: 'End date must be after start date' });

// Create phase schema
export const createPhaseSchema = basePhaseSchema;

// Update phase schema
export const updatePhaseSchema = z.object({
  title: z.string()
    .min(PHASE_CONSTANTS.TITLE.MIN_LENGTH, `Title must be at least ${PHASE_CONSTANTS.TITLE.MIN_LENGTH} characters`)
    .max(PHASE_CONSTANTS.TITLE.MAX_LENGTH, `Title cannot exceed ${PHASE_CONSTANTS.TITLE.MAX_LENGTH} characters`)
    .transform(val => val.trim())
    .optional(),
  
  description: z.string()
    .max(PHASE_CONSTANTS.DESCRIPTION.MAX_LENGTH, `Description cannot exceed ${PHASE_CONSTANTS.DESCRIPTION.MAX_LENGTH} characters`)
    .transform(val => val.trim())
    .optional(),
  
  order: z.number()
    .min(PHASE_CONSTANTS.ORDER.MIN, `Order must be at least ${PHASE_CONSTANTS.ORDER.MIN}`)
    .optional(),
  
  startDate: dateSchema.optional(),
  
  endDate: dateSchema.optional(),
  
  actualStartDate: optionalDateSchema,
  
  actualEndDate: optionalDateSchema,
  
  status: z.enum(PHASE_CONSTANTS.STATUS.VALUES).optional(),
  
  progress: z.number()
    .min(PHASE_CONSTANTS.PROGRESS.MIN, `Progress cannot be less than ${PHASE_CONSTANTS.PROGRESS.MIN}`)
    .max(PHASE_CONSTANTS.PROGRESS.MAX, `Progress cannot exceed ${PHASE_CONSTANTS.PROGRESS.MAX}`)
    .optional(),
  
  budgetAllocation: z.number().min(0, 'Budget allocation cannot be negative').optional(),
  
  actualCost: z.number().min(0, 'Actual cost cannot be negative').optional(),
  
  objectives: z.array(z.string().max(500, 'Objective description too long')).optional(),
  
  deliverables: z.array(z.string().max(500, 'Deliverable description too long')).optional(),
  
  resources: z.array(z.string().max(200, 'Resource description too long')).optional(),
  
  risks: z.array(z.string().max(500, 'Risk description too long')).optional(),
  
  dependencies: z.array(objectIdSchema).optional(),
  
  approvalRequired: z.boolean().optional(),
  
  approvedBy: optionalObjectIdSchema,
  
  approvedAt: optionalDateSchema,
}).strict()
  .refine(data => {
    // At least one field must be provided
    return Object.values(data).some(value => value !== undefined);
  }, { message: 'At least one field must be provided for update' })
  .refine(data => {
    // If both start and end dates are provided, validate them
    if (data.startDate && data.endDate) {
      return data.endDate > data.startDate;
    }
    return true;
  }, { message: 'End date must be after start date' })
  .refine(data => {
    // If both actual dates are provided, validate them
    if (data.actualStartDate && data.actualEndDate) {
      return data.actualEndDate > data.actualStartDate;
    }
    return true;
  }, { message: 'Actual end date must be after actual start date' });

// Query schema for fetching phases
export const phaseQuerySchema = z.object({
  projectId: optionalObjectIdSchema,
  status: z.string().optional()
    .refine(val => !val || val === '' || PHASE_CONSTANTS.STATUS.VALUES.includes(val as any), {
      message: 'Invalid status value'
    })
    .transform(val => !val || val === '' ? undefined : val as any),
  startDateFrom: z.string().optional()
    .refine(val => !val || val === '' || !isNaN(Date.parse(val)), { message: 'Invalid date format' })
    .transform(val => !val || val === '' ? undefined : val),
  startDateTo: z.string().optional()
    .refine(val => !val || val === '' || !isNaN(Date.parse(val)), { message: 'Invalid date format' })
    .transform(val => !val || val === '' ? undefined : val),
  endDateFrom: z.string().optional()
    .refine(val => !val || val === '' || !isNaN(Date.parse(val)), { message: 'Invalid date format' })
    .transform(val => !val || val === '' ? undefined : val),
  endDateTo: z.string().optional()
    .refine(val => !val || val === '' || !isNaN(Date.parse(val)), { message: 'Invalid date format' })
    .transform(val => !val || val === '' ? undefined : val),
  page: z.string().optional()
    .transform(val => val && val !== '' ? parseInt(val, 10) : PHASE_CONSTANTS.PAGINATION.DEFAULT_PAGE)
    .refine(val => val >= PHASE_CONSTANTS.PAGINATION.MIN_PAGE, { message: 'Invalid page number' }),
  limit: z.string().optional()
    .transform(val => val && val !== '' ? parseInt(val, 10) : PHASE_CONSTANTS.PAGINATION.DEFAULT_LIMIT)
    .refine(val => val <= PHASE_CONSTANTS.PAGINATION.MAX_LIMIT, { message: 'Limit too high' }),
  sortBy: z.string().optional()
    .refine(val => !val || val === '' || PHASE_CONSTANTS.SORT.ALLOWED_FIELDS.includes(val as any), {
      message: 'Invalid sort field'
    })
    .transform(val => !val || val === '' ? 'order' : val as any),
  sortOrder: z.string().optional()
    .refine(val => !val || val === '' || ['asc', 'desc'].includes(val), {
      message: 'Invalid sort order'
    })
    .transform(val => !val || val === '' ? 'asc' : val as 'asc' | 'desc'),
});

// Phase ID validation
export const phaseIdSchema = z.object({
  id: objectIdSchema,
});

// Reorder phases schema
export const reorderPhasesSchema = z.object({
  phases: z.array(z.object({
    id: objectIdSchema,
    order: z.number().min(1, 'Order must be positive')
  })).min(1, 'At least one phase must be provided')
});

// Form schemas (frontend)
export const createPhaseFormSchema = z.object({
  title: z.string()
    .min(PHASE_CONSTANTS.TITLE.MIN_LENGTH, `Title must be at least ${PHASE_CONSTANTS.TITLE.MIN_LENGTH} characters`)
    .max(PHASE_CONSTANTS.TITLE.MAX_LENGTH, `Title cannot exceed ${PHASE_CONSTANTS.TITLE.MAX_LENGTH} characters`),
  
  description: z.string().optional(),
  
  projectId: z.string().min(1, 'Project is required'),
  
  order: z.string().optional(),
  
  startDate: z.string().min(1, 'Start date is required'),
  
  endDate: z.string().min(1, 'End date is required'),
  
  objectives: z.array(z.string()).default([]),
  
  deliverables: z.array(z.string()).default([]),
  
  resources: z.array(z.string()).default([]),
  
  risks: z.array(z.string()).default([]),
  
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
  
  approvalRequired: z.boolean().default(false),
});

export const updatePhaseFormSchema = createPhaseFormSchema.partial();

// Type exports
export type CreatePhaseData = z.infer<typeof createPhaseSchema>;
export type UpdatePhaseData = z.infer<typeof updatePhaseSchema>;
export type CreatePhaseFormData = z.infer<typeof createPhaseFormSchema>;
export type UpdatePhaseFormData = z.infer<typeof updatePhaseFormSchema>;
export type PhaseQueryParams = z.infer<typeof phaseQuerySchema>;
export type ReorderPhasesData = z.infer<typeof reorderPhasesSchema>;

// Utility functions
export const formatPhaseProgress = (progress: number): string => {
  return `${progress}%`;
};

export const getPhaseStatusColor = (status: string): string => {
  const colors = {
    'pending': 'text-muted-foreground bg-muted',
    'planning': 'text-blue-600 bg-blue-100',
    'in-progress': 'text-primary bg-primary/10',
    'on-hold': 'text-amber-600 bg-amber-100',
    'completed': 'text-emerald-600 bg-emerald-100',
    'cancelled': 'text-destructive bg-destructive/10'
  };
  return colors[status as keyof typeof colors] || colors['pending'];
};

export const formatPhaseDuration = (startDate: Date, endDate: Date): string => {
  const diffTime = endDate.getTime() - startDate.getTime();
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  
  if (diffDays === 1) return '1 day';
  if (diffDays < 7) return `${diffDays} days`;
  if (diffDays < 30) return `${Math.ceil(diffDays / 7)} weeks`;
  return `${Math.ceil(diffDays / 30)} months`;
};