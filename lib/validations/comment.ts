import { z } from 'zod';

export const COMMENT_CONSTANTS = {
  CONTENT: { MIN_LENGTH: 1, MAX_LENGTH: 2000 },
  PAGINATION: { DEFAULT_PAGE: 1, DEFAULT_LIMIT: 20, MAX_LIMIT: 100, MIN_PAGE: 1 },
  SORT: { ALLOWED_FIELDS: ['createdAt', 'updatedAt'] as const }
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

// Base comment schema
export const baseCommentSchema = z.object({
  content: z.string()
    .min(COMMENT_CONSTANTS.CONTENT.MIN_LENGTH, 'Comment cannot be empty')
    .max(COMMENT_CONSTANTS.CONTENT.MAX_LENGTH, 'Comment too long')
    .transform(val => val.trim()),
  
  taskId: objectIdSchema,
  
  projectId: objectIdSchema,
  
  authorId: objectIdSchema,
  
  mentions: z.array(objectIdSchema)
    .optional()
    .default([]),
  
  parentCommentId: optionalObjectIdSchema,
});

// Create comment schema
export const createCommentSchema = baseCommentSchema
  .omit({ authorId: true }) // Author will be set from session
  .strict();

// Update comment schema
export const updateCommentSchema = z.object({
  content: z.string()
    .min(COMMENT_CONSTANTS.CONTENT.MIN_LENGTH, 'Comment cannot be empty')
    .max(COMMENT_CONSTANTS.CONTENT.MAX_LENGTH, 'Comment too long')
    .transform(val => val.trim()),
  
  mentions: z.array(objectIdSchema)
    .optional()
    .default([]),
}).strict();

// Form schemas (frontend)
export const createCommentFormSchema = z.object({
  content: z.string()
    .min(COMMENT_CONSTANTS.CONTENT.MIN_LENGTH, 'Comment cannot be empty')
    .max(COMMENT_CONSTANTS.CONTENT.MAX_LENGTH, 'Comment too long')
    .transform(val => val.trim()),
  
  taskId: z.string().min(1, 'Task is required'),
  projectId: z.string().min(1, 'Project is required'),
  mentions: z.array(z.string()).optional().default([]),
  parentCommentId: z.string().optional(),
});

export const updateCommentFormSchema = z.object({
  content: z.string()
    .min(COMMENT_CONSTANTS.CONTENT.MIN_LENGTH, 'Comment cannot be empty')
    .max(COMMENT_CONSTANTS.CONTENT.MAX_LENGTH, 'Comment too long')
    .transform(val => val.trim()),
  
  mentions: z.array(z.string()).optional().default([]),
});

// Query schema for fetching comments
export const commentQuerySchema = z.object({
  taskId: optionalObjectIdSchema,
  projectId: optionalObjectIdSchema,
  authorId: optionalObjectIdSchema,
  page: z.string().optional().transform(val => val ? parseInt(val, 10) : COMMENT_CONSTANTS.PAGINATION.DEFAULT_PAGE),
  limit: z.string().optional().transform(val => val ? parseInt(val, 10) : COMMENT_CONSTANTS.PAGINATION.DEFAULT_LIMIT),
  sortBy: z.enum(COMMENT_CONSTANTS.SORT.ALLOWED_FIELDS).optional().default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
});

// Comment ID validation
export const commentIdSchema = z.object({
  id: objectIdSchema,
});

// Type exports
export type CreateCommentData = z.infer<typeof createCommentSchema>;
export type UpdateCommentData = z.infer<typeof updateCommentSchema>;
export type CreateCommentFormData = z.infer<typeof createCommentFormSchema>;
export type UpdateCommentFormData = z.infer<typeof updateCommentFormSchema>;
export type CommentQueryParams = z.infer<typeof commentQuerySchema>;

// Mention extraction utility function
export const extractMentions = (content: string): string[] => {
  const mentionRegex = /@\[([^\]]+)\]\((\w+)\)/g; // Format: @[Display Name](userId)
  const mentions: string[] = [];
  let match;
  
  while ((match = mentionRegex.exec(content)) !== null) {
    const userId = match[2];
    if (userId && /^[0-9a-fA-F]{24}$/.test(userId)) {
      mentions.push(userId);
    }
  }
  
  return [...new Set(mentions)]; // Remove duplicates
};

// Content processing utility - converts mentions to display format
export const processMentionContent = (content: string, users: any[]): string => {
  const mentionRegex = /@\[([^\]]+)\]\((\w+)\)/g;
  
  return content.replace(mentionRegex, (match, displayName, userId) => {
    const user = users.find(u => u._id === userId);
    return user ? `@${user.name}` : displayName;
  });
};