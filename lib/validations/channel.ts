import { z } from 'zod'

// Base constants for validation
export const CHANNEL_CONSTANTS = {
  NAME: {
    MIN_LENGTH: 1,
    MAX_LENGTH: 100,
  },
  TYPE: {
    VALUES: ['dm', 'group', 'project', 'department', 'department-category', 'multi-category', 'client-support'] as const,
    DEFAULT: 'group' as const,
  },
  DEPARTMENT_CATEGORY: {
    VALUES: ['sales', 'support', 'it', 'management'] as const,
  },
  PAGINATION: {
    DEFAULT_PAGE: 1,
    DEFAULT_LIMIT: 10,
    MAX_LIMIT: 100,
    MIN_PAGE: 1,
  },
  SORT: {
    ALLOWED_FIELDS: ['name', 'type', 'created_at', 'updated_at'] as const,
    DEFAULT_FIELD: 'updated_at' as const,
    DEFAULT_ORDER: 'desc' as const,
  },
} as const

// Custom validation helpers
const createStringValidator = (config: { min?: number; max?: number; required?: boolean }) => {
  let validator = z.string()

  if (config.min) {
    validator = validator.min(config.min, `Must be at least ${config.min} characters`)
  }

  if (config.max) {
    validator = validator.max(config.max, `Cannot exceed ${config.max} characters`)
  }

  // Trim all strings
  const trimmedValidator = validator.transform((val) => val.trim())

  if (config.required === false) {
    return trimmedValidator.optional()
  }

  return trimmedValidator
}

// Base channel schema
export const baseChannelSchema = z.object({
  type: z.enum(CHANNEL_CONSTANTS.TYPE.VALUES, {
    errorMap: () => ({ message: `Type must be one of: ${CHANNEL_CONSTANTS.TYPE.VALUES.join(', ')}` })
  }),
  name: createStringValidator({
    min: CHANNEL_CONSTANTS.NAME.MIN_LENGTH,
    max: CHANNEL_CONSTANTS.NAME.MAX_LENGTH,
    required: false
  }),
  mongo_department_id: z.string().optional(),
  mongo_project_id: z.string().optional(),
  is_private: z.boolean().default(false),
  categories: z.array(z.enum(CHANNEL_CONSTANTS.DEPARTMENT_CATEGORY.VALUES)).default([]),
  client_id: z.string().optional(),
  // Channel settings
  auto_sync_enabled: z.boolean().default(true),
  allow_external_members: z.boolean().default(false),
  admin_only_post: z.boolean().default(false),
  admin_only_add: z.boolean().default(false),
})

// Create channel schema
export const createChannelSchema = baseChannelSchema.extend({
  channel_members: z.array(z.string()).optional(),
  category: z.enum(CHANNEL_CONSTANTS.DEPARTMENT_CATEGORY.VALUES).optional(),
})

// Update channel schema
export const updateChannelSchema = z.object({
  name: createStringValidator({
    min: CHANNEL_CONSTANTS.NAME.MIN_LENGTH,
    max: CHANNEL_CONSTANTS.NAME.MAX_LENGTH,
    required: false
  }),
  is_private: z.boolean().optional(),
}).partial()

// Channel query schema for GET requests
export const channelQuerySchema = z.object({
  type: z.string().optional(),
  department_id: z.string().optional(),
  project_id: z.string().optional(),
})

// Channel ID parameter schema
export const channelIdSchema = z.object({
  channelId: z.string().uuid('Invalid channel ID format'),
})

// Message schemas
export const baseMessageSchema = z.object({
  channel_id: z.string().uuid('Invalid channel ID'),
  content: z.string().max(5000, 'Message too long').default(''),
  content_type: z.enum(['text', 'image', 'file', 'audio', 'system']).default('text'),
  thread_id: z.string().uuid().optional(),
  parent_message_id: z.string().uuid().optional(),
  mongo_mentioned_user_ids: z.array(z.string()).default([]),
  // Attachment IDs (if files were uploaded separately first)
  attachment_ids: z.array(z.string().uuid()).optional(),
  // Audio attachment data for voice messages
  audio_attachment: z.object({
    file_url: z.string().url(),
    file_name: z.string().default('Voice Message'),
    file_size: z.number().optional(),
    file_type: z.string().default('audio/webm'),
    duration_seconds: z.number().optional()
  }).optional(),
}).refine(
  (data) => data.content.trim().length > 0 || (data.attachment_ids && data.attachment_ids.length > 0),
  { message: 'Message must have content or at least one attachment' }
)

export const createMessageSchema = baseMessageSchema

export const updateMessageSchema = z.object({
  content: z.string().min(1, 'Message content is required').max(5000, 'Message too long'),
  attachments_to_remove: z.array(z.string().uuid()).optional(),
})

// Message query schema
export const messageQuerySchema = z.object({
  channel_id: z.string().uuid('Invalid channel ID'),
  limit: z.coerce.number().min(1).max(100).default(50),
  offset: z.coerce.number().min(0).default(0),
})

// Message ID parameter schema
export const messageIdSchema = z.object({
  messageId: z.string().uuid('Invalid message ID format'),
})

// Member schemas
export const addMemberSchema = z.object({
  channel_id: z.string().uuid(),
  mongo_member_id: z.string(),
  role: z.enum(['admin', 'member']).default('member'),
})

export const updateMemberStatusSchema = z.object({
  channel_id: z.string().uuid(),
  mongo_member_id: z.string(),
  is_online: z.boolean(),
})

// Reaction schema
export const createReactionSchema = z.object({
  message_id: z.string().uuid(),
  emoji: z.string().min(1).max(10),
})

// Read receipt schema
export const markAsReadSchema = z.object({
  message_id: z.string().uuid(),
})

// Bulk read receipt schema
export const markAllAsReadSchema = z.object({
  channel_id: z.string().uuid(),
  mark_all: z.literal(true),
})

// Trash query schema
export const trashQuerySchema = z.object({
  channelId: z.string().uuid().optional(),
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
})

// Search query schema
export const searchQuerySchema = z.object({
  channel_id: z.string().uuid(),
  query: z.string().min(1).max(500),
  limit: z.coerce.number().min(1).max(100).default(20),
  offset: z.coerce.number().min(0).default(0),
})

// Audit log query schema
export const auditLogQuerySchema = z.object({
  channel_id: z.string().uuid().optional(),
  message_id: z.string().uuid().optional(),
  actor_id: z.string().optional(),
  action: z.enum(['created', 'edited', 'trashed', 'restored', 'permanently_deleted']).optional(),
  start_date: z.string().datetime().optional(),
  end_date: z.string().datetime().optional(),
  limit: z.coerce.number().min(1).max(100).default(50),
  offset: z.coerce.number().min(0).default(0),
})

// Attachment upload schema
export const attachmentUploadSchema = z.object({
  channel_id: z.string().uuid(),
  message_id: z.string().uuid().optional(),
})

// Delete message schema
export const deleteMessageSchema = z.object({
  delete_type: z.enum(['trash', 'self', 'permanent']).default('trash'),
  reason: z.string().max(500).optional(),
})

// Toggle pin schema
export const togglePinSchema = z.object({
  channelId: z.string().uuid(),
})

// Archive channel schema
export const archiveChannelSchema = z.object({
  action: z.enum(['archive', 'unarchive']).default('archive'),
})

// Type exports for TypeScript
export type CreateChannelData = z.infer<typeof createChannelSchema>
export type UpdateChannelData = z.infer<typeof updateChannelSchema>
export type ChannelQueryParams = z.infer<typeof channelQuerySchema>
export type CreateMessageData = z.infer<typeof createMessageSchema>
export type UpdateMessageData = z.infer<typeof updateMessageSchema>
export type MessageQueryParams = z.infer<typeof messageQuerySchema>
export type AddMemberData = z.infer<typeof addMemberSchema>
export type UpdateMemberStatusData = z.infer<typeof updateMemberStatusSchema>
export type CreateReactionData = z.infer<typeof createReactionSchema>
export type MarkAsReadData = z.infer<typeof markAsReadSchema>
export type MarkAllAsReadData = z.infer<typeof markAllAsReadSchema>
export type TrashQueryParams = z.infer<typeof trashQuerySchema>
export type SearchQueryParams = z.infer<typeof searchQuerySchema>
export type AuditLogQueryParams = z.infer<typeof auditLogQuerySchema>
export type AttachmentUploadData = z.infer<typeof attachmentUploadSchema>
export type DeleteMessageData = z.infer<typeof deleteMessageSchema>
export type TogglePinData = z.infer<typeof togglePinSchema>
export type ArchiveChannelData = z.infer<typeof archiveChannelSchema>