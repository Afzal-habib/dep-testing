import { ZodError } from 'zod'

export interface APIError {
  success: false
  error: string
  details?: any
  code?: string
}

export interface ValidationError {
  field: string
  message: string
  code?: string
}

export interface ParsedError {
  message: string
  validationErrors?: ValidationError[]
  code?: string
  isValidationError: boolean
}

/**
 * Generic error parser that handles different types of API errors
 * including Zod validation errors, MongoDB errors, and generic API errors
 */
export function parseAPIError(error: any): ParsedError {
  // Handle Zod validation errors
  if (error.name === 'ZodError' || error.details) {
    const zodError = error.name === 'ZodError' ? error : error.details

    if (zodError && Array.isArray(zodError)) {
      const validationErrors: ValidationError[] = zodError.map((err: any) => ({
        field: err.path?.join('.') || 'unknown',
        message: err.message || 'Invalid value',
        code: err.code
      }))

      return {
        message: 'Validation failed. Please check the form fields.',
        validationErrors,
        isValidationError: true
      }
    }
  }

  // Handle API error responses
  if (error && typeof error === 'object') {
    // Handle structured API errors
    if (error.error) {
      return {
        message: error.error,
        code: error.code,
        validationErrors: error.details ? parseValidationDetails(error.details) : undefined,
        isValidationError: !!error.details
      }
    }

    // Handle fetch errors or generic errors
    if (error.message) {
      return {
        message: error.message,
        isValidationError: false
      }
    }
  }

  // Handle string errors
  if (typeof error === 'string') {
    return {
      message: error,
      isValidationError: false
    }
  }

  // Fallback
  return {
    message: 'An unexpected error occurred',
    isValidationError: false
  }
}

/**
 * Parse validation details from various formats
 */
function parseValidationDetails(details: any): ValidationError[] {
  if (!details) return []

  if (Array.isArray(details)) {
    return details.map((detail: any) => {
      // Handle Zod error format
      if (detail.code === 'unrecognized_keys') {
        return {
          field: detail.keys?.join(', ') || 'unknown',
          message: `Unrecognized field(s): ${detail.keys?.join(', ') || 'unknown'}`,
          code: detail.code
        }
      }

      // Handle standard validation error format
      return {
        field: detail.path?.join('.') || detail.field || 'unknown',
        message: detail.message || 'Invalid value',
        code: detail.code
      }
    })
  }

  if (typeof details === 'object') {
    return Object.entries(details).map(([field, message]) => ({
      field,
      message: typeof message === 'string' ? message : String(message || 'Invalid value'),
      code: typeof message === 'object' && message && 'code' in message ? (message as any).code : undefined
    }))
  }

  return []
}

/**
 * Format validation errors for display
 */
export function formatValidationErrors(validationErrors: ValidationError[]): string {
  if (!validationErrors || validationErrors.length === 0) return ''

  return validationErrors
    .map(err => `${err.field}: ${err.message}`)
    .join('\n')
}

/**
 * Generic error handler for API responses
 * Returns a standardized error object for UI consumption
 */
export function handleAPIError(error: any, fallbackMessage = 'An error occurred'): ParsedError {
  // Only log in development
  // if (process.env.NODE_ENV === 'development') {
  // console.error('API Error:', error)
  // }

  // Handle empty or null errors
  if (!error || (typeof error === 'object' && Object.keys(error).length === 0)) {
    return {
      message: fallbackMessage || 'An unexpected error occurred',
      isValidationError: false
    }
  }

  try {
    return parseAPIError(error)
  } catch (parseError) {
    // Only log parse errors in development
    if (process.env.NODE_ENV === 'development') {
      console.error('Error parsing API error:', parseError)
    }
    return {
      message: fallbackMessage,
      isValidationError: false
    }
  }
}

/**
 * Check if an error is a validation error
 */
export function isValidationError(error: ParsedError): boolean {
  return error.isValidationError
}

/**
 * Get user-friendly error message
 */
export function getErrorMessage(error: ParsedError): string {
  if (error.validationErrors && error.validationErrors.length > 0) {
    return error.message
  }

  return error.message
}

/**
 * Get field-specific validation errors
 */
export function getFieldErrors(error: ParsedError): Record<string, string> {
  if (!error.validationErrors) return {}

  return error.validationErrors.reduce((acc, err) => {
    acc[err.field] = err.message
    return acc
  }, {} as Record<string, string>)
}