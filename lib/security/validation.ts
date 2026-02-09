import { z } from "zod"

// Security utilities for input validation and sanitization
export class SecurityUtils {
  // Sanitize string inputs to prevent XSS
  static sanitizeString(input: string): string {
    return input
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
      .replace(/javascript:/gi, '') // Remove javascript: protocol
      .replace(/on\w+=/gi, '') // Remove event handlers
      .trim()
  }

  // Validate email format with additional security checks
  static validateEmail(email: string): boolean {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
    
    // Additional security checks
    const hasValidLength = email.length <= 254 // RFC 5321 limit
    const hasValidLocalPart = email.split('@')[0]?.length <= 64 // RFC 5321 limit
    const noConsecutiveDots = !email.includes('..')
    const noStartEndDots = !email.startsWith('.') && !email.endsWith('.')
    
    return emailRegex.test(email) && 
           hasValidLength && 
           hasValidLocalPart && 
           noConsecutiveDots && 
           noStartEndDots
  }

  // Alias for validateEmail for consistency
  static isValidEmail(email: string): boolean {
    return this.validateEmail(email)
  }

  // Validate phone number
  static validatePhone(phone: string): boolean {
    // Allow international formats: +1234567890, (123) 456-7890, 123-456-7890, etc.
    const phoneRegex = /^[\+]?[1-9][\d]{0,15}$|^[\(\+\-\s\d\)]{10,20}$/
    return phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''))
  }

  // Check for common SQL injection patterns
  static containsSQLInjection(input: string): boolean {
    const sqlPatterns = [
      // More specific SQL injection patterns that are less likely to trigger false positives
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|UNION|SCRIPT)\b[\s]+)/i, // Must be followed by whitespace
      /(--|\/\*|\*\/);/,  // Comments followed by semicolon
      /[\s;](OR|AND)[\s]+\d+[\s]*=[\s]*\d+/i, // Classic SQL injection patterns
      /[\s;](OR|AND)[\s]+['"`]\w+['"`][\s]*=[\s]*['"`]\w+['"`]/i, // String-based injections
      /UNION[\s]+SELECT/i, // Union-based injections
      /[\s;](DROP|DELETE)[\s]+/i, // Dangerous operations
    ]
    
    return sqlPatterns.some(pattern => pattern.test(input))
  }

  // Check for XSS patterns
  static containsXSS(input: string): boolean {
    const xssPatterns = [
      /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
      /<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<img[\s\S]*?onerror[\s\S]*?>/gi,
      /data:text\/html/gi
    ]
    
    return xssPatterns.some(pattern => pattern.test(input))
  }

  // Comprehensive input validation
  static validateInput(input: any, type: 'string' | 'email' | 'phone' | 'password'): {
    isValid: boolean
    sanitized?: string
    errors: string[]
  } {
    const errors: string[] = []
    
    if (typeof input !== 'string') {
      errors.push('Input must be a string')
      return { isValid: false, errors }
    }

    // Check for malicious patterns
    if (this.containsSQLInjection(input)) {
      errors.push('Input contains potentially malicious SQL patterns')
    }

    if (this.containsXSS(input)) {
      errors.push('Input contains potentially malicious XSS patterns')
    }

    // Type-specific validation
    switch (type) {
      case 'email':
        if (!this.validateEmail(input)) {
          errors.push('Invalid email format')
        }
        break
      
      case 'phone':
        if (input && !this.validatePhone(input)) {
          errors.push('Invalid phone number format')
        }
        break
      
      case 'password':
        if (input.length < 6) {
          errors.push('Password must be at least 6 characters long')
        }
        if (input.length > 128) {
          errors.push('Password is too long')
        }
        break
      
      case 'string':
        if (input.length > 1000) {
          errors.push('Input is too long')
        }
        break
    }

    const sanitized = this.sanitizeString(input)
    
    return {
      isValid: errors.length === 0,
      sanitized,
      errors
    }
  }

  // Generate secure random tokens
  static generateSecureToken(length: number = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    let result = ''
    
    // Use crypto.getRandomValues for better security
    const array = new Uint8Array(length)
    crypto.getRandomValues(array)
    
    for (let i = 0; i < length; i++) {
      result += chars[array[i] % chars.length]
    }
    
    return result
  }

  // Validate ObjectId format for MongoDB
  static isValidObjectId(id: string): boolean {
    const objectIdRegex = /^[0-9a-fA-F]{24}$/
    return objectIdRegex.test(id)
  }

  // Check password strength
  static checkPasswordStrength(password: string): {
    score: number
    feedback: string[]
    isStrong: boolean
  } {
    const feedback: string[] = []
    let score = 0

    // Length check
    if (password.length >= 8) score += 1
    else feedback.push('Use at least 8 characters')

    if (password.length >= 12) score += 1
    else feedback.push('Consider using 12+ characters for better security')

    // Character variety
    if (/[a-z]/.test(password)) score += 1
    else feedback.push('Include lowercase letters')

    if (/[A-Z]/.test(password)) score += 1
    else feedback.push('Include uppercase letters')

    if (/\d/.test(password)) score += 1
    else feedback.push('Include numbers')

    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 1
    else feedback.push('Include special characters')

    // Common patterns check
    if (!/(.)\1{2,}/.test(password)) score += 1
    else feedback.push('Avoid repeating characters')

    const isStrong = score >= 5

    return { score, feedback, isStrong }
  }
}

// Extended validation schemas with security checks
export const secureRegisterSchema = z.object({
  name: z
    .string()
    .min(1, "Name is required")
    .min(2, "Name must be at least 2 characters")
    .max(50, "Name cannot exceed 50 characters")
    .refine(
      (val) => {
        const validation = SecurityUtils.validateInput(val, 'string')
        return validation.isValid
      },
      { message: "Name contains invalid characters" }
    ),
  email: z
    .string()
    .min(1, "Email is required")
    .email("Invalid email format")
    .refine(
      (val) => SecurityUtils.validateEmail(val),
      { message: "Invalid email format" }
    )
    .refine(
      (val) => {
        const validation = SecurityUtils.validateInput(val, 'email')
        return validation.isValid
      },
      { message: "Email contains invalid characters" }
    ),
  password: z
    .string()
    .min(1, "Password is required")
    .min(6, "Password must be at least 6 characters")
    .max(128, "Password cannot exceed 128 characters")
    .refine(
      (val) => {
        const validation = SecurityUtils.validateInput(val, 'password')
        return validation.isValid
      },
      { message: "Password contains invalid characters" }
    ),
  role: z.enum(["admin", "user", "manager"]).default("user"),
  phone: z
    .string()
    .optional()
    .refine(
      (val) => {
        if (!val) return true
        return SecurityUtils.validatePhone(val)
      },
      { message: "Invalid phone number format" }
    ),
  department: z
    .string()
    .optional()
    .refine(
      (val) => {
        if (!val) return true
        const validation = SecurityUtils.validateInput(val, 'string')
        return validation.isValid
      },
      { message: "Department contains invalid characters" }
    ),
})

export const secureUpdateUserSchema = z.object({
  name: z
    .string()
    .min(2, "Name must be at least 2 characters")
    .max(50, "Name cannot exceed 50 characters")
    .refine(
      (val) => {
        const validation = SecurityUtils.validateInput(val, 'string')
        return validation.isValid
      },
      { message: "Name contains invalid characters" }
    )
    .optional(),
  email: z
    .string()
    .email("Invalid email format")
    .refine(
      (val) => SecurityUtils.validateEmail(val),
      { message: "Invalid email format" }
    )
    .refine(
      (val) => {
        const validation = SecurityUtils.validateInput(val, 'email')
        return validation.isValid
      },
      { message: "Email contains invalid characters" }
    )
    .optional(),
  role: z.enum(["admin", "user", "manager"]).optional(),
  phone: z
    .string()
    .optional()
    .refine(
      (val) => {
        if (!val) return true
        return SecurityUtils.validatePhone(val)
      },
      { message: "Invalid phone number format" }
    ),
  department: z
    .string()
    .optional()
    .refine(
      (val) => {
        if (!val) return true
        const validation = SecurityUtils.validateInput(val, 'string')
        return validation.isValid
      },
      { message: "Department contains invalid characters" }
    ),
})

export type SecureRegisterInput = z.infer<typeof secureRegisterSchema>
export type SecureUpdateUserInput = z.infer<typeof secureUpdateUserSchema>
