/**
 * Standardized API Error Response Utility
 * Provides consistent error responses across all API endpoints
 */

import { NextResponse } from "next/server"

export interface APIError {
  success: false
  error: string
  code?: string
  details?: any
  timestamp: string
  statusCode: number
}

export interface APISuccess<T = any> {
  success: true
  data: T
  message?: string
  timestamp: string
}

/**
 * Create a standardized error response
 */
export function createAPIErrorResponse(
  message: string,
  statusCode: number = 500,
  code?: string,
  details?: any
): NextResponse {
  const errorResponse: APIError = {
    success: false,
    error: message,
    ...(code && { code }),
    ...(details && { details }),
    timestamp: new Date().toISOString(),
    statusCode
  }

  return NextResponse.json(errorResponse, { status: statusCode })
}

/**
 * Create a standardized success response
 */
export function createAPISuccessResponse<T>(
  data: T,
  message?: string,
  statusCode: number = 200
): NextResponse {
  const successResponse: APISuccess<T> = {
    success: true,
    data,
    ...(message && { message }),
    timestamp: new Date().toISOString()
  }

  return NextResponse.json(successResponse, { status: statusCode })
}

/**
 * Permission error responses
 */
export const APIErrors = {
  // Authentication errors
  AUTHENTICATION_REQUIRED: (details?: any) => 
    createAPIErrorResponse(
      "Authentication required. Please log in to access this resource.",
      401,
      "AUTH_REQUIRED",
      details
    ),

  INVALID_SESSION: (details?: any) => 
    createAPIErrorResponse(
      "Your session has expired. Please log in again.",
      401,
      "SESSION_EXPIRED",
      details
    ),

  // Authorization errors
  PERMISSION_DENIED: (resource: string, action: string, details?: any) => 
    createAPIErrorResponse(
      `Access denied. You don't have permission to ${action} ${resource}.`,
      403,
      "PERMISSION_DENIED",
      { resource, action, ...details }
    ),

  INSUFFICIENT_PERMISSIONS: (details?: any) => 
    createAPIErrorResponse(
      "You don't have sufficient permissions to perform this action.",
      403,
      "INSUFFICIENT_PERMISSIONS",
      details
    ),

  // Rate limiting errors
  RATE_LIMIT_EXCEEDED: (retryAfter: number, details?: any) => 
    createAPIErrorResponse(
      `Too many requests. Please try again in ${retryAfter} seconds.`,
      429,
      "RATE_LIMIT_EXCEEDED",
      { retryAfter, ...details }
    ),

  // Validation errors
  VALIDATION_FAILED: (validationErrors: any[], details?: any) => 
    createAPIErrorResponse(
      "Request validation failed. Please check your input.",
      400,
      "VALIDATION_FAILED",
      { validationErrors, ...details }
    ),

  INVALID_INPUT: (field: string, details?: any) => 
    createAPIErrorResponse(
      `Invalid input for field: ${field}`,
      400,
      "INVALID_INPUT",
      { field, ...details }
    ),

  // Resource errors
  RESOURCE_NOT_FOUND: (resource: string, id?: string, details?: any) => 
    createAPIErrorResponse(
      `${resource} not found${id ? ` with ID: ${id}` : ""}.`,
      404,
      "RESOURCE_NOT_FOUND",
      { resource, id, ...details }
    ),

  RESOURCE_ALREADY_EXISTS: (resource: string, field: string, value: string, details?: any) => 
    createAPIErrorResponse(
      `${resource} with ${field} '${value}' already exists.`,
      409,
      "RESOURCE_EXISTS",
      { resource, field, value, ...details }
    ),

  // Server errors
  INTERNAL_SERVER_ERROR: (details?: any) => 
    createAPIErrorResponse(
      "An internal server error occurred. Please try again later.",
      500,
      "INTERNAL_ERROR",
      details
    ),

  DATABASE_ERROR: (details?: any) => 
    createAPIErrorResponse(
      "Database operation failed. Please try again later.",
      500,
      "DATABASE_ERROR",
      details
    ),

  // Custom error
  CUSTOM: (message: string, statusCode: number = 400, code?: string, details?: any) => 
    createAPIErrorResponse(message, statusCode, code, details)
}

/**
 * Helper to determine if an error is an API error response
 */
export function isAPIError(response: any): response is APIError {
  return response && typeof response === 'object' && response.success === false
}

/**
 * Helper to extract error message from various error types
 */
export function extractErrorMessage(error: any): string {
  if (error instanceof Response) {
    return "Request failed"
  }
  
  if (error instanceof Error) {
    return error.message
  }
  
  if (typeof error === 'string') {
    return error
  }
  
  if (error && typeof error === 'object') {
    return error.error || error.message || "Unknown error"
  }
  
  return "Unknown error occurred"
}

/**
 * Middleware error handler that creates proper API responses
 */
export function handleMiddlewareError(error: any, resource: string, action: string): NextResponse {
  console.error('Middleware error:', error)
  
  // If it's already a properly formatted Response, return it
  if (error instanceof Response) {
    return error as NextResponse
  }
  
  // Determine error type and create appropriate response
  const errorMessage = extractErrorMessage(error)
  
  if (errorMessage.includes('Rate limit')) {
    return APIErrors.RATE_LIMIT_EXCEEDED(60, { originalError: errorMessage })
  }
  
  if (errorMessage.includes('Authentication required') || errorMessage.includes('login')) {
    return APIErrors.AUTHENTICATION_REQUIRED({ originalError: errorMessage })
  }
  
  if (errorMessage.includes('Access denied') || errorMessage.includes('permission')) {
    return APIErrors.PERMISSION_DENIED(resource, action, { originalError: errorMessage })
  }
  
  if (errorMessage.includes('validation') || errorMessage.includes('Invalid')) {
    return APIErrors.VALIDATION_FAILED([], { originalError: errorMessage })
  }
  
  // Default to internal server error
  return APIErrors.INTERNAL_SERVER_ERROR({ originalError: errorMessage })
}