import { NextResponse } from "next/server"
import { ZodError } from "zod"
import { AuditLogger } from "./audit-logger"

export enum ErrorCode {
  VALIDATION_ERROR = "VALIDATION_ERROR",
  AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR",
  AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR",
  NOT_FOUND = "NOT_FOUND",
  CONFLICT = "CONFLICT",
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",
  INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR",
  DATABASE_ERROR = "DATABASE_ERROR",
  NETWORK_ERROR = "NETWORK_ERROR",
}

export interface ApiError {
  code: ErrorCode
  message: string
  details?: any
  statusCode: number
}

export class ApiErrorHandler {
  static createError(
    code: ErrorCode,
    message: string,
    details?: any,
    statusCode: number = 500
  ): ApiError {
    return {
      code,
      message,
      details,
      statusCode,
    }
  }

  static handleValidationError(error: ZodError): ApiError {
    const details = error.errors.map((err) => ({
      field: err.path.join("."),
      message: err.message,
    }))

    return this.createError(
      ErrorCode.VALIDATION_ERROR,
      "Validation failed",
      { fields: details },
      400
    )
  }

  static handleMongooseError(error: any): ApiError {
    // Handle duplicate key error
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0]
      return this.createError(
        ErrorCode.CONFLICT,
        `${field} already exists`,
        { field },
        409
      )
    }

    // Handle validation error
    if (error.name === "ValidationError") {
      const details = Object.values(error.errors).map((err: any) => ({
        field: err.path,
        message: err.message,
      }))

      return this.createError(
        ErrorCode.VALIDATION_ERROR,
        "Validation failed",
        { fields: details },
        400
      )
    }

    // Handle cast error (invalid ObjectId)
    if (error.name === "CastError") {
      return this.createError(
        ErrorCode.VALIDATION_ERROR,
        "Invalid ID format",
        { field: error.path },
        400
      )
    }

    return this.createError(
      ErrorCode.DATABASE_ERROR,
      "Database operation failed",
      undefined,
      500
    )
  }

  static async handleError(
    error: unknown,
    context?: {
      userId?: string
      userEmail?: string
      action?: string
      resource?: string
      resourceId?: string
      ipAddress?: string
      userAgent?: string
    }
  ): Promise<NextResponse> {
    let apiError: ApiError

    // Handle different error types
    if (error instanceof ZodError) {
      apiError = this.handleValidationError(error)
    } else if (error && typeof error === "object" && "code" in error) {
      apiError = this.handleMongooseError(error)
    } else if (error instanceof Error) {
      // Check for specific error messages
      const message = error.message.toLowerCase()

      if (message.includes("unauthorized") || message.includes("invalid credentials")) {
        apiError = this.createError(
          ErrorCode.AUTHENTICATION_ERROR,
          "Authentication failed",
          undefined,
          401
        )
      } else if (message.includes("forbidden") || message.includes("insufficient permissions")) {
        apiError = this.createError(
          ErrorCode.AUTHORIZATION_ERROR,
          "Insufficient permissions",
          undefined,
          403
        )
      } else if (message.includes("not found")) {
        apiError = this.createError(
          ErrorCode.NOT_FOUND,
          "Resource not found",
          undefined,
          404
        )
      } else if (message.includes("already exists") || message.includes("duplicate")) {
        apiError = this.createError(
          ErrorCode.CONFLICT,
          "Resource already exists",
          undefined,
          409
        )
      } else {
        apiError = this.createError(
          ErrorCode.INTERNAL_SERVER_ERROR,
          "Internal server error",
          undefined,
          500
        )
      }
    } else {
      apiError = this.createError(
        ErrorCode.INTERNAL_SERVER_ERROR,
        "An unexpected error occurred",
        undefined,
        500
      )
    }

    // Log the error for audit purposes
    if (context) {
      await AuditLogger.log({
        userId: context.userId,
        userEmail: context.userEmail,
        action: context.action || "UNKNOWN",
        resource: context.resource || "UNKNOWN",
        resourceId: context.resourceId,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        success: false,
        errorMessage: apiError.message,
        details: {
          errorCode: apiError.code,
          errorDetails: apiError.details,
        },
      })
    }

    // Log to console for debugging (in development)
    if (process.env.NODE_ENV === "development") {
      console.error("API Error:", {
        error: apiError,
        originalError: error,
        context,
        stack: error instanceof Error ? error.stack : undefined,
      })
    }

    return NextResponse.json(
      {
        success: false,
        error: {
          code: apiError.code,
          message: apiError.message,
          ...(apiError.details && { details: apiError.details }),
        },
      },
      { status: apiError.statusCode }
    )
  }

  static createSuccessResponse<T>(
    data: T,
    message?: string,
    statusCode: number = 200
  ): NextResponse {
    return NextResponse.json(
      {
        success: true,
        ...(message && { message }),
        data,
      },
      { status: statusCode }
    )
  }

  static createPaginatedResponse<T>(
    data: T[],
    pagination: {
      page: number
      limit: number
      total: number
      pages: number
    },
    message?: string
  ): NextResponse {
    return NextResponse.json(
      {
        success: true,
        ...(message && { message }),
        data,
        pagination,
      },
      { status: 200 }
    )
  }
}

// Utility function to extract client info from request
export function getClientInfo(request: Request) {
  const headers = request.headers

  return {
    ipAddress:
      headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      headers.get("x-real-ip") ||
      headers.get("cf-connecting-ip") ||
      "unknown",
    userAgent: headers.get("user-agent") || "unknown",
  }
}

// Utility function for consistent error responses
export function createErrorResponse(
  message: string,
  statusCode: number = 400,
  details?: any
) {
  return NextResponse.json(
    {
      success: false,
      error: {
        // ...(code && { code }),
        message,
        ...(details && { details }),
      },
    },
    { status: statusCode }
  )
}
