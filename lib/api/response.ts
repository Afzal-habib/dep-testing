/**
 * Standardized API Response Types and Error Handling
 * Provides consistent API responses and error handling
 */

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  errors?: Record<string, string[]>;
  meta?: {
    pagination?: {
      page: number;
      limit: number;
      total: number;
      pages: number;
    };
    stats?: Record<string, number>;
    cached?: boolean;
    timestamp?: string;
  };
}

export interface PaginationParams {
  page: number;
  limit: number;
  total: number;
  pages: number;
}

export interface ApiError {
  code: string;
  message: string;
  statusCode: number;
  details?: any;
}

export class ApiResponseBuilder {
  /**
   * Create success response
   */
  static success<T>(
    data: T,
    message?: string,
    meta?: ApiResponse<T>['meta']
  ): ApiResponse<T> {
    return {
      success: true,
      data,
      message,
      meta: {
        ...meta,
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Create error response
   */
  static error(
    message: string,
    statusCode: number = 500,
    errors?: Record<string, string[]>
  ): ApiResponse {
    return {
      success: false,
      error: message,
      errors,
      meta: {
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Create validation error response
   */
  static validationError(
    errors: Record<string, string[]>,
    message: string = 'Validation failed'
  ): ApiResponse {
    return {
      success: false,
      error: message,
      errors,
      meta: {
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Create paginated response
   */
  static paginated<T>(
    data: T[],
    pagination: PaginationParams,
    message?: string,
    stats?: Record<string, number>
  ): ApiResponse<T[]> {
    return {
      success: true,
      data,
      message,
      meta: {
        pagination,
        stats,
        timestamp: new Date().toISOString()
      }
    };
  }
}

/**
 * Enhanced Error Handler with Logging
 */
export class EnhancedErrorHandler {
  static async handleApiError(
    error: any,
    context: {
      endpoint: string;
      method: string;
      userId?: string;
      requestId?: string;
    }
  ): Promise<ApiResponse> {
    console.error(`[API Error] ${context.endpoint}:`, {
      error: error.message,
      stack: error.stack,
      context
    });

    // Handle specific error types
    if (error.name === 'ValidationError') {
      const validationErrors = this.formatValidationErrors(error);
      return ApiResponseBuilder.validationError(validationErrors);
    }

    if (error.name === 'CastError') {
      return ApiResponseBuilder.error('Invalid ID format', 400);
    }

    if (error.code === 11000) {
      return ApiResponseBuilder.error('Resource already exists', 409);
    }

    if (error.name === 'UnauthorizedError') {
      return ApiResponseBuilder.error('Unauthorized access', 401);
    }

    if (error.name === 'ForbiddenError') {
      return ApiResponseBuilder.error('Forbidden access', 403);
    }

    // Default server error
    return ApiResponseBuilder.error(
      process.env.NODE_ENV === 'production' 
        ? 'Internal server error' 
        : error.message,
      500
    );
  }

  private static formatValidationErrors(error: any): Record<string, string[]> {
    const errors: Record<string, string[]> = {};
    
    if (error.errors) {
      for (const [field, err] of Object.entries(error.errors)) {
        errors[field] = [(err as any).message];
      }
    }
    
    return errors;
  }
}

/**
 * API Response Middleware
 */
export function withApiHandler(handler: Function) {
  return async (req: Request, context?: any) => {
    try {
      const result = await handler(req, context);
      return result;
    } catch (error: any) {
      const errorResponse = await EnhancedErrorHandler.handleApiError(error, {
        endpoint: req.url,
        method: req.method,
        requestId: req.headers.get('x-request-id') || undefined
      });
      
      return Response.json(errorResponse, { 
        status: error.statusCode || 500 
      });
    }
  };
}

/**
 * Next.js API Response Helper
 */
export class NextApiResponse {
  static json(data: ApiResponse, status: number = 200) {
    return Response.json(data, { status });
  }

  static success<T>(data: T, message?: string, meta?: ApiResponse<T>['meta']) {
    const response = ApiResponseBuilder.success(data, message, meta);
    return this.json(response, 200);
  }

  static error(message: string, status: number = 500) {
    return this.json(ApiResponseBuilder.error(message, status), status);
  }

  static validationError(errors: Record<string, string[]>) {
    return this.json(ApiResponseBuilder.validationError(errors), 422);
  }

  static notFound(message: string = 'Resource not found') {
    return this.json(ApiResponseBuilder.error(message, 404), 404);
  }

  static unauthorized(message: string = 'Unauthorized') {
    return this.json(ApiResponseBuilder.error(message, 401), 401);
  }

  static forbidden(message: string = 'Forbidden') {
    return this.json(ApiResponseBuilder.error(message, 403), 403);
  }
}