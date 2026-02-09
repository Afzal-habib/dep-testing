/**
 * Error Display Component
 * Shows user-friendly error messages for various error types
 */

import React from 'react'
import { AlertCircle, Lock, RefreshCw, Home, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useRouter } from 'next/navigation'
import { cn } from '@/lib/utils'

interface PermissionErrorProps {
  title?: string
  message?: string
  resource?: string
  action?: string
  showRetry?: boolean
  showGoHome?: boolean
  onRetry?: () => void
  className?: string
}

export function PermissionError({
  title = "Access Denied",
  message,
  resource,
  action,
  showRetry = true,
  showGoHome = true,
  onRetry,
  className = ""
}: PermissionErrorProps) {
  const router = useRouter()

  // Generate contextual message based on resource and action
  const getContextualMessage = () => {
    if (message) return message

    if (resource && action) {
      const resourceName = resource.replace(/[-_]/g, ' ').toLowerCase()
      const actionName = action.toLowerCase()

      switch (actionName) {
        case 'read':
        case 'view':
          return `You don't have permission to view ${resourceName}.`
        case 'create':
        case 'add':
          return `You don't have permission to create ${resourceName}.`
        case 'update':
        case 'edit':
          return `You don't have permission to edit ${resourceName}.`
        case 'delete':
        case 'remove':
          return `You don't have permission to delete ${resourceName}.`
        case 'manage':
          return `You don't have permission to manage ${resourceName}.`
        default:
          return `You don't have permission to perform this action on ${resourceName}.`
      }
    }

    return "You don't have sufficient permissions to access this resource."
  }

  const handleGoHome = () => {
    router.push('/dashboard')
  }

  const handleRetry = () => {
    if (onRetry) {
      onRetry()
    } else {
      window.location.reload()
    }
  }

  return (
    <div className={`flex items-center justify-center min-h-[400px] p-4 ${className}`}>
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
            <Lock className="h-6 w-6 text-destructive" />
          </div>
          <CardTitle className="text-xl font-semibold text-foreground">
            {title}
          </CardTitle>
          <CardDescription className="text-muted-foreground">
            {getContextualMessage()}
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center space-y-4">
          <div className="text-sm text-muted-foreground">
            Contact your administrator if you believe this is an error.
          </div>

          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            {showGoHome && (
              <Button
                onClick={handleGoHome}
                variant="default"
                className="flex items-center gap-2"
              >
                <Home className="h-4 w-4" />
                Go to Dashboard
              </Button>
            )}

            {showRetry && (
              <Button
                onClick={handleRetry}
                variant="outline"
                className="flex items-center gap-2"
              >
                <RefreshCw className="h-4 w-4" />
                Try Again
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

/**
 * Network Error Display Component
 */
interface NetworkErrorProps {
  title?: string
  message?: string
  onRetry?: () => void
  className?: string
}

export function NetworkError({
  title = "Connection Error",
  message = "Unable to connect to the server. Please check your internet connection.",
  onRetry,
  className = ""
}: NetworkErrorProps) {
  return (
    <div className={`flex items-center justify-center min-h-[400px] p-4 ${className}`}>
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900/20">
            <AlertCircle className="h-6 w-6 text-amber-600 dark:text-amber-400" />
          </div>
          <CardTitle className="text-xl font-semibold text-foreground">
            {title}
          </CardTitle>
          <CardDescription className="text-muted-foreground">
            {message}
          </CardDescription>
        </CardHeader>
        {onRetry && (
          <CardContent className="text-center">
            <Button
              onClick={onRetry}
              variant="default"
              className="flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Retry
            </Button>
          </CardContent>
        )}
      </Card>
    </div>
  )
}

/**
 * Generic Error Boundary Component
 */
interface ErrorDisplayProps {
  error: any
  resource?: string
  action?: string
  onRetry?: () => void
  className?: string
}

export function ErrorDisplay({
  error,
  resource,
  action,
  onRetry,
  className = ""
}: ErrorDisplayProps) {
  // Determine error type and show appropriate component
  if (error?.statusCode === 403 || error?.code === 'PERMISSION_DENIED') {
    return (
      <PermissionError
        resource={resource}
        action={action}
        message={error.error || error.message}
        onRetry={onRetry}
        className={className}
      />
    )
  }

  if (error?.statusCode === 401 || error?.code === 'AUTH_REQUIRED') {
    return (
      <PermissionError
        title="Authentication Required"
        message="Please log in to access this resource."
        showRetry={false}
        onRetry={onRetry}
        className={className}
      />
    )
  }

  if (!navigator.onLine || error?.code === 'NETWORK_ERROR') {
    return (
      <NetworkError
        onRetry={onRetry}
        className={className}
      />
    )
  }

  // Default error display
  return (
    <div className={`flex items-center justify-center min-h-[400px] p-4 ${className}`}>
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
            <AlertCircle className="h-6 w-6 text-destructive" />
          </div>
          <CardTitle className="text-xl font-semibold text-foreground">
            Something went wrong
          </CardTitle>
          <CardDescription className="text-muted-foreground">
            {error?.error || error?.message || "An unexpected error occurred."}
          </CardDescription>
        </CardHeader>
        {onRetry && (
          <CardContent className="text-center">
            <Button
              onClick={onRetry}
              variant="default"
              className="flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Try Again
            </Button>
          </CardContent>
        )}
      </Card>
    </div>
  )
}

/**
 * Error Display Component
 * Shows user-friendly error messages for various error types
 */

interface BaseErrorDisplayProps {
  error?: string | Error | null;
  title?: string;
  variant?: 'default' | 'destructive' | 'warning' | 'minimal';
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  showDismiss?: boolean;
  showRetry?: boolean;
  onDismiss?: () => void;
  onRetry?: () => void;
  className?: string;
  children?: React.ReactNode;
}

export function BaseErrorDisplay({
  error,
  title = 'Error',
  variant = 'destructive',
  size = 'md',
  showIcon = true,
  showDismiss = false,
  showRetry = false,
  onDismiss,
  onRetry,
  className,
  children,
}: BaseErrorDisplayProps) {
  if (!error) return null;

  const errorMessage = typeof error === 'string' ? error : error.message || 'An unexpected error occurred';

  const variants = {
    default: 'bg-muted border-border text-foreground',
    destructive: 'bg-destructive/10 border-destructive/20 text-destructive',
    warning: 'bg-amber-50 border-amber-200 text-amber-900 dark:bg-amber-900/20 dark:border-amber-800 dark:text-amber-400',
    minimal: 'bg-transparent border-transparent text-destructive',
  };

  const sizes = {
    sm: 'p-3 text-sm',
    md: 'p-4 text-sm',
    lg: 'p-6 text-base',
  };

  const iconVariants = {
    default: 'text-muted-foreground',
    destructive: 'text-destructive',
    warning: 'text-amber-500 dark:text-amber-400',
    minimal: 'text-red-500',
  };

  return (
    <div
      className={cn(
        'border rounded-lg flex items-start space-x-3',
        variants[variant],
        sizes[size],
        className
      )}
      role="alert"
      aria-live="polite"
    >
      {showIcon && (
        <AlertCircle className={cn('h-5 w-5 mt-0.5 flex-shrink-0', iconVariants[variant])} />
      )}

      <div className="flex-1 min-w-0">
        {title && (
          <h3 className="font-medium mb-1">
            {title}
          </h3>
        )}
        <p className="text-sm opacity-90">
          {errorMessage}
        </p>
        {children && (
          <div className="mt-2">
            {children}
          </div>
        )}
      </div>

      <div className="flex items-center space-x-2 flex-shrink-0">
        {showRetry && onRetry && (
          <button
            onClick={onRetry}
            className={cn(
              'inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors',
              'h-8 w-8 hover:bg-black/5 focus:outline-none focus:ring-2 focus:ring-offset-2',
              variant === 'destructive' && 'hover:bg-red-100 focus:ring-red-500',
              variant === 'warning' && 'hover:bg-yellow-100 focus:ring-yellow-500',
              variant === 'default' && 'hover:bg-gray-100 focus:ring-gray-500'
            )}
            title="Retry"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        )}

        {showDismiss && onDismiss && (
          <button
            onClick={onDismiss}
            className={cn(
              'inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors',
              'h-8 w-8 hover:bg-black/5 focus:outline-none focus:ring-2 focus:ring-offset-2',
              variant === 'destructive' && 'hover:bg-red-100 focus:ring-red-500',
              variant === 'warning' && 'hover:bg-yellow-100 focus:ring-yellow-500',
              variant === 'default' && 'hover:bg-gray-100 focus:ring-gray-500'
            )}
            title="Dismiss"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
};