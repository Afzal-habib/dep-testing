'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { usePermissions } from '@/hooks/use-permissions'
import { useToast } from '@/hooks/use-toast'
import { PermissionError } from '@/components/ui/error-display'
import { ProfessionalLoader } from '../shared/professional-loader'
import { useNavigation } from '../providers/navigation-provider'

interface RouteGuardProps {
  children: React.ReactNode
  resource: string
  action?: string
  redirectTo?: string
  showToast?: boolean
  showErrorPage?: boolean
}
/**
 * Route-level permission guard
 * Redirects users if they don't have required permissions
 */
export function RouteGuard({
  children,
  resource,
  action = 'read',
  redirectTo = '/dashboard',
  showToast = false,
  showErrorPage = true
}: RouteGuardProps) {
  const { hasPermission, loading, permissions } = usePermissions()
  const router = useRouter()
  const { toast } = useToast()
  const [shouldRedirect, setShouldRedirect] = useState(false)
  const [hasCheckedPermissions, setHasCheckedPermissions] = useState(false)
    const { navigateTo, isNavigating } = useNavigation()
  
  useEffect(() => {
    // Don't check permissions until loading is complete and we have actually checked
    if (loading) {
      setHasCheckedPermissions(false)
      return
    }

    // Wait a tick to ensure permissions are fully loaded
    const timeoutId = setTimeout(() => {
      const hasRequiredPermission = hasPermission(resource, action)
      setHasCheckedPermissions(true)

      if (!hasRequiredPermission) {
        if (showToast && !shouldRedirect) {
          toast({
            title: 'Access Denied',
            description: `You don't have permission to access this page (${resource}:${action})`,
            variant: 'destructive'
          })
        }

        if (!showErrorPage && !shouldRedirect) {
          setShouldRedirect(true)
          // Add a delay to prevent immediate navigation conflicts
          setTimeout(() => {
            navigateTo(redirectTo)
          }, 200)
        }
      } else {
        // Reset redirect flag if permission is now available
        setShouldRedirect(false)
      }
    }, 50) // Small delay to ensure permissions are ready

    return () => clearTimeout(timeoutId)
  }, [hasPermission, loading, resource, action, redirectTo, showToast, showErrorPage, router, toast, shouldRedirect])

  // Show loading while checking permissions
  if (loading || !hasCheckedPermissions) {
    return (
      <div className="fixed inset-0 bg-background flex items-center justify-center z-50">
        <ProfessionalLoader
          size="md"
        />
      </div>
    )
  }

  // Show permission error page if no permission and showErrorPage is true
  if (hasCheckedPermissions && !hasPermission(resource, action)) {
    if (showErrorPage && !shouldRedirect) {
      return (
        <PermissionError
          resource={resource}
          action={action}
          onRetry={() => window.location.reload()}
        />
      )
    }
    return null
  }

  return <>{children}</>
}

/**
 * Higher-order component for route protection
 */
export function withRouteGuard<P extends object>(
  Component: React.ComponentType<P>,
  resource: string,
  action: string = 'read',
  redirectTo: string = '/dashboard'
) {
  return function GuardedComponent(props: P) {
    return (
      <RouteGuard resource={resource} action={action} redirectTo={redirectTo}>
        <Component {...props} />
      </RouteGuard>
    )
  }
}
