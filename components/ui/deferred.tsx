"use client"

import { useEffect, useState, type ReactNode } from 'react'

interface DeferredProps {
  children: ReactNode
  delay?: number
  fallback?: ReactNode
}

/**
 * Defer rendering of non-critical components to reduce initial blocking time
 * This breaks up long tasks and improves Time to Interactive
 */
export function Deferred({ children, delay = 0, fallback = null }: DeferredProps) {
  const [shouldRender, setShouldRender] = useState(delay === 0)

  useEffect(() => {
    if (delay === 0) return

    // Use setTimeout to defer rendering and break up blocking tasks
    const timer = setTimeout(() => {
      setShouldRender(true)
    }, delay)

    return () => clearTimeout(timer)
  }, [delay])

  if (!shouldRender) {
    return <>{fallback}</>
  }

  return <>{children}</>
}

/**
 * Defer rendering using requestIdleCallback for optimal performance
 * Renders when browser is idle to avoid blocking critical tasks
 */
export function DeferredIdle({ children, fallback = null }: Omit<DeferredProps, 'delay'>) {
  const [shouldRender, setShouldRender] = useState(false)

  useEffect(() => {
    // Use requestIdleCallback if available, otherwise fallback to setTimeout
    if (typeof window !== 'undefined' && 'requestIdleCallback' in window) {
      const handle = requestIdleCallback(() => {
        setShouldRender(true)
      })
      return () => cancelIdleCallback(handle)
    } else {
      const timer = setTimeout(() => {
        setShouldRender(true)
      }, 1)
      return () => clearTimeout(timer)
    }
  }, [])

  if (!shouldRender) {
    return <>{fallback}</>
  }

  return <>{children}</>
}
