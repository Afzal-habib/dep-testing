"use client"

import { createContext, useContext, useState, useTransition, useCallback, memo, ReactNode } from 'react'
import { useRouter, usePathname } from 'next/navigation'

interface NavigationContextType {
  isNavigating: boolean
  navigateTo: (path: string) => void
  currentPath: string
}

const NavigationContext = createContext<NavigationContextType | undefined>(undefined)

export const NavigationProvider = memo(function NavigationProvider({ children }: { children: ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()
  const [isPending, startTransition] = useTransition()
  const [isNavigating, setIsNavigating] = useState(false)

  const navigateTo = useCallback((path: string) => {
    // Don't navigate if already on the same page
    if (path === pathname) return

    // Show instant loading feedback
    setIsNavigating(true)

    // Use startTransition for non-blocking navigation
    startTransition(() => {
      router.push(path)
      // Reset loading state quickly
      setTimeout(() => setIsNavigating(false), 50)
    })
  }, [pathname, router])

  return (
    <NavigationContext.Provider value={{ 
      isNavigating: isNavigating || isPending, 
      navigateTo,
      currentPath: pathname || '/'
    }}>
      {children}
    </NavigationContext.Provider>
  )
})

export function useNavigation() {
  const context = useContext(NavigationContext)
  if (!context) {
    throw new Error('useNavigation must be used within NavigationProvider')
  }
  return context
}
