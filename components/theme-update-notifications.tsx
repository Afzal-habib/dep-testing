"use client"

import { useEffect } from 'react'
import { useToast } from '@/hooks/use-toast'
import { useThemeVariant } from '@/components/theme-variant-provider'

export function ThemeUpdateNotifications() {
  const { toast } = useToast()
  const { currentVariant, error } = useThemeVariant()

  useEffect(() => {
    // Listen for global theme change events
    const handleThemeChange = (event: CustomEvent) => {
      const { theme } = event.detail
      
      // Only show notification if this is a different theme than what we currently have
      if (theme !== currentVariant) {
        toast({
          title: "Theme Updated",
          description: `System theme has been changed to ${theme}. Changes applied automatically.`,
          duration: 4000,
        })
      }
    }

    // Listen for theme change events
    window.addEventListener('themeVariantChange', handleThemeChange as EventListener)

    return () => {
      window.removeEventListener('themeVariantChange', handleThemeChange as EventListener)
    }
  }, [currentVariant, toast])

  // Show error notifications for theme loading issues
  useEffect(() => {
    if (error) {
      toast({
        title: "Theme Loading Error",
        description: error,
        variant: "destructive",
        duration: 5000,
      })
    }
  }, [error, toast])

  return null // This component doesn't render anything
}