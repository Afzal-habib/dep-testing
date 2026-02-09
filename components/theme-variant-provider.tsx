"use client"

import React, { createContext, useContext, useCallback, useState, useRef, memo, useEffect } from 'react'
import { THEME_VARIANTS, VALID_THEME_VARIANTS, type ThemeVariant } from '@/lib/constants/theme-variants'

interface ThemeVariantContextType {
  currentVariant: string
  setVariant: (variant: string) => Promise<boolean>
  availableVariants: string[]
  getThemeConfig: (variant?: string) => ThemeVariant | null
  isLoading: boolean
  error: string | null
  refreshTheme: () => Promise<void>
  syncTheme: () => void
}

const ThemeVariantContext = createContext<ThemeVariantContextType | undefined>(undefined)

export function useThemeVariant() {
  const context = useContext(ThemeVariantContext)
  if (context === undefined) {
    throw new Error('useThemeVariant must be used within a ThemeVariantProvider')
  }
  return context
}

interface ThemeVariantProviderProps {
  children: React.ReactNode
  defaultVariant?: string
}

export const ThemeVariantProvider = memo(function ThemeVariantProvider({ 
  children, 
  defaultVariant = 'default' 
}: ThemeVariantProviderProps) {
  const [currentVariant, setCurrentVariant] = useState(defaultVariant)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const appliedThemeRef = useRef<string>('')

  // Static theme configuration - no server dependency
  const themeConfig = THEME_VARIANTS
  const availableVariants = VALID_THEME_VARIANTS

  // Optimized theme application - runs once per theme change
  const applyThemeToDOM = useCallback((variant: string) => {
    if (typeof document === 'undefined' || appliedThemeRef.current === variant) {
      return // Skip if already applied
    }

    const root = document.documentElement
    const isDark = root.classList.contains('dark') || 
                   (window.matchMedia?.('(prefers-color-scheme: dark)').matches && 
                    !root.classList.contains('light'))
    
    const themeVariant = themeConfig[variant] || themeConfig.default
    const colors = isDark ? themeVariant.dark : themeVariant.light

    if (colors) {
      // Use a single RAF for all style updates
      requestAnimationFrame(() => {
        Object.entries(colors).forEach(([key, value]) => {
          root.style.setProperty(`--${key}`, value)
        })
        root.setAttribute('data-theme-variant', variant)
        appliedThemeRef.current = variant
      })
    }
  }, [themeConfig])

  // Initialize theme immediately without server fetch
  useEffect(() => {
    setError(null)
    applyThemeToDOM(currentVariant)
  }, [currentVariant, applyThemeToDOM])

  // Listen for theme mode changes (dark/light)
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    const handleChange = () => {
      // Reapply current theme when mode changes
      appliedThemeRef.current = '' // Force reapplication
      applyThemeToDOM(currentVariant)
    }
    
    mediaQuery.addEventListener('change', handleChange)
    return () => mediaQuery.removeEventListener('change', handleChange)
  }, [currentVariant, applyThemeToDOM])

  // Simplified theme setter - no server calls
  const setVariant = useCallback(async (variant: string): Promise<boolean> => {
    if (!availableVariants.includes(variant)) {
      return false
    }

    setCurrentVariant(variant)
    applyThemeToDOM(variant)

    // Optional: persist to localStorage
    try {
      localStorage.setItem('theme-variant', variant)
    } catch (error) {
      // Ignore localStorage errors
    }

    return true
  }, [availableVariants, applyThemeToDOM])

  const getThemeConfig = useCallback((variant?: string): ThemeVariant | null => {
    return themeConfig[variant || currentVariant] || null
  }, [currentVariant, themeConfig])

  const refreshTheme = useCallback(async () => {
    // No server fetch needed - just reapply current theme
    appliedThemeRef.current = ''
    applyThemeToDOM(currentVariant)
  }, [currentVariant, applyThemeToDOM])

  const syncTheme = useCallback(() => {
    appliedThemeRef.current = ''
    applyThemeToDOM(currentVariant)
  }, [currentVariant, applyThemeToDOM])

  // Load saved theme variant from localStorage on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem('theme-variant')
      if (saved && availableVariants.includes(saved)) {
        setCurrentVariant(saved)
      }
    } catch (error) {
      // Ignore localStorage errors
    }
  }, [availableVariants])

  const contextValue: ThemeVariantContextType = {
    currentVariant,
    setVariant,
    availableVariants,
    getThemeConfig,
    isLoading,
    error,
    refreshTheme,
    syncTheme
  }

  return (
    <ThemeVariantContext.Provider value={contextValue}>
      {children}
    </ThemeVariantContext.Provider>
  )
})