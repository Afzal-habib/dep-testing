import { useState, useEffect, useCallback } from 'react'
import { useToast } from '@/hooks/use-toast'

export interface Setting {
  _id: string
  key: string
  value: any
  description?: string
  category: string
  isPublic: boolean
  metadata: {
    createdBy: string
    updatedBy: string
    createdAt: string
    updatedAt: string
  }
}

export interface ThemeVariant {
  name: string
  description: string
  light: Record<string, string>
  dark: Record<string, string>
}

export interface ThemeData {
  variants: Record<string, ThemeVariant>
  currentTheme: string
  availableThemes: string[]
}

interface UseSettingsReturn {
  settings: Setting[]
  themeData: ThemeData | null
  loading: boolean
  error: string | null
  fetchSettings: (category?: string) => Promise<void>
  fetchThemeData: () => Promise<void>
  updateSetting: (key: string, value: any, category?: string, description?: string) => Promise<boolean>
  updateTheme: (theme: string) => Promise<boolean>
  createSetting: (setting: Omit<Setting, '_id' | 'metadata'>) => Promise<boolean>
  getSetting: (key: string) => Setting | undefined
  getSettingValue: (key: string, defaultValue?: any) => any
}

export function useSettings(): UseSettingsReturn {
  const [settings, setSettings] = useState<Setting[]>([])
  const [themeData, setThemeData] = useState<ThemeData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [lastFetch, setLastFetch] = useState<{ settings: number, themes: number }>({ settings: 0, themes: 0 })
  const { toast } = useToast()

  // Fetch settings from API with rate limiting
  const fetchSettings = useCallback(async (category?: string) => {
    const now = Date.now()
    const timeSinceLastFetch = now - lastFetch.settings
    
    // Rate limit: Don't fetch more than once every 2 seconds
    if (timeSinceLastFetch < 2000) {
      console.log('Settings fetch rate limited, skipping...')
      return
    }

    try {
      setLoading(true)
      setError(null)
      setLastFetch(prev => ({ ...prev, settings: now }))

      const url = new URL('/api/settings', window.location.origin)
      if (category) {
        url.searchParams.set('category', category)
      }

      const response = await fetch(url.toString(), {
        cache: 'no-cache',
        headers: {
          'Cache-Control': 'no-cache'
        }
      })
      const data = await response.json()

      if (!response.ok) {
        // Handle rate limiting gracefully
        if (response.status === 429) {
          console.warn('Settings API rate limited, will retry later')
          return
        }
        throw new Error(data.error || 'Failed to fetch settings')
      }

      setSettings(data.data || [])
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to fetch settings'
      setError(errorMessage)
      console.error('Error fetching settings:', err)
      
      // Don't show toast for permission/rate limit errors
      if (!errorMessage.includes('Access denied') && !errorMessage.includes('rate limit')) {
        toast({
          title: "Error",
          description: errorMessage,
          variant: "destructive",
        })
      }
    } finally {
      setLoading(false)
    }
  }, [toast, lastFetch.settings])

  // Fetch theme data with rate limiting
  const fetchThemeData = useCallback(async () => {
    const now = Date.now()
    const timeSinceLastFetch = now - lastFetch.themes
    
    // Rate limit: Don't fetch more than once every 2 seconds
    if (timeSinceLastFetch < 2000) {
      console.log('Theme data fetch rate limited, skipping...')
      return
    }

    try {
      setError(null)
      setLastFetch(prev => ({ ...prev, themes: now }))

      const response = await fetch('/api/settings/themes', {
        cache: 'no-cache',
        headers: {
          'Cache-Control': 'no-cache'
        }
      })
      const data = await response.json()

      if (!response.ok) {
        // Handle rate limiting gracefully
        if (response.status === 429) {
          console.warn('Theme API rate limited, will retry later')
          return
        }
        throw new Error(data.error || 'Failed to fetch theme data')
      }

      setThemeData(data.data)
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to fetch theme data'
      setError(errorMessage)
      console.error('Error fetching theme data:', err)
      
      // Don't show toast for permission/rate limit errors
      if (!errorMessage.includes('Access denied') && !errorMessage.includes('rate limit')) {
        toast({
          title: "Error",
          description: errorMessage,
          variant: "destructive",
        })
      }
    }
  }, [toast, lastFetch.themes])

  // Update a setting
  const updateSetting = useCallback(async (
    key: string, 
    value: any, 
    category: string = 'general',
    description?: string
  ): Promise<boolean> => {
    try {
      setError(null)

      const response = await fetch('/api/settings', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          key,
          value,
          category,
          description
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Failed to update setting')
      }

      // Update local state
      setSettings(prev => {
        const existingIndex = prev.findIndex(s => s.key === key)
        if (existingIndex >= 0) {
          const updated = [...prev]
          updated[existingIndex] = data.data
          return updated
        } else {
          return [...prev, data.data]
        }
      })

      toast({
        title: "Success",
        description: "Setting updated successfully",
      })

      return true
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to update setting'
      setError(errorMessage)
      console.error('Error updating setting:', err)
      
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      })
      
      return false
    }
  }, [toast])

  // Update theme
  const updateTheme = useCallback(async (theme: string): Promise<boolean> => {
    try {
      setError(null)

      const response = await fetch('/api/settings/themes', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ theme }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Failed to update theme')
      }

      // Update local theme data
      setThemeData(prev => prev ? { ...prev, currentTheme: theme } : null)

      // Apply theme immediately by dispatching custom event
      window.dispatchEvent(new CustomEvent('themeVariantChange', { 
        detail: { theme, themeConfig: data.data.themeConfig } 
      }))

      toast({
        title: "Success",
        description: data.message || "Theme updated successfully",
      })

      return true
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to update theme'
      setError(errorMessage)
      console.error('Error updating theme:', err)
      
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      })
      
      return false
    }
  }, [toast])

  // Create a new setting
  const createSetting = useCallback(async (
    setting: Omit<Setting, '_id' | 'metadata'>
  ): Promise<boolean> => {
    try {
      setError(null)

      const response = await fetch('/api/settings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(setting),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Failed to create setting')
      }

      // Update local state
      if (Array.isArray(data.data)) {
        setSettings(prev => [...prev, ...data.data])
      } else {
        setSettings(prev => [...prev, data.data])
      }

      toast({
        title: "Success",
        description: "Setting created successfully",
      })

      return true
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to create setting'
      setError(errorMessage)
      console.error('Error creating setting:', err)
      
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      })
      
      return false
    }
  }, [toast])

  // Helper to get a specific setting
  const getSetting = useCallback((key: string): Setting | undefined => {
    return settings.find(s => s.key === key)
  }, [settings])

  // Helper to get a setting value with optional default
  const getSettingValue = useCallback((key: string, defaultValue?: any): any => {
    const setting = getSetting(key)
    return setting ? setting.value : defaultValue
  }, [getSetting])

  return {
    settings,
    themeData,
    loading,
    error,
    fetchSettings,
    fetchThemeData,
    updateSetting,
    updateTheme,
    createSetting,
    getSetting,
    getSettingValue
  }
}