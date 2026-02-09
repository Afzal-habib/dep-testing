import { useCallback, useEffect, useState } from 'react'
import { useThemeVariant } from '@/components/theme-variant-provider'
import { useToast } from '@/hooks/use-toast'

export interface UseThemeManagementReturn {
  currentTheme: string
  availableThemes: string[]
  isLoading: boolean
  error: string | null
  changeTheme: (theme: string) => Promise<boolean>
  refreshTheme: () => Promise<void>
  getThemeConfig: (variant?: string) => any
  canChangeTheme: boolean
}

export function useThemeManagement(): UseThemeManagementReturn {
  const { 
    currentVariant, 
    setVariant, 
    availableVariants, 
    getThemeConfig, 
    isLoading, 
    error, 
    refreshTheme 
  } = useThemeVariant()
  
  const { toast } = useToast()
  const [canChangeTheme, setCanChangeTheme] = useState(false)
  const [permissionChecked, setPermissionChecked] = useState(false)

  // Check if user can change themes (admin/super admin only) - only once
  useEffect(() => {
    if (permissionChecked) return
    
    const checkPermissions = async () => {
      try {
        // Try to access the admin themes endpoint to check permissions
        const response = await fetch('/api/settings/themes', {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        })
        
        setCanChangeTheme(response.ok)
        setPermissionChecked(true)
      } catch (error) {
        setCanChangeTheme(false)
        setPermissionChecked(true)
      }
    }
    
    checkPermissions()
  }, [permissionChecked])

  const changeTheme = useCallback(async (theme: string): Promise<boolean> => {
    if (!canChangeTheme) {
      toast({
        title: "Access Denied",
        description: "You don't have permission to change themes. Only administrators can modify global theme settings.",
        variant: "destructive",
      })
      return false
    }

    if (!availableVariants.includes(theme)) {
      toast({
        title: "Invalid Theme",
        description: `Theme '${theme}' is not available. Please select from available themes.`,
        variant: "destructive",
      })
      return false
    }

    try {
      const success = await setVariant(theme)
      
      if (success) {
        toast({
          title: "Theme Changed",
          description: `Theme has been changed to ${theme}. The change will apply to all users.`,
          variant: "default",
        })
        return true
      } else {
        toast({
          title: "Theme Change Failed",
          description: "Failed to change the theme. Please try again.",
          variant: "destructive",
        })
        return false
      }
    } catch (error: any) {
      console.error('Error changing theme:', error)
      toast({
        title: "Error",
        description: error.message || "An unexpected error occurred while changing the theme.",
        variant: "destructive",
      })
      return false
    }
  }, [canChangeTheme, availableVariants, setVariant, toast])

  return {
    currentTheme: currentVariant,
    availableThemes: availableVariants,
    isLoading,
    error,
    changeTheme,
    refreshTheme,
    getThemeConfig,
    canChangeTheme,
  }
}