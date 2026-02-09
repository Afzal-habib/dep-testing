"use client"

import { Moon, Sun } from "lucide-react"
import { useTheme } from "next-themes"
import { Button } from "@/components/ui/button"
import { useThemeVariant } from "@/components/theme-variant-provider"

export function ThemeToggle() {
  const { setTheme, theme, resolvedTheme } = useTheme()
  const { syncTheme } = useThemeVariant()

  // Sync theme colors when toggling
  const handleThemeToggle = () => {
    const newTheme = resolvedTheme === 'dark' ? 'light' : 'dark'
    console.log('🎨 Theme toggle:', resolvedTheme, '->', newTheme)
    setTheme(newTheme)
    
    // Force sync after a short delay to ensure DOM updates
    setTimeout(() => {
      syncTheme()
    }, 100)
  }

  return (
    <Button 
      variant="ghost" 
      size="sm" 
      onClick={handleThemeToggle}
      title={`Switch to ${resolvedTheme === 'dark' ? 'light' : 'dark'} theme`}
    >
      <Sun className="h-4 w-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
      <Moon className="absolute h-4 w-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
      <span className="sr-only">Toggle theme</span>
    </Button>
  )
}
