"use client"

import { useEffect, useState } from 'react'
import { useNavigation } from '@/components/providers/navigation-provider'
import { ProfessionalLoader } from './professional-loader'

export function NavigationLoadingBar() {
  const { isNavigating } = useNavigation()
  const [progress, setProgress] = useState(0)

  useEffect(() => {
    if (isNavigating) {
      setProgress(20) // Instant feedback
      const timer = setTimeout(() => setProgress(90), 100)
      return () => clearTimeout(timer)
    } else {
      setProgress(100)
      const timer = setTimeout(() => setProgress(0), 200)
      return () => clearTimeout(timer)
    }
  }, [isNavigating])

  if (progress === 0) return null

  return (
    <div className="fixed top-0 left-0 right-0 z-[9999] h-1">
      <div 
        className="h-full bg-primary transition-all duration-200 ease-out shadow-lg shadow-primary/50"
        style={{ width: `${progress}%` }}
      />
    </div>
    // <div className="fixed inset-0 bg-background flex items-center justify-center z-50">
    //   <ProfessionalLoader
    //     size="md"
    //   />
    // </div>

  )
}
