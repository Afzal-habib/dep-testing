"use client"

import { usePathname } from "next/navigation"
import type React from "react"
import { AdminLayout } from "./admin-layout"
import { memo, useMemo } from "react"

interface LayoutProviderProps {
    children: React.ReactNode
}

// Memoized layout provider to prevent unnecessary re-renders
export const LayoutProvider = memo(function LayoutProvider({ children }: LayoutProviderProps) {
    const pathname = usePathname()

    // Memoize the route check to prevent recalculation on every render
    const isAuthRoute = useMemo(() => 
        pathname?.startsWith("/auth"), 
        [pathname]
    )

    // No artificial delays - render immediately for better performance
    if (isAuthRoute) {
        return <>{children}</>
    }

    return <AdminLayout>{children}</AdminLayout>
})