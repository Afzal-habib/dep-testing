"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { memo, useMemo, Suspense } from "react"
import dynamic from "next/dynamic"

// Lazy load the charts component for better initial page load
const LazyDashboardCharts = dynamic(
  () => import("./charts").then(mod => ({ default: mod.DashboardCharts })),
  { 
    ssr: false,
    loading: () => (
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i} className={`col-span-2 ${i % 2 === 0 ? 'lg:col-span-2' : 'lg:col-span-4'}`}>
            <CardHeader>
              <div className="h-4 w-32 bg-muted rounded animate-pulse mb-2" />
              <div className="h-3 w-48 bg-muted rounded animate-pulse" />
            </CardHeader>
            <CardContent>
              <div className="h-[300px] bg-muted animate-pulse rounded-md flex items-center justify-center">
                <div className="text-muted-foreground text-sm">Loading charts...</div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }
)

function OptimizedDashboardChartsComponent() {
  return (
    <Suspense fallback={
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-6">
        <div className="col-span-full">
          <div className="h-4 w-32 bg-muted rounded animate-pulse mb-4" />
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-[300px] bg-muted animate-pulse rounded-md" />
            ))}
          </div>
        </div>
      </div>
    }>
      <LazyDashboardCharts />
    </Suspense>
  )
}

// Export the optimized version
export const OptimizedDashboardCharts = memo(OptimizedDashboardChartsComponent)