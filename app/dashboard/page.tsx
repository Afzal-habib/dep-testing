"use client"

import { Users, Building2, Target, TrendingUp } from "lucide-react"
import { useAuthUser } from "@/hooks/use-auth-user"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { ChartErrorBoundary } from "@/components/ui/chart-error-boundary"
import { memo, useMemo, Suspense } from "react"
import dynamic from "next/dynamic"


// Lazy load heavy components with optimized loading
const DashboardCharts = dynamic(
  () => import("@/components/dashboard/charts-lazy").then(mod => ({ default: mod.OptimizedDashboardCharts })),
  {
    ssr: false,
    loading: () => (
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i} className={`col-span-2 ${i === 0 ? 'lg:col-span-2' : i === 1 ? 'lg:col-span-4' : 'lg:col-span-3'}`}>
            <CardHeader>
              <div className="h-4 w-32 bg-muted rounded animate-pulse mb-2" />
              <div className="h-3 w-48 bg-muted rounded animate-pulse" />
            </CardHeader>
            <CardContent>
              <div className="h-[300px] bg-muted animate-pulse rounded-md" />
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }
)


function DashboardPage() {
  const { user, loading } = useAuthUser()

  // Memoize static data to prevent recreation on every render
  const stats = useMemo(() => [
    {
      title: "Total Users",
      value: "1,234",
      change: "+12%",
      icon: Users,
      color: "text-blue-600",
    },
    {
      title: "Active Deals",
      value: "856",
      change: "+8%",
      icon: Target,
      color: "text-green-600",
    },
    {
      title: "Companies",
      value: "432",
      change: "+15%",
      icon: Building2,
      color: "text-purple-600",
    },
    {
      title: "Revenue",
      value: "$124,500",
      change: "+23%",
      icon: TrendingUp,
      color: "text-orange-600",
    },
  ], [])

  // Show loading state
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading dashboard...</p>
        </div>
      </div>
    )
  }
  return (
    <div className="space-y-6">
      {/* Welcome Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Welcome back, {user?.name || 'User'}!</h1>
          <p className="text-muted-foreground">Here&apos;s what&apos;s happening with your CRM today.</p>
        </div>
        <div className="flex items-center space-x-4">
          <Avatar className="h-12 w-12">
            {user?.avatar ? (
              <AvatarImage src={user.avatar} alt={user.name || "User"} className="object-cover" />
            ) : (
              <AvatarFallback className="bg-primary text-white text-xl font-semibold">
                {user?.name
                  ? (() => {
                      const parts = user.name.trim().split(' ');
                      if (parts.length === 1) {
                        return parts[0][0].toUpperCase();
                      }
                      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                    })()
                  : ''}
              </AvatarFallback>
            )}
          </Avatar>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat, index) => (
          <Card key={index}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
              <stat.icon className={`h-4 w-4 ${stat.color}`} />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stat.value}</div>
              <p className="text-xs text-muted-foreground">
                <span className="text-green-600">{stat.change}</span> from last month
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
      {/* Charts Section */}
      <ChartErrorBoundary>
        <Suspense fallback={
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-6">
            {Array.from({ length: 4 }).map((_, i) => (
              <Card key={i} className="col-span-2 lg:col-span-3">
                <CardHeader>
                  <div className="h-4 w-32 bg-muted rounded animate-pulse mb-2" />
                  <div className="h-3 w-48 bg-muted rounded animate-pulse" />
                </CardHeader>
                <CardContent>
                  <div className="h-[300px] bg-muted animate-pulse rounded-md" />
                </CardContent>
              </Card>
            ))}
          </div>
        }>
          <DashboardCharts />
        </Suspense>
      </ChartErrorBoundary>

      {/* Main Content Grid */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {/* Quick Actions */}
        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Common tasks to get you started</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center space-x-3 p-3 rounded-lg border cursor-pointer transition-colors">
              <Users className="h-5 w-5 text-blue-600" />
              <div>
                <p className="font-medium">Manage Users</p>
                <p className="text-sm text-muted-foreground">Add or edit system users</p>
              </div>
            </div>
            <div className="flex items-center space-x-3 p-3 rounded-lg border cursor-pointer transition-colors">
              <Target className="h-5 w-5 text-green-600" />
              <div>
                <p className="font-medium">View Deals</p>
                <p className="text-sm text-muted-foreground">Track your sales pipeline</p>
              </div>
            </div>
            <div className="flex items-center space-x-3 p-3 rounded-lg border cursor-pointer transition-colors">
              <Building2 className="h-5 w-5 text-purple-600" />
              <div>
                <p className="font-medium">Companies</p>
                <p className="text-sm text-muted-foreground">Manage company records</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>Latest updates in your CRM</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 rounded-full bg-blue-600 mt-2"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">New user registered</p>
                <p className="text-xs text-muted-foreground">Afzal Habib joined the system</p>
                <p className="text-xs text-muted-foreground">2 hours ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 rounded-full bg-green-600 mt-2"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Deal closed</p>
                <p className="text-xs text-muted-foreground">$15,000 deal with Acme Corp</p>
                <p className="text-xs text-muted-foreground">4 hours ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 rounded-full bg-orange-600 mt-2"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Meeting scheduled</p>
                <p className="text-xs text-muted-foreground">Client call with Tech Solutions</p>
                <p className="text-xs text-muted-foreground">6 hours ago</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* System Status */}
        <Card>
          <CardHeader>
            <CardTitle>System Status</CardTitle>
            <CardDescription>Current system information</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Database</span>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 rounded-full bg-green-600"></div>
                <span className="text-sm text-green-600">Connected</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Authentication</span>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 rounded-full bg-green-600"></div>
                <span className="text-sm text-green-600">Active</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">API Status</span>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 rounded-full bg-green-600"></div>
                <span className="text-sm text-green-600">Operational</span>
              </div>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Your Role</span>
              <span className="text-sm font-medium capitalize">{user?.roleDisplayName || user?.role || "User"}</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

// Memoize the component to prevent unnecessary re-renders
export default memo(DashboardPage)




