"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { memo, useMemo } from "react"
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, 
  LineChart, Line, AreaChart, Area, PieChart, Pie, Cell 
} from "recharts"

// Sample data for the charts
const pipelineData = [
    { stage: "Development", count: 120 },
    { stage: "Designing", count: 86 },
    { stage: "SEO", count: 65 },
    { stage: "Marketing", count: 42 },
    { stage: "Sales", count: 28 },
]

const revenueData = [
    { month: "Jan", revenue: 45000 },
    { month: "Feb", revenue: 52000 },
    { month: "Mar", revenue: 48000 },
    { month: "Apr", revenue: 61000 },
    { month: "May", revenue: 58000 },
    { month: "Jun", revenue: 65000 },
    { month: "Jul", revenue: 71000 },
    { month: "Aug", revenue: 68000 },
    { month: "Sep", revenue: 75000 },
    { month: "Oct", revenue: 82000 },
    { month: "Nov", revenue: 87000 },
    { month: "Dec", revenue: 92000 },
]

const customerGrowthData = [
    { month: "Jan", customers: 250 },
    { month: "Feb", customers: 285 },
    { month: "Mar", customers: 310 },
    { month: "Apr", customers: 345 },
    { month: "May", customers: 370 },
    { month: "Jun", customers: 395 },
    { month: "Jul", customers: 430 },
    { month: "Aug", customers: 465 },
    { month: "Sep", customers: 490 },
    { month: "Oct", customers: 525 },
    { month: "Nov", customers: 560 },
    { month: "Dec", customers: 600 },
]

const industryData = [
    { name: "Development", value: 35 },
    { name: "Designing", value: 25 },
    { name: "SEO", value: 20 },
    { name: "Marketing", value: 12 },
    { name: "Sales", value: 8 },
]

const COLORS = ['#4f46e5', '#7c3aed', '#2563eb', '#0891b2', '#0d9488']

function DashboardChartsComponent() {
  // Memoize chart data to prevent recreation on every render
  const chartData = useMemo(() => ({
    pipelineData,
    revenueData, 
    customerGrowthData,
    industryData
  }), [])

  return (
    <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-6">
      {/* Industry Distribution Chart */}
      <Card className="col-span-2 lg:col-span-2">
        <CardHeader>
          <CardTitle>Deals by Industry</CardTitle>
          <CardDescription>Distribution of deals across sectors</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData.industryData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {chartData.industryData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value: number) => [`${value}%`, "Percentage"]}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Sales Pipeline Chart */}
      <Card className="col-span-2 lg:col-span-4">
        <CardHeader>
          <CardTitle>Sales Pipeline</CardTitle>
          <CardDescription>Distribution of deals by stage</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData.pipelineData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="stage" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="count" name="Deals" fill="#4f46e5" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Revenue Trend Chart */}
      <Card className="col-span-2 lg:col-span-3">
        <CardHeader>
          <CardTitle>Revenue Trend</CardTitle>
          <CardDescription>Monthly revenue performance</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData.revenueData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" />
                <YAxis />
                <Tooltip
                  formatter={(value: number) => [`$${value.toLocaleString()}`, "Revenue"]}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="revenue"
                  name="Revenue"
                  stroke="#4f46e5"
                  strokeWidth={2}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Customer Growth Chart */}
      <Card className="col-span-2 lg:col-span-3">
        <CardHeader>
          <CardTitle>Customer Growth</CardTitle>
          <CardDescription>Total customers over time</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData.customerGrowthData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" />
                <YAxis />
                <Tooltip
                  formatter={(value: number) => [value.toLocaleString(), "Customers"]}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="customers"
                  name="Total Customers"
                  fill="#4f46e5"
                  fillOpacity={0.2}
                  stroke="#4f46e5"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// Memoize the component to prevent unnecessary re-renders
export const DashboardCharts = memo(DashboardChartsComponent)