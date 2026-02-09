"use client";

import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import { useProjectAnalytics, EnhancedAnalyticsData, useAnalyticsAutoRefresh } from "@/hooks/use-analytics";
import { useQueryClient } from "@tanstack/react-query";
import {
  TrendingUp,
  TrendingDown,
  Calendar,
  DollarSign,
  Users,
  AlertTriangle,
  CheckCircle,
  Clock,
  Target,
  BarChart3,
  RefreshCw,
  Download,
  Activity,
  Zap,
  PieChart as PieChartIcon,
  Globe,
  Brain,
  Shield,
  Settings,
  Award,
  ChevronUp,
  ChevronDown,
  ArrowRight,
  TrendingDown as TrendingDownIcon,
  Filter
} from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import GenericReportExporter from '@/components/shared/GenericReportExporter';
import GenericFilter, { FilterConfig } from '@/components/shared/generic-filter';
import { useToast } from '@/hooks/use-toast';
import { useDepartments } from '@/hooks/use-departments';
import { useUsers } from '@/hooks/use-users';

interface ProjectAnalyticsProps {
  projectId: string;
}

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#84cc16'];

export function ProjectAnalytics({ projectId }: ProjectAnalyticsProps) {
  // All useState hooks first
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d' | '1y'>('30d');
  const [activeTab, setActiveTab] = useState('overview');
  const [refreshing, setRefreshing] = useState(false);
  const [filterOpen, setFilterOpen] = useState(false);
  const [filterValues, setFilterValues] = useState<Record<string, any>>({});

  // All useRef hooks
  const filterButtonRef = React.useRef<HTMLButtonElement | null>(null);
  const previousAnalyticsRef = useRef<EnhancedAnalyticsData | null>(null);

  // All custom hooks
  const { toast } = useToast();
  const { departments } = useDepartments();
  const { users } = useUsers();

  // Build backend filter object
  const backendFilters = useMemo(() => {
    const filters: any = {};
    if (filterValues.departmentId && filterValues.departmentId !== 'all') {
      filters.departmentId = filterValues.departmentId;
    }
    if (filterValues.userId && filterValues.userId !== 'all') {
      filters.userId = filterValues.userId;
    }
    if (filterValues.metricType && filterValues.metricType !== 'all') {
      filters.metricType = filterValues.metricType;
    }
    return filters;
  }, [filterValues]);

  const { analytics, loading, error, refetch } = useProjectAnalytics(projectId, timeRange, backendFilters);

  // useAnalyticsAutoRefresh hook
  useAnalyticsAutoRefresh(projectId, refetch);

  // Filter configuration for analytics
  const analyticsFilterConfig: FilterConfig = useMemo(() => ({
    fields: [
      {
        key: 'departmentId',
        label: 'Department',
        type: 'select',
        placeholder: 'All Departments',
        options: [
          { value: 'all', label: 'All Departments' },
          ...(departments || []).filter((d: any) => d.status === 'active').map((d: any) => ({ value: d._id, label: d.name }))
        ],
        searchable: true,
        cols: 12
      },
      {
        key: 'userId',
        label: 'Team Member',
        type: 'select',
        placeholder: 'All Users',
        options: [
          { value: 'all', label: 'All Users' },
          ...(users || []).filter((u: any) => u.status === 'active').map((u: any) => ({ value: u._id, label: u.name }))
        ],
        searchable: true,
        cols: 12
      },
      {
        key: 'metricType',
        label: 'Metric Type',
        type: 'select',
        placeholder: 'All Metrics',
        options: [
          { value: 'all', label: 'All Metrics' },
          { value: 'tasks', label: 'Tasks Only' },
          { value: 'budget', label: 'Budget Only' },
        ],
        cols: 12
      },
    ],
    defaultValues: { departmentId: 'all', userId: 'all', metricType: 'all' }
  }), [departments, users]);

  // Apply filters function
  const applyFilters = useCallback((values: any) => {
    setFilterValues(values);
    // Trigger refetch with new filters
    setTimeout(() => refetch(), 100);
  }, [refetch]);

  // Compute number of applied filters
  const filterCount = useMemo(() => {
    let count = 0;
    if (filterValues.departmentId && filterValues.departmentId !== 'all') count++;
    if (filterValues.userId && filterValues.userId !== 'all') count++;
    if (filterValues.metricType && filterValues.metricType !== 'all') count++;
    return count;
  }, [filterValues]);

  // Data extraction (backend already filtered)
  const analyticsData = analytics as EnhancedAnalyticsData | null;
  const kpiData = analyticsData?.kpi;
  const teamData = analyticsData?.team;
  const resourceData = analyticsData?.resources;
  const collaborationData = analyticsData?.collaboration;
  const insights = analyticsData?.insights;
  const risks = analyticsData?.risks;

  // All useEffect hooks at the end
  useEffect(() => {
    if (projectId && timeRange) {
      refetch();
    }
  }, [projectId, timeRange, refetch]);

  useEffect(() => {
    if (previousAnalyticsRef.current && analytics &&
      JSON.stringify(previousAnalyticsRef.current) !== JSON.stringify(analytics) &&
      !loading && !refreshing) {
      toast({
        title: "Data Updated",
        description: "Analytics data has been automatically refreshed with the latest information.",
        duration: 2000,
      });
    }
    previousAnalyticsRef.current = analytics;
  }, [analytics, loading, refreshing, toast]);


  const handleRefresh = async () => {
    setRefreshing(true);
    await refetch();
    setRefreshing(false);
    toast({
      title: "Analytics Refreshed",
      description: "Project analytics data has been updated successfully.",
    });
  };

  // Prepare export data based on active tab
  const getExportData = () => {
    switch (activeTab) {
      case 'team':
        return {
          moduleName: 'analytics-departments',
          data: teamData?.departments || []
        };
      case 'resources':
        return {
          moduleName: 'analytics-budget',
          data: analytics?.resources?.budget?.breakdown ? Object.entries(analytics.resources.budget.breakdown).map(([category, value]) => ({
            category,
            allocated: value,
            actual: 0, // Would need actual data
            variance: 0,
            utilization: 0,
            remaining: value,
            status: 'good'
          })) : []
        };
      case 'risks':
        return {
          moduleName: 'analytics-risks',
          data: analytics?.risks || []
        };
      default:
        return {
          moduleName: 'analytics',
          data: [{
            metric: 'Task Completion',
            value: `${analytics?.kpi?.taskCompletion || 0}%`,
            category: 'Performance',
            status: 'Good',
            trend: 'Up',
            lastUpdated: new Date()
          }]
        };
    }
  };

  const handleExportComplete = (result: any) => {
    if (result.success) {
      toast({
        title: "Export Successful",
        description: `Analytics report exported successfully as ${result.fileName}`,
      });
    } else {
      toast({
        title: "Export Failed",
        description: result.message,
        variant: "destructive",
      });
    }
  };

  console.log('Analytics Data:246', analytics);

  if (loading) {
    return (
      <div className="space-y-4">
        {/* Header Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-primary" />
            <h2 className="text-xl font-semibold">Project Analytics</h2>
          </div>
          <div className="flex items-center gap-2">
            <RefreshCw className="h-4 w-4 animate-spin text-primary" />
            <span className="text-sm text-muted-foreground">Loading analytics...</span>
          </div>
        </div>

        {/* Simple loading state - just show that data is being fetched */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardContent className="p-6">
                <div className="space-y-2">
                  <div className="h-4 bg-muted rounded w-3/4"></div>
                  <div className="h-8 bg-muted rounded w-1/2"></div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <Card className="animate-pulse">
          <CardContent className="p-6">
            <div className="h-64 bg-muted rounded"></div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error || !analytics) {
    return (
      <div className="text-center py-8">
        <AlertTriangle className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
        <p>{error ? `Error loading analytics: ${typeof error === 'string' ? error : error}` : "No analytics data available"}</p>
        <Button onClick={handleRefresh} className="mt-4">
          <RefreshCw className="h-4 w-4 mr-2" />
          Retry
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-primary" />
          <h2 className="text-xl font-semibold">Comprehensive Project Analytics</h2>
          {loading && (
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
              <span className="text-xs text-muted-foreground">Updating...</span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            ref={filterButtonRef}
            variant="outline"
            size="sm"
            onClick={() => setFilterOpen(!filterOpen)}
            className="relative"
          >
            <Filter className="h-4 w-4 mr-1" />
            Filters
            {filterCount > 0 && (
              <Badge variant="destructive" className="ml-1 px-1 py-0 h-4 text-xs">
                {filterCount}
              </Badge>
            )}
          </Button>
          <Select value={timeRange} onValueChange={(value) => setTimeRange(value as '7d' | '30d' | '90d' | '1y')}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7d">Last 7 days</SelectItem>
              <SelectItem value="30d">Last 30 days</SelectItem>
              <SelectItem value="90d">Last 90 days</SelectItem>
              <SelectItem value="1y">Last year</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || loading}>
            <RefreshCw className={`h-4 w-4 mr-1 ${refreshing || loading ? 'animate-spin' : ''}`} />
            {refreshing ? 'Refreshing...' : loading ? 'Loading...' : 'Refresh'}
          </Button>
          <GenericReportExporter
            {...getExportData()}
            onExportComplete={handleExportComplete}
          />
        </div>
      </div>

      {/* Analytics Filters */}
      <div className="mt-3">
        {filterOpen && (
          <GenericFilter
            config={analyticsFilterConfig}
            values={filterValues}
            onFilterChange={applyFilters}
            onReset={() => {
              const defaults = analyticsFilterConfig.defaultValues || {};
              setFilterValues(defaults);
              applyFilters(defaults);
            }}
            presentation="dropdown"
            isOpen={filterOpen}
            onOpenChange={setFilterOpen}
            anchorRef={filterButtonRef}
          />
        )}
      </div>

      {/* Key Performance Indicators - 5 Card Dashboard */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <Card className="relative overflow-hidden">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Task Completion</p>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold">{kpiData?.taskCompletion || 0}%</span>
                  {(kpiData?.taskCompletion || 0) >= 80 ?
                    <TrendingUp className="h-4 w-4 text-green-500" /> :
                    <TrendingDownIcon className="h-4 w-4 text-red-500" />
                  }
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {analyticsData?.tasks?.completedTasks || 0} of {analyticsData?.tasks?.totalTasks || 0} completed
                </p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-500 opacity-20" />
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-green-500 to-emerald-500 opacity-20" />
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Budget Utilization</p>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold">{kpiData?.budgetUtilization || 0}%</span>
                  {(kpiData?.budgetUtilization || 0) <= 85 ?
                    <TrendingUp className="h-4 w-4 text-green-500" /> :
                    <TrendingDownIcon className="h-4 w-4 text-amber-500" />
                  }
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  ${(resourceData?.budget?.actualCosts || 0).toLocaleString()} of ${(resourceData?.budget?.total || 0).toLocaleString()}
                </p>
              </div>
              <DollarSign className="h-8 w-8 text-blue-500 opacity-20" />
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-500 to-cyan-500 opacity-20" />
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Team Productivity</p>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold">{kpiData?.teamProductivity || 0}%</span>
                  {(kpiData?.teamProductivity || 0) >= 75 ?
                    <TrendingUp className="h-4 w-4 text-green-500" /> :
                    <TrendingDownIcon className="h-4 w-4 text-amber-500" />
                  }
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {teamData?.summary?.totalTeamMembers || 0} team members
                </p>
              </div>
              <Users className="h-8 w-8 text-purple-500 opacity-20" />
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-purple-500 to-violet-500 opacity-20" />
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Timeline Health</p>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold">{kpiData?.overallHealth || 0}%</span>
                  {(kpiData?.overallHealth || 0) >= 80 ?
                    <TrendingUp className="h-4 w-4 text-green-500" /> :
                    <TrendingDownIcon className="h-4 w-4 text-red-500" />
                  }
                </div>
              </div>
              <Clock className="h-8 w-8 text-orange-500 opacity-20" />
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-orange-500 to-red-500 opacity-20" />
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Overall Health</p>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold">{Math.round(kpiData?.overallHealth || 0)}%</span>
                  {(kpiData?.overallHealth || 0) >= 75 ?
                    <TrendingUp className="h-4 w-4 text-green-500" /> :
                    <TrendingDownIcon className="h-4 w-4 text-red-500" />
                  }
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {risks?.length || 0} active risks
                </p>
              </div>
              <Target className="h-8 w-8 text-green-500 opacity-20" />
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-green-500 to-teal-500 opacity-20" />
          </CardContent>
        </Card>
      </div>

      {/* Enhanced Analytics Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="overview" className="text-xs">
            <BarChart3 className="h-4 w-4 mr-1" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="team" className="text-xs">
            <Users className="h-4 w-4 mr-1" />
            Team Performance
          </TabsTrigger>
          <TabsTrigger value="resources" className="text-xs">
            <DollarSign className="h-4 w-4 mr-1" />
            Resource Optimization
          </TabsTrigger>
          <TabsTrigger value="collaboration" className="text-xs">
            <Globe className="h-4 w-4 mr-1" />
            Collaboration
          </TabsTrigger>
          <TabsTrigger value="insights" className="text-xs">
            <Brain className="h-4 w-4 mr-1" />
            Insights
          </TabsTrigger>
          <TabsTrigger value="risks" className="text-xs">
            <Shield className="h-4 w-4 mr-1" />
            Risks
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <PieChartIcon className="h-5 w-5" />
                  Task Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                {(() => {
                  const taskData = [
                    { name: 'Completed', value: analyticsData?.tasks?.completedTasks || 0, color: '#10b981' },
                    { name: 'In Progress', value: analyticsData?.tasks?.inProgressTasks || 0, color: '#3b82f6' },
                    { name: 'Pending', value: analyticsData?.tasks?.pendingTasks || 0, color: '#f59e0b' },
                    { name: 'Overdue', value: analyticsData?.tasks?.overdueTasks || 0, color: '#ef4444' }
                  ].filter(item => item.value > 0);
                  return taskData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={400}>
                      <PieChart>
                        <Pie
                          data={taskData}
                          cx="50%"
                          cy="50%"
                          outerRadius={150}
                          innerRadius={100}
                          paddingAngle={2}
                          dataKey="value" 
                          label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(1)}%`}
                        >
                          {taskData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip formatter={(value) => [value, 'Tasks']} />
                        <Legend wrapperStyle={{ paddingTop: '20px' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="text-center py-8">
                      <PieChartIcon className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                      <p className="text-muted-foreground">No task data available for distribution.</p>
                    </div>
                  );
                })()}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <TrendingUp className="h-5 w-5" />
                  Performance Metrics
                </CardTitle>
              </CardHeader>
              <CardContent>
                {analyticsData?.kpi ? (
                  <div className="space-y-4">
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span>Task Completion Rate</span>
                        <span>{analyticsData.kpi.taskCompletion || 0}%</span>
                      </div>
                      <Progress value={analyticsData.kpi.taskCompletion || 0} className="h-2" />
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span>Team Productivity</span>
                        <span>{analyticsData.kpi.teamProductivity || 0}%</span>
                      </div>
                      <Progress value={analyticsData.kpi.teamProductivity || 0} className="h-2" />
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span>Budget Efficiency</span>
                        <span>{Math.max(0, 100 - Math.abs((resourceData?.budget?.utilization || 0) - 85))}%</span>
                      </div>
                      <Progress value={Math.max(0, 100 - Math.abs((resourceData?.budget?.utilization || 0) - 85))} className="h-2" />
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span>Timeline Health</span>
                        <span>{analyticsData.kpi.overallHealth || 0}%</span>
                      </div>
                      <Progress value={analyticsData.kpi.overallHealth || 0} className="h-2" />
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <TrendingUp className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No performance metrics data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Team Performance Tab */}
        <TabsContent value="team" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  Department Performance
                </CardTitle>
              </CardHeader>
              <CardContent>
                {teamData?.departments && teamData.departments.length > 0 ? (
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {teamData.departments.map((dept: any, index: number) => (
                      <div key={dept.id || index} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex-1">
                          <h4 className="font-medium">{dept.name}</h4>
                          <p className="text-sm text-muted-foreground">
                            {dept.completedTasks}/{dept.totalTasks} tasks • {dept.teamMembers} members
                          </p>
                          <div className="mt-2">
                            <Progress value={dept.completionRate || 0} className="h-2" />
                          </div>
                        </div>
                        <div className="text-right ml-4">
                          <Badge variant={dept.productivity >= 85 ? "default" : dept.productivity >= 70 ? "secondary" : "destructive"}>
                            {dept.productivity}% Productive
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Users className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No department data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Award className="h-5 w-5" />
                  Individual Performance
                </CardTitle>
              </CardHeader>
              <CardContent>
                {teamData?.individuals && teamData.individuals.length > 0 ? (
                  <div className="space-y-3 max-h-96 overflow-y-auto">
                    {teamData.individuals.map((member: any, index: number) => (
                      <div key={member.id || index} className="flex items-center justify-between p-2 border rounded">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full flex items-center justify-center text-white text-sm font-medium">
                            {member.name?.charAt(0) || 'U'}
                          </div>
                          <div>
                            <p className="font-medium text-sm">{member.name}</p>
                            <p className="text-xs text-muted-foreground">{member.department}</p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-sm font-medium">{member.completedTasks}/{member.totalTasks}</p>
                          <Badge variant="outline" className="text-xs">
                            {member.productivity}%
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Award className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No individual performance data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="h-5 w-5" />
                Team Efficiency Comparison
              </CardTitle>
            </CardHeader>
            <CardContent>
              {teamData?.departments && teamData.departments.length > 0 ? (
                <ResponsiveContainer width="100%" height={500}>
                  <BarChart data={teamData.departments}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="completionRate" fill="#3b82f6" name="Completion Rate %" />
                    <Bar dataKey="productivity" fill="#10b981" name="Productivity Score" />
                    <Bar dataKey="efficiency" fill="#f59e0b" name="Efficiency %" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-center py-8">
                  <BarChart3 className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                  <p className="text-muted-foreground">No department data available for efficiency comparison.</p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Award className="h-5 w-5" />
                Individual Member Progress
              </CardTitle>
            </CardHeader>
            <CardContent>
              {teamData?.individuals && teamData.individuals.length > 0 ? (
                <ResponsiveContainer width="100%" height={500}>
                  <BarChart 
                    data={teamData.individuals.map((m: any) => ({
                      name: m.name,
                      completedTasks: m.completedTasks || 0,
                      totalTasks: m.totalTasks || 0,
                      productivity: m.productivity || 0
                    }))}
                    layout="vertical"
                    margin={{ top: 5, right: 30, left: 100, bottom: 5 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis type="number" />
                    <YAxis dataKey="name" type="category" width={90} />
                    <Tooltip 
                      formatter={(value, name) => {
                        if (name === 'Productivity') return [`${value}%`, name];
                        return [value, name];
                      }}
                    />
                    <Legend />
                    <Bar dataKey="completedTasks" fill="#10b981" name="Completed Tasks" />
                    <Bar dataKey="totalTasks" fill="#3b82f6" name="Total Tasks" />
                    <Bar dataKey="productivity" fill="#f59e0b" name="Productivity %" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-center py-8">
                  <Award className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                  <p className="text-muted-foreground">No individual performance data available.</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Resource Optimization Tab */}
        <TabsContent value="resources" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <DollarSign className="h-5 w-5" />
                  Budget Overview
                </CardTitle>
              </CardHeader>
              <CardContent>
                {resourceData?.budget ? (
                  <div className="space-y-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold">
                        ${(resourceData.budget.actualCosts || 0).toLocaleString()}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        of ${(resourceData.budget.total || 0).toLocaleString()} total
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span>Budget Utilization</span>
                        <span>{resourceData.budget.utilization || 0}%</span>
                      </div>
                      <Progress value={resourceData.budget.utilization || 0} className="h-3" />
                    </div>
                    <div className="text-center">
                      <Badge variant={
                        (resourceData.budget.variance || 0) <= 0 ? "default" :
                          (resourceData.budget.variance || 0) <= 10 ? "secondary" : "destructive"
                      }>
                        {(resourceData.budget.variance ?? 0) > 0 ? '+' : ''}{resourceData.budget.variance ?? 0}% Variance
                      </Badge>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <DollarSign className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No budget data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  Hour Efficiency
                </CardTitle>
              </CardHeader>
              <CardContent>
                {resourceData?.hours ? (
                  <div className="space-y-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold">{resourceData.hours.efficiency || 0}%</div>
                      <div className="text-sm text-muted-foreground">Hour Efficiency</div>
                    </div>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <div className="text-muted-foreground">Estimated</div>
                        <div className="font-medium">{resourceData.hours.totalEstimated || 0}h</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Actual</div>
                        <div className="font-medium">{resourceData.hours.totalActual || 0}h</div>
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span>Efficiency</span>
                        <span>{resourceData.hours.efficiency || 0}%</span>
                      </div>
                      <Progress value={resourceData.hours.efficiency || 0} className="h-3" />
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Clock className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No hour efficiency data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="h-5 w-5" />
                  Resource Utilization
                </CardTitle>
              </CardHeader>
              <CardContent>
                {resourceData?.utilization ? (
                  <div className="space-y-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold">{resourceData.utilization.utilizationRate || 0}%</div>
                      <div className="text-sm text-muted-foreground">Task Assignment Rate</div>
                    </div>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <div className="text-muted-foreground">Assigned</div>
                        <div className="font-medium">{resourceData.utilization.assignedTasks || 0}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Unassigned</div>
                        <div className="font-medium text-red-500">{resourceData.utilization.unassignedTasks || 0}</div>
                      </div>
                    </div>
                    <div>
                      <Badge variant={resourceData?.summary?.resourceHealth === 'good' ? "default" :
                        resourceData?.summary?.resourceHealth === 'warning' ? "secondary" : "destructive"}>
                        {resourceData?.summary?.resourceHealth || 'unknown'} Health
                      </Badge>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Target className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No resource utilization data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <PieChartIcon className="h-5 w-5" />
                Budget Breakdown Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              {(() => {
                const breakdownData = Object.entries(resourceData?.budget?.breakdown || {});
                return breakdownData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={400}>
                    <PieChart>
                      <Pie
                        data={breakdownData.map(([key, value]) => ({
                          name: key.charAt(0).toUpperCase() + key.slice(1),
                          value: value as number
                        }))}
                        cx="50%"
                        cy="50%"
                        outerRadius={150}
                        fill="#8884d8"
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      >
                        {breakdownData.map((_, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip formatter={(value) => [`$${(value as number).toLocaleString()}`, 'Amount']} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="text-center py-8">
                    <PieChartIcon className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No budget breakdown data available.</p>
                  </div>
                );
              })()}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Collaboration Tab */}
        <TabsContent value="collaboration" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Department Collaboration
                </CardTitle>
              </CardHeader>
              <CardContent>
                {collaborationData ? (
                  <div className="text-center space-y-2">
                    <div className="text-3xl font-bold">{collaborationData.departmentCollaboration || 0}</div>
                    <div className="text-sm text-muted-foreground">Active Departments</div>
                    <Badge variant="outline">Cross-functional</Badge>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Globe className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No collaboration data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Task Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                {collaborationData ? (
                  <div className="text-center space-y-2">
                    <div className="text-3xl font-bold">{collaborationData.crossDepartmentTasks || 0}</div>
                    <div className="text-sm text-muted-foreground">Cross-Department Tasks</div>
                    <Badge variant="secondary">Active</Badge>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Activity className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No task distribution data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Communication Score
                </CardTitle>
              </CardHeader>
              <CardContent>
                {collaborationData ? (
                  <div className="text-center space-y-4">
                    <div className="text-3xl font-bold">{collaborationData.communicationScore || 0}%</div>
                    <div className="text-sm text-muted-foreground">Team Communication</div>
                    <Progress value={collaborationData.communicationScore || 0} className="h-3" />
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Zap className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                    <p className="text-muted-foreground">No communication data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                Team Collaboration Matrix
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-medium mb-3">Department Interaction</h4>
                  <div className="space-y-2">
                    {teamData?.departments?.map((dept: any, index: number) => (
                      <div key={index} className="flex items-center justify-between p-2 border rounded">
                        <span className="text-sm">{dept.name}</span>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs">
                            {dept.teamMembers} members
                          </Badge>
                          <Badge variant="secondary" className="text-xs">
                            {dept.totalTasks} tasks
                          </Badge>
                        </div>
                      </div>
                    )) || <p className="text-muted-foreground text-sm">No department data available</p>}
                  </div>
                </div>
                <div>
                  <h4 className="font-medium mb-3">Communication Patterns</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between text-sm">
                      <span>Active Collaborations</span>
                      <Badge>{collaborationData?.departmentCollaboration || 0}</Badge>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Cross-Department Tasks</span>
                      <Badge variant="outline">{collaborationData?.crossDepartmentTasks || 0}</Badge>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span>Communication Efficiency</span>
                      <Badge variant={
                        (collaborationData?.communicationScore || 0) >= 80 ? "default" :
                          (collaborationData?.communicationScore || 0) >= 60 ? "secondary" : "destructive"
                      }>
                        {collaborationData?.communicationScore || 0}%
                      </Badge>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="h-5 w-5" />
                Department Task Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              {teamData?.departments && teamData.departments.length > 0 ? (
                <ResponsiveContainer width="100%" height={400}>
                  <BarChart data={teamData.departments}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="totalTasks" fill="#3b82f6" name="Total Tasks" />
                    <Bar dataKey="completedTasks" fill="#10b981" name="Completed Tasks" />
                    <Bar dataKey="teamMembers" fill="#f59e0b" name="Team Members" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-center py-8">
                  <BarChart3 className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                  <p className="text-muted-foreground">No department data available for task distribution.</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI-Powered Insights Tab */}
        <TabsContent value="insights" className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            {Array.isArray(insights) && insights.length > 0 ? insights.map((insight: any, index: number) => (
              <Card key={index} className={`border-l-4 ${insight.type === 'success' ? 'border-l-green-500' :
                  insight.type === 'warning' ? 'border-l-yellow-500' :
                    insight.type === 'critical' ? 'border-l-red-500' :
                      'border-l-blue-500'
                }`}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    {insight.type === 'success' ? <CheckCircle className="h-5 w-5 text-green-500" /> :
                      insight.type === 'warning' ? <AlertTriangle className="h-5 w-5 text-yellow-500" /> :
                        insight.type === 'critical' ? <AlertTriangle className="h-5 w-5 text-red-500" /> :
                          <Brain className="h-5 w-5 text-blue-500" />}
                    {insight.title}
                    <Badge variant={
                      insight.type === 'success' ? 'default' :
                        insight.type === 'warning' ? 'secondary' :
                          insight.type === 'critical' ? 'destructive' :
                            'outline'
                    }>
                      {insight.category}
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground mb-3">{insight.description}</p>
                  <div className="flex items-start gap-2 p-3 bg-muted/50 rounded-lg">
                    <ArrowRight className="h-4 w-4 mt-0.5 text-muted-foreground" />
                    <div>
                      <p className="font-medium text-sm">Recommendation</p>
                      <p className="text-sm text-muted-foreground">{insight.recommendation}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )) : (
              <Card>
                <CardContent className="text-center py-8">
                  <Brain className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                  <p className="text-muted-foreground">No AI insights available at the moment.</p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Insights will be generated based on project performance data.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        {/* Risk Assessment Tab */}
        <TabsContent value="risks" className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            {Array.isArray(risks) && risks.length > 0 ? risks.map((risk: any, index: number) => (
              <Card key={index} className={`border-l-4 ${risk.level === 'critical' ? 'border-l-red-500' :
                  risk.level === 'high' ? 'border-l-orange-500' :
                    risk.level === 'medium' ? 'border-l-yellow-500' :
                      'border-l-green-500'
                }`}>
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Shield className="h-5 w-5" />
                      {risk.description || 'Risk Assessment'}
                      <Badge variant={
                        risk.level === 'critical' ? 'destructive' :
                          risk.level === 'high' ? 'destructive' :
                            risk.level === 'medium' ? 'secondary' :
                              'outline'
                      }>
                        {risk.level} {risk.type}
                      </Badge>
                    </div>
                    {risk.probability && (
                      <Badge variant="outline" className="text-xs">
                        {risk.probability} probability
                      </Badge>
                    )}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h5 className="font-medium text-sm mb-1">Impact</h5>
                      <p className="text-sm text-muted-foreground">{risk.impact}</p>
                    </div>
                    <div>
                      <h5 className="font-medium text-sm mb-1">Mitigation Strategy</h5>
                      <p className="text-sm text-muted-foreground">{risk.mitigation}</p>
                    </div>
                    {risk.affectedAreas && (
                      <div>
                        <h5 className="font-medium text-sm mb-2">Affected Areas</h5>
                        <div className="flex gap-2 flex-wrap">
                          {risk.affectedAreas.map((area: string, idx: number) => (
                            <Badge key={idx} variant="outline" className="text-xs">
                              {area}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            )) : (
              <Card>
                <CardContent className="text-center py-8">
                  <Shield className="h-12 w-12 mx-auto mb-3 text-green-500" />
                  <p className="text-muted-foreground">No significant risks identified.</p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Your project appears to be on track with minimal risk factors.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

