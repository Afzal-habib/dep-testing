"use client";

import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, Edit, Settings, Share2, MoreVertical, Clock, DollarSign, Users, Target, Archive, Trash2, Plus, Building2, AlertTriangle, Loader2, MessageSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import PageHeader from "@/components/shared/page-header";
import { useToast } from "@/hooks/use-toast";
import { usePermissions } from "@/hooks/use-permissions";

// Import our new components
import { ProjectAnalytics } from "@/components/projects/ProjectAnalytics";
import { ProjectCategorization } from "@/components/projects/ProjectCategorization";
import { ProjectEditTab } from "@/components/projects/ProjectEditTab";
import { ProjectChannelButton } from "@/components/projects/project-channel-button";
import { useNavigation } from "@/components/providers/navigation-provider";
import { Project } from "@/types";
import HtmlTextRenderer from "@/components/shared/html-text-renderer";
import { PRIORITY_COLORS, STATUS_COLORS } from "@/lib/colorConstants";

interface Risk {
  description: string;
  impact: 'low' | 'medium' | 'high' | 'critical';
  probability: 'low' | 'medium' | 'high';
  mitigation?: string;
  status?: 'identified' | 'mitigated' | 'occurred';
}

interface Department {
  _id: string;
  name: string;
  status?: string;
  description?: string;
}

interface TeamMember {
  _id: string;
  name: string;
  email: string;
  avatar?: string;
  role?: string;
  department?: Department;
}

interface DepartmentTeamMember {
  departmentId: string | null;
  departmentName: string;
  teamMembers: TeamMember[];
}


// Enhanced interfaces for better type safety
interface ExtendedClient {
  _id: string
  name: string
  email: string
  company?: string
  phone?: string
  status?: string
  avatar?: string
  address?: {
    street?: string
    city?: string
    state?: string
    country?: string
    zipCode?: string
  }
}

interface ExtendedTeamMember {
  _id: string
  name: string
  email: string
  avatar?: string
  role?: string
  department?: {
    _id: string
    name: string
    status?: string
    description?: string
  }
}

interface ExtendedDepartmentTask {
  departmentId: string
  departmentName: string
  taskCount: number
  subTaskCount: number
  tasks: Array<{
    _id: string
    title: string
    status: string
    assigneeId?: string
    assignee?: ExtendedTeamMember | null
    dueDate?: string
    estimatedHours?: number
    actualHours?: number
    subTasks?: Array<{
      _id: string
      title: string
      status: string
      estimatedHours?: number
      actualHours?: number
    }>
  }>
}

interface ExtendedProject extends Omit<Project, 'client' | 'creator' | 'departmentTasks'> {
  client?: ExtendedClient;
  creator?: {
    _id: string
    name: string
    email: string
    avatar?: string
  }
  departmentTasks?: ExtendedDepartmentTask[];
  progress?: {
    overall: number;
    byDepartment?: Record<string, number>;
  };
  budgetHealth?: 'good' | 'warning' | 'critical';
  timelineHealth?: 'good' | 'warning' | 'critical';
  qualityMetrics?: {
    onTimeDelivery: boolean;
    withinBudget: boolean;
  };
}

// Using Project type from @/types

export default function ProjectDetailsPage() {
  const params = useParams();
  const router = useRouter();
  const { toast } = useToast();
  const { canUpdate, canDelete } = usePermissions();
  const { navigateTo, isNavigating } = useNavigation()
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedProject, setSelectedProject] = useState<ExtendedProject | null>(null);
  const [activeTab, setActiveTab] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('project-details-active-tab') || 'overview';
    }
    return 'overview';
  });

  const projectId = params?.id as string;
  const project = selectedProject;

  // Safe renderer for sections that might have data issues
  const safeRender = (renderFn: () => React.ReactNode, fallback?: React.ReactNode) => {
    try {
      return renderFn();
    } catch (error) {
      console.error('Error rendering section:', error);
      return fallback || (
        <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
          <p className="text-sm text-destructive">Error loading this section</p>
        </div>
      );
    }
  };

  // Fetch project details with retry mechanism
  const fetchProject = async (retryCount = 0) => {
    if (!projectId) return;

    const maxRetries = 3;

    try {
      setLoading(true);
      setError(null);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

      const response = await fetch(`/api/projects/${projectId}`, {
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
        },
      });

      clearTimeout(timeoutId);

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error || `HTTP ${response.status}: Failed to fetch project details`);
      }

      if (result.success && result.data) {
        setSelectedProject(result.data);
      } else {
        throw new Error(result.error || 'Project not found');
      }
    } catch (error: unknown) {
      console.error('Error fetching project:', error);

      const errorObj = error as Error;

      // Retry logic for network errors
      if ((errorObj.name === 'AbortError' || errorObj.message?.includes('fetch')) && retryCount < maxRetries) {
        console.log(`Retrying project fetch (${retryCount + 1}/${maxRetries})`);
        setTimeout(() => fetchProject(retryCount + 1), 1000 * (retryCount + 1)); // Exponential backoff
        return;
      }

      const errorMessage = errorObj.name === 'AbortError'
        ? 'Request timed out. Please try again.'
        : errorObj.message || 'Failed to load project details';

      setError(errorMessage);
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (projectId) {
      fetchProject();
    }
  }, [projectId, toast]);

  // Save active tab to localStorage whenever it changes
  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('project-details-active-tab', activeTab);
    }
  }, [activeTab]);


  // Remove global loading - each tab handles its own loading state
  // if (loading) {
  //   return (
  //     <div className="space-y-6">
  //       <div className="flex items-center justify-between">
  //         <div className="space-y-2">
  //           <Skeleton className="h-8 w-64" />
  //           <Skeleton className="h-4 w-96" />
  //         </div>
  //         <div className="flex gap-2">
  //           <Skeleton className="h-9 w-20" />
  //           <Skeleton className="h-9 w-9" />
  //         </div>
  //       </div>
  //       <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
  //         {[...Array(4)].map((_, i) => (
  //           <Card key={i}>
  //             <CardContent className="p-6">
  //               <Skeleton className="h-16 w-full" />
  //             </CardContent>
  //           </Card>
  //         ))}
  //       </div>
  //       <Skeleton className="h-96 w-full" />
  //     </div>
  //   );
  // }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-destructive" />
        <h2 className="text-lg font-semibold mb-2">Error Loading Project</h2>
        <p className="text-muted-foreground mb-4">{error}</p>
        <div className="flex gap-2 justify-center">
          <Button variant="outline" onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Go Back
          </Button>
          <Button onClick={() => fetchProject()}>
            Try Again
          </Button>
        </div>
      </div>
    );
  }

  if (!project) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <Skeleton className="h-8 w-64" />
            <Skeleton className="h-4 w-96" />
          </div>
          <div className="flex gap-2">
            <Skeleton className="h-9 w-20" />
            <Skeleton className="h-9 w-9" />
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <Card key={i}>
              <CardContent className="p-6">
                <Skeleton className="h-16 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <PageHeader
        title={project.name}
        subtitle={project.description}
        fullScreenMode="fullscreen-hide-layout"
        showAddButton={false}
        actions={
          <div className="flex items-center gap-2">
            <ProjectChannelButton
              projectId={projectId}
              projectName={project.name}
              variant="outline"
              size="sm"
            />
            <Button variant="outline" size="sm">
              <Share2 className="h-4 w-4 mr-1" />
              Share
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <MoreVertical className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem>
                  <Settings className="h-4 w-4" />
                  Project Settings
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => navigateTo('/projects')}>
                  <ArrowLeft className="h-4 w-4" />
                  Project List
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => navigateTo('/projects/add')}>
                  <Plus className="h-4 w-4" />
                  Add Project
                </DropdownMenuItem>
                <DropdownMenuItem>
                  <Archive className="h-4 w-4" />
                  Archive Project
                </DropdownMenuItem>
                {canDelete("projects") && (
                  <DropdownMenuItem className="text-destructive">
                    <Trash2 className="h-4 w-4" />
                    Delete Project
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />

      {/* Project Details Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="edit">Edit</TabsTrigger>
          <TabsTrigger value="categorization">Categorize & Task Creation</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {loading ? (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-2">
                  <Skeleton className="h-8 w-64" />
                  <Skeleton className="h-4 w-96" />
                </div>
                <div className="flex gap-2">
                  <Skeleton className="h-9 w-20" />
                  <Skeleton className="h-9 w-9" />
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {[...Array(4)].map((_, i) => (
                  <Card key={i}>
                    <CardContent className="p-6">
                      <Skeleton className="h-16 w-full" />
                    </CardContent>
                  </Card>
                ))}
              </div>
              <Skeleton className="h-96 w-full" />
            </div>
          ) : (
            <>
              <div>
                {/* Project Statistics */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Target className="h-5 w-5 text-indigo-600" />
                      Project Statistics & Health
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">

                        <div className="text-center p-3 bg-indigo-50 dark:bg-indigo-900/20 rounded-lg">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-sm text-muted-foreground">Progress</p>
                            </div>
                            <div>
                              <p className="text-xl font-bold text-indigo-600">{project.progress?.overall ?? 0}%</p>
                            </div>
                          </div>
                          <Progress value={project.progress?.overall ?? 0} className="mt-1" />
                        </div>
                        <div className="text-center p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                          <p className="text-sm text-muted-foreground">Total Tasks</p>
                          <p className="text-xl font-bold text-blue-600">{project.departmentTasks?.reduce((total, dept) => total + dept.taskCount, 0) ?? 0}</p>
                        </div>
                        <div className="text-center p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                          <p className="text-sm text-muted-foreground">Departments</p>
                          <p className="text-xl font-bold text-orange-600">
                            {project.departmentTasks?.length || 0}
                          </p>
                        </div>
                      </div>

                      {/* Project Health Indicators */}
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 pt-4 border-t">
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-full ${(project.progress?.overall || 0) >= 80 ? 'bg-green-100 text-green-600' :
                            (project.progress?.overall || 0) >= 50 ? 'bg-yellow-100 text-yellow-600' :
                              'bg-red-100 text-red-600'
                            }`}>
                            <Target className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="text-sm font-medium">Progress Health</p>
                            <p className="text-xs text-muted-foreground">
                              {(project.progress?.overall || 0) >= 80 ? 'On Track' :
                                (project.progress?.overall || 0) >= 50 ? 'At Risk' : 'Behind Schedule'}
                            </p>
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-full ${project.budgetHealth === 'good' ? 'bg-green-100 text-green-600' :
                            project.budgetHealth === 'warning' ? 'bg-yellow-100 text-yellow-600' :
                              'bg-red-100 text-red-600'
                            }`}>
                            <DollarSign className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="text-sm font-medium">Budget Health</p>
                            <p className="text-xs text-muted-foreground">
                              {project.budgetHealth === 'good' ? 'On Budget' :
                                project.budgetHealth === 'warning' ? 'Budget Warning' : 'Budget Critical'}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-full ${project.timelineHealth === 'good' ? 'bg-green-100 text-green-600' :
                            project.timelineHealth === 'warning' ? 'bg-yellow-100 text-yellow-600' :
                              'bg-red-100 text-red-600'
                            }`}>
                            <Clock className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="text-sm font-medium">Timeline Health</p>
                            <p className="text-xs text-muted-foreground">
                              {project.timelineHealth === 'good' ? 'On Schedule' :
                                project.timelineHealth === 'warning' ? 'Timeline Warning' : 'Timeline Critical'}
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2 space-y-4">
                  {/* Project Info */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        Project Information
                        <div className="flex gap-2 ml-auto">
                          <Badge className={STATUS_COLORS[project.status]}>
                            {project.status.replace('-', ' ')}
                          </Badge>
                          <Badge className={PRIORITY_COLORS[project.priority]}>
                            {project.priority} priority
                          </Badge>
                        </div>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid grid-cols-12 gap-4">
                        <div className="col-span-3">
                          <label className="text-sm text-muted-foreground">Start Date</label>
                          <p className="font-medium">
                            {project.startDate ? new Date(project.startDate).toLocaleDateString('en-US', {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric'
                            }) : 'Not set'}
                          </p>
                        </div>
                        <div className="col-span-3">
                          <label className="text-sm text-muted-foreground">End Date</label>
                          <p className="font-medium">
                            {project.endDate ? new Date(project.endDate).toLocaleDateString('en-US', {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric'
                            }) : 'Not set'}
                          </p>
                        </div>
                        <div className="col-span-3">
                          <label className="text-sm text-muted-foreground">Last Updated</label>
                          <p className="font-medium">{project.updatedAt ? new Date(project.updatedAt).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric'
                          }) : 'N/A'}</p>
                        </div>
                        <div className="col-span-3">
                          <label className="text-sm text-muted-foreground">Created</label>
                          <p className="font-medium">{project.createdAt ? new Date(project.createdAt).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric'
                          }) : 'N/A'}</p>
                        </div>
                        <div className="col-span-4">
                          <label className="text-sm text-muted-foreground">Created By</label>
                          <div className="flex items-center gap-2">

                            <Avatar className="h-8 w-8">
                              <AvatarImage src={project.creator?.avatar} />
                              <AvatarFallback className="text-xs">
                                {project.creator?.name ? (() => {
                                  const parts = project.creator.name.trim().split(' ');
                                  if (parts.length === 1) {
                                    return parts[0][0].toUpperCase();
                                  }
                                  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                                })()
                                  : ''}
                              </AvatarFallback>
                            </Avatar>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium truncate">{project.creator?.name}</p>
                              <p className="text-xs text-muted-foreground">{project.creator?.email}</p>
                            </div>
                          </div>
                        </div>
                        <div className="col-span-4">
                          <label className="text-sm text-muted-foreground">Client</label>
                          <div className="flex items-center gap-2">

                            <Avatar className="h-8 w-8">
                              <AvatarImage src={project.client?.avatar} />
                              <AvatarFallback className="text-xs">
                                {project.client?.name ? (() => {
                                  const parts = project.client.name.trim().split(' ');
                                  if (parts.length === 1) {
                                    return parts[0][0].toUpperCase();
                                  }
                                  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                                })()
                                  : ''}
                              </AvatarFallback>
                            </Avatar>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium truncate">{project.client?.name}</p>
                              <p className="text-xs text-muted-foreground">{project.client?.email}</p>
                            </div>
                          </div>
                        </div>
                        <div className="col-span-4">
                          <label className="text-sm text-muted-foreground">Budget</label>
                          <div className="space-y-1">
                            <p className="font-medium">
                              ${(project.budget ?? 0).toLocaleString()}
                            </p>
                            {project.actualCost !== undefined && (
                              <p className="text-xs text-muted-foreground">
                                Spent: ${project.actualCost.toLocaleString()}
                              </p>
                            )}
                          </div>
                        </div>
                        <div className="col-span-12">
                          <label className="text-sm text-muted-foreground">Departments</label>
                          <div className="space-y-1">
                            {project.departmentTasks && Array.isArray(project.departmentTasks) && project.departmentTasks.length > 0 ? (
                              project.departmentTasks.map((dept) => (
                                <Badge key={dept.departmentId} variant="outline" className="text-xs">
                                  {dept.departmentName}
                                </Badge>
                              ))
                            ) : (
                              <p className="font-medium text-muted-foreground">No departments assigned</p>
                            )}
                          </div>
                        </div>
                        {project.requirements && project.requirements.length > 0 && (
                          <div className="col-span-12">
                            <label className="text-sm font-medium text-muted-foreground">Requirements</label>
                            <div className="flex gap-2 items-center mt-1 flex-wrap">
                              {project.requirements.map((req, index) => (
                                <Badge variant="outline" className="text-xs" key={index}>
                                  {req}
                                </Badge>
                              ))}
                            </div>

                          </div>
                        )}
                        {project.customerServices && project.customerServices.length > 0 && (
                          <div className="col-span-12">
                            <label className="text-sm font-medium text-muted-foreground">Customer Services</label>
                            <div className="flex gap-2 items-center mt-1 flex-wrap">
                              {project.customerServices.map((service, index) => (
                                <Badge variant="outline" className="text-xs" key={index}>
                                  {service}
                                </Badge>
                              ))}
                            </div>

                          </div>
                        )}

                      </div>
                    </CardContent>
                  </Card>

                  {/* Project Description */}
                  {project.description && (
                    <Card>
                      <CardHeader>
                        <CardTitle>Project Description</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <HtmlTextRenderer
                          content={project.description}
                          fallbackText="No description"
                          showFallback={true}
                          renderAsHtml={true}
                          truncateHtml={false}
                        />
                      </CardContent>
                    </Card>
                  )}

                  {/* Project Requirements & Technical Details */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Settings className="h-5 w-5 text-slate-600" />
                        Technical Specifications
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid grid-cols-12 gap-3">
                        <div className="col-span-6">
                          <label className="text-sm font-medium text-muted-foreground">Project Type</label>
                          <p className="text-sm font-medium mt-1">
                            {project.projectType || 'Not specified'}
                          </p>
                        </div>

                        <div className="col-span-6">
                          <label className="text-sm font-medium text-muted-foreground">Timeline</label>
                          <p className="text-sm font-medium mt-1">
                            {project.timeline || 'Not specified'}
                          </p>
                        </div>

                        {project.resources?.estimatedHours && (
                          <div className="col-span-6">
                            <label className="text-sm font-medium text-muted-foreground">Estimated Hours</label>
                            <p className="text-sm font-medium mt-1">
                              {project.resources.estimatedHours.toLocaleString()} hours
                            </p>
                          </div>
                        )}

                        {project.resources?.tools && project.resources.tools.length > 0 && (
                          <div className="col-span-6">
                            <label className="text-sm font-medium text-muted-foreground">Tools & Technologies</label>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {project.resources.tools.map((tool, index) => (
                                <Badge key={index} variant="outline" className="text-xs">
                                  {tool}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}

                        {project.resources?.externalResources && project.resources.externalResources.length > 0 && (
                          <div className="col-span-6">
                            <label className="text-sm font-medium text-muted-foreground">External Resources</label>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {project.resources.externalResources.map((resource, index) => (
                                <Badge key={index} variant="secondary" className="text-xs">
                                  {resource}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>

                  {/* Budget Breakdown */}
                  {project.budgetBreakdown && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          <DollarSign className="h-5 w-5 text-green-600" />
                          Budget Breakdown
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                          {project.budgetBreakdown.development && (
                            <div className="text-center p-3 bg-muted/30 rounded-lg">
                              <p className="text-xs text-muted-foreground">Development</p>
                              <p className="font-semibold">${project.budgetBreakdown.development.toLocaleString()}</p>
                            </div>
                          )}
                          {project.budgetBreakdown.design && (
                            <div className="text-center p-3 bg-muted/30 rounded-lg">
                              <p className="text-xs text-muted-foreground">Design</p>
                              <p className="font-semibold">${project.budgetBreakdown.design.toLocaleString()}</p>
                            </div>
                          )}
                          {project.budgetBreakdown.testing && (
                            <div className="text-center p-3 bg-muted/30 rounded-lg">
                              <p className="text-xs text-muted-foreground">Testing</p>
                              <p className="font-semibold">${project.budgetBreakdown.testing.toLocaleString()}</p>
                            </div>
                          )}
                          {project.budgetBreakdown.deployment && (
                            <div className="text-center p-3 bg-muted/30 rounded-lg">
                              <p className="text-xs text-muted-foreground">Deployment</p>
                              <p className="font-semibold">${project.budgetBreakdown.deployment.toLocaleString()}</p>
                            </div>
                          )}
                          {project.budgetBreakdown.maintenance && (
                            <div className="text-center p-3 bg-muted/30 rounded-lg">
                              <p className="text-xs text-muted-foreground">Maintenance</p>
                              <p className="font-semibold">${project.budgetBreakdown.maintenance.toLocaleString()}</p>
                            </div>
                          )}
                          {project.budgetBreakdown.contingency && (
                            <div className="text-center p-3 bg-muted/30 rounded-lg">
                              <p className="text-xs text-muted-foreground">Contingency</p>
                              <p className="font-semibold">${project.budgetBreakdown.contingency.toLocaleString()}</p>
                            </div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </div>

                <div className="space-y-6">
                  {/* Team Members by Department */}
                  {safeRender(() => (
                    <Card className="max-h-96 overflow-y-auto">
                      <CardHeader>
                        <CardTitle className="flex align-center">
                          Team Members
                          {project.departmentTasks && Array.isArray(project.departmentTasks) && (
                            <div className="flex align-center justify-between gap-2 flex-1">
                              <span className="ml-1">
                                ({
                                  project.departmentTasks.reduce((assignees: Set<string>, dept) => {
                                    dept.tasks.forEach(task => {
                                      if (task.assigneeId) {
                                        assignees.add(task.assigneeId);
                                      }
                                    });
                                    return assignees;
                                  }, new Set<string>()).size
                                })
                              </span>
                              <Badge variant="outline" className="text-xs">
                                {project.departmentTasks?.reduce((total, dept) => total + dept.taskCount, 0) ?? 0} Total Tasks
                              </Badge>
                            </div>


                          )}

                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        {project.departmentTasks && Array.isArray(project.departmentTasks) && project.departmentTasks.length > 0 ? (
                          project.departmentTasks
                            // .filter(dept => dept.taskCount > 0) // Only show departments with assigned tasks
                            .map((dept, idx, arr) => {
                              // Collect unique assignees for this department
                              const uniqueAssignees = dept.tasks.reduce((acc: ExtendedTeamMember[], task) => {
                                if (task.assignee && !acc.some(a => a._id === task?.assignee?._id)) {
                                  acc.push(task.assignee);
                                }
                                return acc;
                              }, []);

                              if (uniqueAssignees.length === 0) return null; // Skip departments if no unique assignees were found
                              const isLast = idx === arr.length - 1;
                              return (
                                <div key={dept.departmentId || 'unassigned'} className={`space-y-2 pb-3${!isLast ? ' border-b' : ''}`}>
                                  <div className="flex items-center justify-between gap-2">
                                    {/* Assuming Building2 is an icon component for a department */}
                                    <div className="flex items-center gap-2">
                                      <Building2 className="h-4 w-4 text-muted-foreground" />
                                      <span className="font-medium text-sm">{dept.departmentName}</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      {/* Display the count of unique assignees in this department */}
                                      {/* <Badge variant="outline" className="text-xs">
                                    {uniqueAssignees.length} Assignees
                                  </Badge> */}
                                      <Badge variant="outline" className="text-xs">
                                        {dept.tasks.length} Tasks
                                      </Badge>
                                    </div>
                                  </div>

                                  <div className="space-y-2 ml-2 ">
                                    {/* Map over the unique assignees and display their details */}
                                    {uniqueAssignees.map((member) => (
                                      <div key={member._id} className="flex items-center gap-2">
                                        {/* Assuming Avatar/AvatarImage/AvatarFallback components exist */}
                                        <Avatar className="h-8 w-8">
                                          <AvatarImage src={member.avatar} />
                                          <AvatarFallback className="text-xs">
                                            {member.name ? (() => {
                                              const parts = member.name.trim().split(' ');
                                              if (parts.length === 1) {
                                                return parts[0][0].toUpperCase();
                                              }
                                              return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                                            })() : ''}
                                          </AvatarFallback>
                                        </Avatar>
                                        <div className="flex-1 min-w-0">
                                          <p className="text-sm font-medium truncate">{member.name}</p>
                                          <p className="text-xs text-muted-foreground">{member.email}</p>
                                        </div>
                                        <Badge variant="outline" className="text-xs">
                                          {
                                            dept.tasks.filter(
                                              (task) =>
                                                (task.assignee?._id === member._id) ||
                                                (task.assigneeId === member._id)
                                            ).length
                                          } Tasks
                                        </Badge>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              );
                            })
                        ) : (
                          // Fallback if there are no departments or tasks
                          <p className="text-sm text-muted-foreground">No assignees found in project tasks.</p>
                        )}
                      </CardContent>
                    </Card>
                  ))}

                  {/* Client info including the address */}
                  {project.client && (
                    <Card className="max-h-96 overflow-y-auto">
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          <Users className="h-4 w-4 text-blue-500" />
                          Project Client Details
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          <div className="flex items-center gap-2">
                            <Avatar className="h-10 w-10">
                              <AvatarImage src={project.client.avatar} />
                              <AvatarFallback className="text-sm">
                                {project.client.name ? (() => {
                                  const parts = project.client.name.trim().split(' ');
                                  if (parts.length === 1) {
                                    return parts[0][0].toUpperCase();
                                  }
                                  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                                })() : 'C'}
                              </AvatarFallback>
                            </Avatar>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium truncate">{project.client.name}</p>
                              <p className="text-xs text-muted-foreground">{project.client.email}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 justify-between">
                            {project.client.phone && (
                              <div>
                                <label className="text-sm text-muted-foreground">Phone</label>
                                <p className="font-medium">{project.client.phone}</p>
                              </div>
                            )}
                            {project.client?.address?.zipCode && (
                              <div>
                                <label className="text-sm text-muted-foreground">Zip Code</label>
                                <p className="font-medium">{project.client?.address.zipCode}</p>
                              </div>
                            )}
                            {project.client.status && (
                              <div>
                                <label className="text-sm text-muted-foreground">Status</label><br />
                                <Badge className={STATUS_COLORS[project?.client?.status as keyof typeof STATUS_COLORS]} variant="outline">
                                  {project.client.status.replace('-', ' ')}
                                </Badge>
                              </div>
                            )}
                          </div>

                          {project.client.address && (
                            <div>
                              <label className="text-sm text-muted-foreground">Address</label>
                              <div className="text-sm font-medium">
                                <p>
                                  {project.client.address.street && `${project.client.address.street}, `}
                                  {project.client.address.city && `${project.client.address.city}, `}
                                  {project.client.address.state && `${project.client.address.state}, `}
                                  {project.client.address.country && `${project.client.address.country}`}
                                </p>
                              </div>
                            </div>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  )}
                  {/* Risks */}
                  {project.risks && Array.isArray(project.risks) && project.risks.length > 0 && (
                    <Card className="max-h-96 overflow-y-auto">
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          <AlertTriangle className="h-4 w-4 text-amber-500" />
                          Project Risks
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {project.risks.map((risk, index: number) => {
                            const impactColor =
                              risk.impact === 'critical' ? 'border-red-500 bg-red-50 dark:bg-red-900/10' :
                                risk.impact === 'high' ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/10' :
                                  risk.impact === 'medium' ? 'border-amber-500 bg-amber-50 dark:bg-amber-900/10' :
                                    'border-green-500 bg-green-50 dark:bg-green-900/10';

                            return (
                              <div key={index} className={`p-3 rounded-lg border-l-4 ${impactColor}`}>
                                <div className="flex items-start justify-between">
                                  <div className="flex-1">
                                    <p className="text-sm font-medium">{risk.description}</p>
                                    {risk.mitigation && (
                                      <p className="text-xs text-muted-foreground mt-1">
                                        <strong>Mitigation:</strong> {risk.mitigation}
                                      </p>
                                    )}
                                  </div>
                                  <div className="flex gap-1 ml-2">
                                    {risk.impact && (
                                      <Badge variant="outline" className="text-xs">
                                        {risk.impact}
                                      </Badge>
                                    )}
                                    {risk.probability && (
                                      <Badge variant="outline" className="text-xs">
                                        {risk.probability}
                                      </Badge>
                                    )}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </CardContent>
                    </Card>
                  )}
                  <Card className="max-h-96 overflow-y-auto">
                    <CardHeader>
                      <CardTitle>Budget & Timeline</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-2">
                        <div className="flex justify-between">
                          <span className="text-sm text-muted-foreground">Budget Utilization</span>
                          <span className="text-sm font-medium">
                            {(() => {
                              const budgetBreakdown = project.budgetBreakdown || {}
                              const totalAllocated = Object.values(budgetBreakdown).reduce((sum: number, val: any) => sum + (val || 0), 0)
                              return project.budget ? Math.round((totalAllocated / project.budget) * 100) : 0
                            })()}%
                          </span>
                        </div>
                        <Progress value={(() => {
                          const budgetBreakdown = project.budgetBreakdown || {}
                          const totalAllocated = Object.values(budgetBreakdown).reduce((sum: number, val: any) => sum + (val || 0), 0)
                          return project.budget ? (totalAllocated / project.budget) * 100 : 0
                        })()} className="h-2" />
                        <div className="flex justify-between text-xs text-muted-foreground">
                          <span>${(() => {
                            const budgetBreakdown = project.budgetBreakdown || {}
                            return Object.values(budgetBreakdown).reduce((sum: number, val: any) => sum + (val || 0), 0)
                          })().toLocaleString()} allocated</span>
                          <span>${(project.budget ?? 0).toLocaleString()} budget</span>
                        </div>
                      </div>

                      <Separator />

                      <div className="space-y-2">
                        <div className="flex justify-between">
                          <span className="text-sm text-muted-foreground">Timeline Progress</span>
                          <span className="text-sm font-medium">{project.progress?.overall ?? 0}%</span>
                        </div>
                        <Progress value={project.progress?.overall ?? 0} className="h-2" />
                        <div className="flex justify-between text-xs text-muted-foreground">
                          <span>{project.startDate ? new Date(project.startDate).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric'
                          }) : 'Not set'}</span>
                          <span>{project.endDate ? new Date(project.endDate).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric'
                          }) : 'Not set'}</span>
                        </div>
                      </div>

                      <Separator />

                      <div className="space-y-2">
                        <div className="flex justify-between">
                          <span className="text-sm text-muted-foreground">Hour Efficiency</span>
                          <span className="text-sm font-medium">
                            {project.departmentTasks?.length ? (() => {
                              const totalEstimated = project.departmentTasks.reduce((sum, dept) =>
                                sum + dept.tasks.reduce((taskSum, task) =>
                                  taskSum + (task.estimatedHours || 0) + (task.subTasks?.reduce((subSum, sub) => subSum + (sub.estimatedHours || 0), 0) || 0), 0), 0)
                              const totalActual = project.departmentTasks.reduce((sum, dept) =>
                                sum + dept.tasks.reduce((taskSum, task) =>
                                  taskSum + (task.actualHours || 0) + (task.subTasks?.reduce((subSum, sub) => subSum + (sub.actualHours || 0), 0) || 0), 0), 0)
                              return totalEstimated > 0 ? Math.min(200, Math.round((totalActual / totalEstimated) * 100)) : 100
                            })() : 100}%
                          </span>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Estimated vs Actual Hours
                        </div>
                      </div>

                      <Separator />

                      <div className="space-y-2">
                        <div className="flex justify-between">
                          <span className="text-sm text-muted-foreground">Timeline Health</span>
                          <span className={`text-sm font-medium ${project.timelineHealth === 'good' ? 'text-green-600' :
                            project.timelineHealth === 'warning' ? 'text-yellow-600' : 'text-red-600'}`}>
                            {project.timelineHealth === 'good' ? 'On Schedule' :
                              project.timelineHealth === 'warning' ? 'Warning' : 'Critical'}
                          </span>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Based on progress vs time remaining
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </>
          )}
        </TabsContent>

        <TabsContent value="categorization">
          {safeRender(() => (
            <ProjectCategorization
              projectId={projectId}
              project={project}
              onProjectUpdate={fetchProject}
            />
          ))}
        </TabsContent>


        <TabsContent value="edit">
          <ProjectEditTab
            project={project}
            onProjectUpdate={fetchProject}
          />
        </TabsContent>

        <TabsContent value="analytics">
          {safeRender(() => (
            <ProjectAnalytics projectId={projectId} />
          ), (
            <Card>
              <CardContent className="p-8 text-center">
                <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <h3 className="text-lg font-semibold mb-2">Analytics Unavailable</h3>
                <p className="text-muted-foreground mb-4">
                  There was an error loading the analytics for this project.
                </p>
                <Button onClick={() => window.location.reload()} variant="outline">
                  Try Again
                </Button>
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div >
  );
}
