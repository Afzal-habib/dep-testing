"use client";

import { useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import PageHeader from "@/components/shared/page-header";
import GenericForm from "@/components/shared/generic-form";
import { Button } from "@/components/ui/button";
import { ArrowLeft, FolderPlus } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useNavigationLoading } from "@/hooks/use-navigation-loading";
import { createProjectFormSchema } from '@/lib/validations/project';
import { CreateProjectFormData } from '@/types';
import { useProjects } from '@/hooks/use-projects';
import { useClients } from '@/hooks/use-clients';
import { useNavigation } from "@/components/providers/navigation-provider";

export default function AddProjectPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const { navigateTo } = useNavigation()
  // Get prefill data from URL params (when creating from client page)
  const clientId = searchParams?.get('clientId') || undefined;
  const prefill = searchParams?.get('prefill') === 'true';

  const form = useForm<CreateProjectFormData>({
    resolver: zodResolver(createProjectFormSchema),
    defaultValues: {
      name: "",
      description: "",
      clientId: clientId || "",
      departmentIds: [],
      status: "pending",
      priority: "medium",
      budget: 0,
      startDate: "",
      endDate: "",
      projectType: "",
      requirements: [],
      customerServices: [],
      timeline: "",
      budgetBreakdown: {
        development: 0,
        design: 0,
        testing: 0,
        deployment: 0,
        maintenance: 0,
        contingency: 0,
      },
      resources: {
        estimatedHours: 0,
        actualHours: 0,
        tools: [],
        externalResources: [],
      },
    },
  });

  // Use new hooks
  const { createProject } = useProjects();
  const { clients, loading: clientsLoading } = useClients();

  // Prefill project data from client if available
  useEffect(() => {
    const fetchLeadAndPrefill = async () => {
      if (prefill && clientId && clients.length > 0) {
        // Find the client and get related data for prefilling
        const client = clients.find(c => c._id === clientId);
        if (client && client._id) {
          // Prefill basic client selection and disable it
          form.setValue('clientId', client._id);

          // Set basic project name from client
          form.setValue('name', `${client.name} Project`);

          // Fetch lead data associated with this client
          try {
            const response = await fetch(`/api/leads?clientId=${clientId}&limit=1`);
            const data = await response.json();
            if (data.success && data.data.leads.length > 0) {
              const lead = data.data.leads[0];

              // Populate form with lead's project-related data
              if (lead.projectName) {
                form.setValue('name', lead.projectName);
              }
              if (lead.projectDescription) {
                form.setValue('description', lead.projectDescription);
              }
              if (lead.projectBudget) {
                form.setValue('budget', lead.projectBudget);
              }
              if (lead.projectTimeline) {
                form.setValue('timeline', lead.projectTimeline);
              }
              if (lead.complexity) {
                form.setValue('complexity', lead.complexity);
              }
              if (lead.projectType) {
                form.setValue('projectType', lead.projectType);
              }
              if (lead.projectRequirements) {
                form.setValue('requirements', lead.projectRequirements);
              }
              if (lead.customerServices) {
                form.setValue('customerServices', lead.customerServices);
              }
              if (lead.projectType) {
                form.setValue('projectType', lead.projectType);
              }
              if (lead.estimatedHours) {
                form.setValue('resources.estimatedHours', lead.estimatedHours);
              }
              if (lead.technologies) {
                form.setValue('resources.tools', lead.technologies);
              }
            }
          } catch (error) {
            console.error('Error fetching lead data:', error);
          }
        }
      }
    };

    fetchLeadAndPrefill();
  }, [prefill, clientId, clients, form]);

  const handleSubmit = async (data: CreateProjectFormData) => {
    setLoading(true);
    try {
      const result = await createProject(data);
      toast({
        title: "Success",
        description: "Project created successfully",
      });

      // Navigate to project edit page for further configuration
      navigateTo(`/projects`);
    } catch (error: any) {
      console.error('Error creating project:', error);
      toast({
        variant: "destructive",
        title: "Error",
        description: error.message || "Failed to create project",
      });
    } finally {
      setLoading(false);
    }
  };

  const { isNavigating, handleNavigation } = useNavigationLoading();

  const handleCancel = () => {
    handleNavigation("/projects");
  };

  // Prepare client options for dropdown
  const clientOptions = clients
    // .filter(client => client.status === 'qualified' && client._id) // Only qualified clients can have projects
    .filter(client => client.clientStatus === 'qualified') // Only qualified clients can have projects
    .map(client => ({
      value: client._id!,
      label: `${client.name} (${client.email})`,
    }));

  console.log('clients98', clients);
  console.log('clientOPtions', clientOptions);

  const formFields = [
    {
      subform_title: "Basic Information",
      fields: [
        {
          name: "name",
          label: "Project Name",
          type: "text" as const,
          placeholder: "Enter project name",
          required: true,
          description: "A clear, descriptive name for the project",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "status",
          label: "Status",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "pending", label: "Pending" },
            { value: "active", label: "Active" },
            { value: "completed", label: "Completed" },
            { value: "approved", label: "Approved" },
            { value: "inactive", label: "Inactive" },
          ],
          description: "Current project status",
          defaultValue: "pending",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "priority",
          label: "Priority",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "low", label: "Low" },
            { value: "medium", label: "Medium" },
            { value: "high", label: "High" },
            { value: "urgent", label: "Urgent" },
          ],
          defaultValue: "medium",
          description: "Project priority level",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "clientId",
          label: "Client",
          type: "select" as const,
          searchable: true,
          options: clientOptions,
          placeholder: "Select a client",
          required: true,
          disabled: !!clientId, // Disable if prefilled from client page
          description: "The client for whom this project is being created",
          cols: 12,
          mdCols: 4,
          lgCols: 4,
        },
        // {
        //   name: "projectType",
        //   label: "Project Type",
        //   type: "text" as const,
        //   placeholder: "e.g., Web Development, Mobile App, etc.",
        //   description: "The type or category of project",
        //   cols: 12,
        //   mdCols: 6,
        //   lgCols: 6,
        // },
         {
          name: "projectType",
          label: "Project Type",
          type: "select" as const,
          searchable: true,
          options: [
            { value: "web", label: "Web Development" },
            { value: "mobile", label: "Mobile App" },
            { value: "desktop", label: "Desktop Software" },
            { value: "api", label: "API Development" },
            { value: "consulting", label: "Consulting" },
            { value: "other", label: "Other" },
          ],
          description: "Type of project",
          cols: 12,
          mdCols: 4,
          lgCols: 4,
        },
        {
          name: "complexity",
          label: "Complexity",
          type: "select" as const,
          searchable: true,
          options: [
            { value: "simple", label: "Simple" },
            { value: "medium", label: "Medium" },
            { value: "complex", label: "Complex" },
          ],
          description: "Project complexity level",
          cols: 12,
          mdCols: 4,
          lgCols: 4,
        },
        {
          name: "requirements",
          label: "Key Requirements",
          type: "array-input" as const,
          placeholder: "List project requirements and specifications",
          description: "Detailed project requirements",
          cols: 12,
          mdCols: 6,
          lgCols: 6,
        },
        {
          name: "customerServices",
          label: "Customer Services",
          type: "array-input" as const,
          placeholder: "List customer services provided",
          description: "Detailed customer services provided",
          cols: 12,
          mdCols: 6,
          lgCols: 6,
        },
        {
          name: "description",
          label: "Description",
          type: "rich-text" as const,
          placeholder: "Describe the project objectives and scope",
          description: "Detailed project description",
          cols: 12,
          mdCols: 12,
          lgCols: 12,
        },
      ]
    },
    {
      subform_title: "Dates & Budget Breakdown",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "budget",
          label: "Total Budget",
          type: "number" as const,
          placeholder: "Enter total budget",
          description: "Total project budget",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "startDate",
          label: "Start Date",
          type: "date" as const,
          description: "Project start date",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "endDate",
          label: "End Date",
          type: "date" as const,
          description: "Project end date",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.development",
          label: "Development Costs",
          type: "number" as const,
          placeholder: "Development costs",
          description: "Estimated development costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.design",
          label: "Design Costs",
          type: "number" as const,
          placeholder: "Design costs",
          description: "Estimated design costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.testing",
          label: "Testing Costs",
          type: "number" as const,
          placeholder: "Testing costs",
          description: "Estimated testing costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.deployment",
          label: "Deployment Costs",
          type: "number" as const,
          placeholder: "Deployment costs",
          description: "Estimated deployment costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.maintenance",
          label: "Maintenance Costs",
          type: "number" as const,
          placeholder: "Maintenance costs",
          description: "Estimated maintenance costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "budgetBreakdown.contingency",
          label: "Contingency",
          type: "number" as const,
          placeholder: "Contingency budget",
          description: "Contingency budget for unexpected costs",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
      ]
    },
    {
      subform_title: "Resources",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "timeline",
          label: "Timeline",
          type: "text" as const,
          placeholder: "Expected project duration (e.g., 3-6 months)",
          description: "Expected timeline or duration",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "resources.actualHours",
          label: "Actual Hours",
          type: "number" as const,
          placeholder: "Actual hours spent",
          description: "Actual hours spent so far",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "resources.estimatedHours",
          label: "Estimated Hours",
          type: "number" as const,
          placeholder: "Total estimated hours",
          description: "Total estimated hours for the project",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "resources.tools",
          label: "Tools & Technologies",
          type: "array-input" as const,
          placeholder: "Add tool or technology",
          description: "Tools and technologies used in the project",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "resources.externalResources",
          label: "External Resources",
          type: "array-input" as const,
          placeholder: "Add external resource",
          description: "External resources and dependencies",
          cols: 12,
          mdCols: 6,
        },
      ]
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title="Add Project"
        subtitle={prefill ? "Create project from client data" : "Create a new project"}
        actions={
          <Button variant="outline" onClick={handleCancel} disabled={loading || isNavigating}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Projects
          </Button>
        }
      />

      {/* Form */}
      <div className="rounded-lg border bg-card">
        <div className="flex items-center gap-2 border-b px-6 py-4">
          <FolderPlus className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">Project Information</h2>
        </div>

        <div className="p-6">
          <GenericForm
            form={form}
            fields={formFields}
            onSubmit={handleSubmit}
            loading={loading}
            submitText="Create Project"
            cancelText="Cancel"
            onCancel={handleCancel}
          />
        </div>
      </div>

      {prefill && (
        <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
          <div className="flex items-start gap-2">
            <div className="mt-0.5">
              <div className="h-2 w-2 rounded-full bg-blue-500" />
            </div>
            <div>
              <h4 className="font-medium text-blue-900">Prefilled Data</h4>
              <p className="text-sm text-blue-700">
                This form has been prefilled with project information from the related lead.
                You can modify these details as needed.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}