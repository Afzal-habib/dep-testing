"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useLeads } from "@/hooks/use-leads";
import { useGenericQueryById } from "@/hooks/use-generic-query";
import PageHeader from "@/components/shared/page-header";
import GenericForm from "@/components/shared/generic-form";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ArrowLeft, UserPlus } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { usePermissions } from "@/hooks/use-permissions";
import Swal from 'sweetalert2';
import { updateLeadFormSchema } from '@/lib/validations/lead';
import type { UpdateLeadFormData } from '@/lib/validations/lead';
import { useNavigation } from "@/components/providers/navigation-provider";

export default function EditLeadPage() {
  const router = useRouter();
  const params = useParams();
  const { toast } = useToast();
  const { canCreate } = usePermissions();
  const leadId = params?.id as string;
  const { navigateTo, isNavigating } = useNavigation();
  // Generic options for leads
  const genericOptions = {
    entityName: 'leads',
    baseUrl: '/api/leads',
    reduxDispatchers: {
      setEntity: (lead: any) => { }, // Will be handled by the query
    },
  };

  // Fetch lead data
  const { data: lead, isLoading: leadLoading } = useGenericQueryById(genericOptions, leadId, !!leadId);

  const { updateLead, actionLoading } = useLeads();

  const form = useForm<UpdateLeadFormData>({
    resolver: zodResolver(updateLeadFormSchema),
    defaultValues: {
      name: "",
      email: "",
      phone: "",
      position: "",
      company: "",
      website: undefined,
      industry: "",
      companySize: undefined,
      annualRevenue: "",
      employeeCount: "",
      status: "active",
      source: "website",
      priority: "medium",
      nextFollowUpDate: "",
      notes: "",
      address: {
        street: "",
        city: "",
        state: "",
        zipCode: "",
        country: "",
      },
      socialLinks: [],
      projectName: "",
      projectType: undefined,
      complexity: undefined,
      projectBudget: "",
      estimatedHours: "",
      projectTimeline: "",
      projectDescription: "",
      technologies: [],
      projectRequirements: [],
      customerServices: [],
    },
  });

  // Populate form when lead data is loaded
  useEffect(() => {
    if (lead) {
      form.reset({
        name: lead.name,
        email: lead.email,
        phone: lead.phone || "",
        position: lead.position || "",
        company: lead.company || "",
        website: lead.website || "",
        industry: lead.industry || "",
        companySize: (lead.companySize && ['startup', 'small', 'medium', 'large', 'enterprise'].includes(lead.companySize)) ? lead.companySize as any : undefined,
        annualRevenue: lead.annualRevenue ? String(lead.annualRevenue) : "",
        employeeCount: lead.employeeCount ? String(lead.employeeCount) : "",
        status: lead.status,
        source: lead.source,
        priority: lead.priority,
        nextFollowUpDate: lead.nextFollowUpDate ? new Date(lead.nextFollowUpDate).toISOString().split('T')[0] : "",
        notes: lead.notes || "",
       address: {
          street: lead.address?.street || "",
          city: lead.address?.city || "",
          state: lead.address?.state || "",
          zipCode: lead.address?.zipCode || "",
          country: lead.address?.country || "",
        },
        socialLinks: lead.socialLinks || [],
        projectName: lead.projectName,
        projectType: (lead.projectType && ['web', 'mobile', 'desktop', 'api', 'consulting', 'other'].includes(lead.projectType)) ? lead.projectType as any : undefined,
        complexity: (lead.complexity && ['simple', 'medium', 'complex'].includes(lead.complexity)) ? lead.complexity as any : undefined,
        projectBudget: lead.projectBudget ? String(lead.projectBudget) : "",
        estimatedHours: lead.estimatedHours ? String(lead.estimatedHours) : "",
        projectTimeline: lead.projectTimeline || "",
        projectDescription: lead.projectDescription || "",
        technologies: lead.technologies || [],
        projectRequirements: lead.projectRequirements || [],
        customerServices: lead.customerServices || [],
      });
    }
  }, [lead, form]);


  const handleSubmit = async (data: UpdateLeadFormData) => {
    if (!lead || !lead._id) return;

    try {

      // Transform form data to API format
      const cleanedData = {
        ...data,
        phone: data.phone?.trim() || undefined,
        position: data.position?.trim() || undefined,
        company: data.company?.trim() || undefined,
        website: data.website?.trim() || undefined,
        industry: data.industry?.trim() || undefined,
        annualRevenue: data.annualRevenue ? Number(data.annualRevenue) : undefined,
        employeeCount: data.employeeCount ? Number(data.employeeCount) : undefined,
        projectDescription: data.projectDescription?.trim() || undefined,
        projectTimeline: data.projectTimeline?.trim() || undefined,
        projectBudget: data.projectBudget ? Number(data.projectBudget) : undefined,
        estimatedHours: data.estimatedHours ? Number(data.estimatedHours) : undefined,
        technologies: data.technologies?.filter((tech: string) => tech.trim().length > 0) || undefined,
        projectRequirements: data.projectRequirements?.filter((req: string) => req.trim().length > 0) || undefined,
        customerServices: data.customerServices?.filter((service: string) => service.trim().length > 0) || undefined,
        notes: data.notes?.trim() || undefined,
        nextFollowUpDate: data.nextFollowUpDate ? new Date(data.nextFollowUpDate) : undefined,
         // Address
        address: data.address ? {
          street: data.address.street?.trim() || undefined,
          city: data.address.city?.trim() || undefined,
          state: data.address.state?.trim() || undefined,
          zipCode: data.address.zipCode?.trim() || undefined,
          country: data.address.country?.trim() || undefined,
        } : undefined,
      };

      const result = await updateLead(leadId, cleanedData);

      toast({
        title: "Success",
        description: "Lead updated successfully",
      });

      navigateTo("/leads");
    } catch (error: any) {
      console.error('Update lead error:', error)

      // Handle structured API errors
      let errorMessage = "Failed to update lead"
      let errorDetails = ""

      if (error?.error) {
        errorMessage = error.error
        if (error.details && Array.isArray(error.details)) {
          errorDetails = error.details.join(', ')
        } else if (error.details) {
          errorDetails = typeof error.details === 'string' ? error.details : JSON.stringify(error.details)
        }
      } else if (error?.message) {
        errorMessage = error.message
      }

      toast({
        title: "Error",
        description: errorDetails ? `${errorMessage}: ${errorDetails}` : errorMessage,
        variant: "destructive",
      });
    }
  };

  const handleCancel = () => {
    navigateTo("/leads");
  };

  const handleCreateClient = async () => {
    if (!lead) return;

    try {
      // Show confirmation dialog
      const result = await Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Create Client from Lead',
        text: `Are you sure you want to create a client account for ${lead.name}? This will qualify the lead and create a new client profile.`,
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Yes, Create Client',
        cancelButtonText: 'Cancel',
        confirmButtonColor: '#3B82F6',
        cancelButtonColor: '#6B7280',
      });

      if (!result.isConfirmed) return;

      // Call API to create client from lead
      const response = await fetch(`/api/leads/${leadId}/create-client`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const responseData = await response.json();

      if (!responseData.success) {
        const details = responseData.details && Array.isArray(responseData.details) ? responseData.details.map((d: any) => d.message || d).join(', ') : ''
        throw new Error((responseData.error || 'Failed to create client') + (details ? `: ${details}` : ''));
      }

      toast({
        title: "Success",
        description: `Client created successfully for ${lead.name}`,
      });

      // Navigate to client edit page
      navigateTo(`/clients/edit/${responseData.client._id}`);

    } catch (error: any) {
      console.error('Error creating client from lead:', error);
      toast({
        variant: "destructive",
        title: "Error",
        description: error.message || "Failed to create client from lead",
      });
    }
  };

  const formFields = [
    {
      subform_title: "Client Information",
      fields: [
        {
          name: "name",
          label: "Contact Name",
          type: "text" as const,
          required: true,
          placeholder: "Enter contact name",
          description: "Full name of the primary contact",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "email",
          label: "Email Address",
          type: "email" as const,
          required: true,
          placeholder: "contact@company.com",
          description: "Primary email address for communication",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "phone",
          label: "Phone Number",
          type: "text" as const,
          placeholder: "+1 (555) 123-4567",
          description: "Phone number with country code",
          cols: 12,
          mdCols: 12,
        },
      ]
    },
    {
      subform_title: "Company Information",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "company",
          label: "Company Name",
          type: "text" as const,
          placeholder: "Enter company name",
          description: "Company or organization name",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "website",
          label: "Company Website",
          type: "text" as const,
          placeholder: "https://www.company.com",
          description: "Company website URL",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "position",
          label: "Job Title",
          type: "text" as const,
          placeholder: "CEO, CTO, Manager, etc.",
          description: "Contact's job title or position",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "industry",
          label: "Industry",
          type: "text" as const,
          placeholder: "Technology, Healthcare, Finance, etc.",
          description: "Industry or sector the company operates in",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "companySize",
          label: "Company Size",
          type: "select" as const,
          searchable: true,
          options: [
            { value: "startup", label: "Startup (1-10 employees)" },
            { value: "small", label: "Small (11-50 employees)" },
            { value: "medium", label: "Medium (51-200 employees)" },
            { value: "large", label: "Large (201-1000 employees)" },
            { value: "enterprise", label: "Enterprise (1000+ employees)" },
          ],
          description: "Approximate company size",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "annualRevenue",
          label: "Annual Revenue",
          type: "text" as const,
          placeholder: "5000000",
          description: "Annual revenue in USD (optional)",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "employeeCount",
          label: "Employee Count",
          type: "text" as const,
          placeholder: "50",
          description: "Number of employees in the company",
          cols: 12,
          mdCols: 4,
        },
      ]
    },
    {
      subform_title: "Address Information",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "address.street",
          label: "Street Address",
          type: "text" as const,
          placeholder: "123 Main Street",
          description: "Street address",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "address.city",
          label: "City",
          type: "text" as const,
          placeholder: "New York",
          description: "City",
          cols: 12,
          mdCols: 6,
        },
        {
          name: "address.state",
          label: "State/Province",
          type: "text" as const,
          placeholder: "NY",
          description: "State or province",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "address.zipCode",
          label: "ZIP/Postal Code",
          type: "text" as const,
          placeholder: "10001",
          description: "ZIP or postal code",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "address.country",
          label: "Country",
          type: "text" as const,
          placeholder: "United States",
          description: "Country",
          cols: 12,
          mdCols: 4,
        },
      ]
    },
    {
      subform_title: "Social Links",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "socialLinks",
          label: "Social Links",
          type: "array-object" as const,
          description: "Lead's Social links",
          cols: 12,
          fields: [
            {
              name: "linkName",
              label: "Social Media Platform",
              type: "text" as const,
              required: true,
              description: "Social media platform name",
              cols: 12,
              mdCols: 6,
              lgCols: 6,
            },
            {
              name: "linkUrl",
              label: "Social Media Url",
              type: "url" as const,
              required: true,
              description: "Social media platform URL",
              cols: 12,
              mdCols: 6,
              lgCols: 6,
            },
          ]
        },
      ]
    },
    {
      subform_title: "Source & Follow-up",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "source",
          label: "Lead Source",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "website", label: "Website" },
            { value: "referral", label: "Referral" },
            { value: "cold_call", label: "Cold Call" },
            { value: "email", label: "Email Marketing" },
            { value: "social_media", label: "Social Media" },
            { value: "event", label: "Event/Conference" },
            { value: "partner", label: "Partner" },
            { value: "advertising", label: "Advertising" },
            { value: "other", label: "Other" },
          ],
          cols: 12,
          mdCols: 3,
        },
        {
          name: "status",
          label: "Status",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "active", label: "Active" },
            { value: "inactive", label: "Inactive" },
            { value: "qualified", label: "Qualified" },
            { value: "unqualified", label: "Unqualified" },
          ],
          cols: 12,
          mdCols: 3,
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
          cols: 12,
          mdCols: 3,
        },
        {
          name: "nextFollowUpDate",
          label: "Next Follow-up",
          type: "date" as const,
          description: "Schedule next follow-up date",
          cols: 12,
          mdCols: 3,
        },
        {
          name: "notes",
          label: "Notes",
          type: "rich-text" as const,
          placeholder: "Add any additional notes about this lead...",
          description: "Internal notes about the lead",
          cols: 12,
          rows: 3,
        },
      ]
    },
    {
      subform_title: "Project Information",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "projectName",
          label: "Project Name",
          type: "text" as const,
          required: true,
          placeholder: "Enter project name",
          description: "Name or title of the proposed project",
          cols: 12,
          mdCols: 6,
        },
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
          mdCols: 3,
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
          mdCols: 3,
        },
        {
          name: "projectBudget",
          label: "Budget (USD)",
          type: "text" as const,
          placeholder: "50000",
          description: "Estimated project budget in USD",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "estimatedHours",
          label: "Estimated Hours",
          type: "text" as const,
          placeholder: "160",
          description: "Estimated total hours for the project",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "projectTimeline",
          label: "Timeline",
          type: "text" as const,
          placeholder: "3-6 months",
          description: "Expected project duration or timeline",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "projectDescription",
          label: "Project Description",
          type: "rich-text" as const,
          placeholder: "Describe the project requirements and goals...",
          description: "Detailed description of the project",
          cols: 12,
          rows: 4,
        },
        {
          name: "customerServices",
          label: "Customer Services",
          type: "array-input" as const,
          placeholder: "Add Services that Customers Offers in his Business...",
          description: "Required customer services for the project",
          cols: 12,
        },
        {
          name: "technologies",
          label: "Tools & Technologies",
          type: "array-input" as const,
          placeholder: "Add technology...",
          description: "Required technologies for the project",
          cols: 6,
        },
        {
          name: "projectRequirements",
          label: "Key Requirements",
          type: "array-input" as const,
          placeholder: "Add requirement...",
          description: "Key requirements and features needed",
          cols: 6,
        },
      ]
    }
  ];

  // Show loading skeleton while fetching lead data
  if (leadLoading && !lead) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Edit Lead"
          subtitle="Update lead information"
          showAddButton={false}
          actions={
            <Button variant="outline" disabled>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Leads
            </Button>
          }
        />

        <div className=" space-y-6">
          <div className="space-y-4">
            <div className="space-y-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-10 w-full" />
            </div>
            <div className="space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-10 w-48" />
            </div>
            <div className="space-y-2">
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-24 w-full" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Show error if lead not found
  if (!actionLoading && !lead) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Lead Not Found"
          subtitle="The requested lead could not be found"
          showAddButton={false}
          actions={
            <Button variant="outline" onClick={handleCancel}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Leads
            </Button>
          }
        />

        <div className="text-center py-12">
          <p className="text-muted-foreground">
            The lead you're looking for doesn't exist or has been deleted.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Edit Lead"
        subtitle={`Update information for "${lead?.name}"`}
        showAddButton={false}
        actions={
          <div className="flex items-center gap-2">
            {/* Create Client button - only show if lead can be converted */}
            {lead &&
              lead.status === 'active' &&
              !lead.clientId &&
              canCreate('clients') && (
                <Button
                  variant="default"
                  onClick={handleCreateClient}
                  disabled={actionLoading}
                  className="bg-primary hover:bg-primary/90 text-primary-foreground"
                >
                  <UserPlus className="h-4 w-4 mr-2" />
                  Create Client
                </Button>
              )}

            <Button
              variant="outline"
              onClick={handleCancel}
              disabled={actionLoading}
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Leads
            </Button>
          </div>
        }
      />

      <div>
        <GenericForm
          form={form}
          fields={formFields}
          onSubmit={handleSubmit}
          onCancel={handleCancel}
          loading={actionLoading}
          submitText="Update Lead"
          cancelText="Cancel"
        />
      </div>
    </div>
  );
}