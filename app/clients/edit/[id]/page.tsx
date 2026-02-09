"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useClients } from "@/hooks/use-clients";
import PageHeader from "@/components/shared/page-header";
import GenericForm from "@/components/shared/generic-form";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ArrowLeft, FolderPlus } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useNavigationLoading } from "@/hooks/use-navigation-loading";
import { updateClientFormSchema, UpdateClientFormData, UpdateClientData } from '@/lib/validations/client';
import { useNavigation } from "@/components/providers/navigation-provider";

export default function EditClientPage() {
  const router = useRouter();
  const params = useParams();
  const { toast } = useToast();
  const clientId = params?.id as string;
  const { navigateTo } = useNavigation()

  const { updateClient, actionLoading, fetchClientById, selectedClient, clientByIdLoading, setSelectedClient } = useClients();

  const form = useForm({
    resolver: zodResolver(updateClientFormSchema),
    defaultValues: {
      name: "",
      email: "",
      phone: "",
      position: "",
      company: "",
      website: "",
      industry: "",
      companySize: "",
      annualRevenue: "",
      employeeCount: "",
      clientStatus: "qualified",
      status: "active",
      address: {
        street: "",
        city: "",
        state: "",
        zipCode: "",
        country: "",
      },
      socialLinks: [] as { linkName: string; linkUrl: string }[],
      notes: "",
    },
  });

  // Load client data
  useEffect(() => {
    if (clientId) {
      fetchClientById(clientId);
    }
  }, [clientId, fetchClientById]);

  // Populate form when client data is loaded
  useEffect(() => {
    if (selectedClient) {
      interface Address {
        street: string;
        city: string;
        state: string;
        zipCode: string;
        country: string;
      }

      interface SocialLink {
        linkName: string;
        linkUrl: string;
      }

      interface SelectedClient {
        name?: string;
        email?: string;
        phone?: string;
        position?: string;
        company?: string;
        website?: string;
        industry?: string;
        companySize?: "startup" | "small" | "medium" | "large" | "enterprise";
        annualRevenue?: string | number;
        employeeCount?: string | number;
        clientStatus?: string;
        status?: string;
        address?: Address;
        socialLinks?: SocialLink[];
        notes?: string;
        _id?: string;
      }

      form.reset({
        name: (selectedClient as SelectedClient).name || "",
        email: (selectedClient as SelectedClient).email || "",
        phone: (selectedClient as SelectedClient).phone || "",
        position: (selectedClient as SelectedClient).position || "",
        company: (selectedClient as SelectedClient).company || "",
        website: (selectedClient as SelectedClient).website || "",
        industry: (selectedClient as SelectedClient).industry || "",
        companySize:
          (selectedClient as SelectedClient).companySize &&
          ["startup", "small", "medium", "large", "enterprise"].includes(
        (selectedClient as SelectedClient).companySize as string
          )
        ? ((selectedClient as SelectedClient).companySize as
            | "startup"
            | "small"
            | "medium"
            | "large"
            | "enterprise")
        : "",
        annualRevenue: (selectedClient as SelectedClient).annualRevenue
          ? String((selectedClient as SelectedClient).annualRevenue)
          : "",
        employeeCount: (selectedClient as SelectedClient).employeeCount
          ? String((selectedClient as SelectedClient).employeeCount)
          : "",
        clientStatus: (selectedClient as SelectedClient).clientStatus || "qualified",
        status: (selectedClient as SelectedClient).status || "active",
        address: {
          street: (selectedClient as SelectedClient).address?.street || "",
          city: (selectedClient as SelectedClient).address?.city || "",
          state: (selectedClient as SelectedClient).address?.state || "",
          zipCode: (selectedClient as SelectedClient).address?.zipCode || "",
          country: (selectedClient as SelectedClient).address?.country || "",
        },
        socialLinks: Array.isArray((selectedClient as SelectedClient).socialLinks)
          ? ((selectedClient as SelectedClient).socialLinks as SocialLink[]).map(
          (link: SocialLink | undefined) =>
            link && typeof link === "object"
          ? { linkName: link.linkName || "", linkUrl: link.linkUrl || "" }
          : { linkName: "", linkUrl: "" }
        )
          : ([] as SocialLink[]),
        notes: (selectedClient as SelectedClient).notes || "",
      });
    }
  }, [selectedClient, form]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      setSelectedClient(null);
    };
  }, [setSelectedClient]);

  const handleSubmit = async (data: UpdateClientFormData) => {
    console.log('Form data being sent: form ready to submit');
    console.log('Form data being sent:133', data);
    console.log('clientId:134', selectedClient?._id);
    if (!selectedClient || !selectedClient._id) return;

    try {
      console.log('Form data being sent:', data);

      // Clean up data
      const cleanedData = {
        ...data,
        phone: data.phone?.trim() || undefined,
        companySize: (data.companySize && data.companySize.length > 0) ? data.companySize as "startup" | "small" | "medium" | "large" | "enterprise" : undefined,
        annualRevenue: data.annualRevenue || undefined,
        employeeCount: data.employeeCount || undefined,
        socialLinks: data.socialLinks ? data.socialLinks.map(item => ({
          linkName: item.linkName,
          linkUrl: item.linkUrl as string,
        })) : undefined,
      };

      const result = await updateClient(selectedClient._id, cleanedData);

      toast({
        title: "Success",
        description: "Client updated successfully",
      });

      navigateTo("/clients");
    } catch (error: any) {
      console.error('Update client error:', error)

      // Handle structured API errors
      let errorMessage = "Failed to update client"
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

  const { isNavigating, handleNavigation } = useNavigationLoading();

  const handleCancel = () => {
    handleNavigation("/clients");
  };

  const formFields = [
    {
      subform_title: "Basic Information",
      fields: [
        {
          name: "name",
          label: "Client Name",
          type: "text" as const,
          required: true,
          placeholder: "Enter client name",
          description: "Full name of the client",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "email",
          label: "Email Address",
          type: "email" as const,
          required: true,
          placeholder: "client@company.com",
          description: "Primary email address for communication",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "phone",
          label: "Phone Number",
          type: "text" as const,
          placeholder: "+1 (555) 123-4567",
          description: "Phone number with country code",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "position",
          label: "Job Title",
          type: "text" as const,
          placeholder: "CEO, CTO, Manager, etc.",
          description: "Client's job title or position",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "clientStatus",
          label: "Client Status",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "qualified", label: "Qualified" },
            { value: "unqualified", label: "Unqualified" },
          ],
          description: "Client qualification status",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "status",
          label: "Account Status",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "active", label: "Active" },
            { value: "inactive", label: "Inactive" },
            { value: "qualified", label: "Qualified" },
            { value: "unqualified", label: "Unqualified" },
          ],
          description: "Account status",
          cols: 12,
          mdCols: 4,
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
          required: true,
          placeholder: "Enter company name",
          description: "Company or organization name",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "website",
          label: "Company Website",
          type: "url" as const,
          required: true,
          placeholder: "Enter company website url",
          description: "Company or organization website URL",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "industry",
          label: "Industry",
          type: "text" as const,
          placeholder: "Technology, Healthcare, Finance, etc.",
          description: "Industry or sector the company operates in",
          cols: 12,
          mdCols: 4,
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
          required: false,
          fields: [
            {
              name: "linkName",
              label: "Platform",
              type: "text" as const,
              required: true,
              placeholder: "LinkedIn, Twitter, GitHub, etc.",
              cols: 12,
              mdCols: 6,
              lgCols: 6,
            },
            {
              name: "linkUrl",
              label: "URL",
              type: "url" as const,
              required: true,
              placeholder: "https://...",
              cols: 12,
              mdCols: 6,
              lgCols: 6,
            },
          ],
          description: "Add social media profiles and links",
          cols: 12,
        },
      ]
    },
    {
      subform_title: "Additional Notes",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "notes",
          label: "Notes",
          type: "rich-text" as const,
          placeholder: "Add any additional notes about this client...",
          description: "Internal notes about the client",
          cols: 12,
          rows: 3,
        },
      ]
    }
  ];

  // Show loading skeleton while fetching client data
  if (clientByIdLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Edit Client"
          subtitle="Update client information"
          showAddButton={false}
          actions={
            <Button variant="outline" disabled>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Clients
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

  // Show error if client not found
  if (!clientByIdLoading && !selectedClient) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Client Not Found"
          subtitle="The requested client could not be found"
          showAddButton={false}
          actions={
            <Button variant="outline" onClick={handleCancel}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Clients
            </Button>
          }
        />

        <div className="text-center py-12">
          <p className="text-muted-foreground">
            The client you're looking for doesn't exist or has been deleted.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Edit Client"
        subtitle={`Update information for "${selectedClient?.name}"`}
        showAddButton={false}
        actions={
          <div className="flex gap-2">
            {selectedClient?.status === 'qualified' && (
              <Button
                onClick={() => navigateTo(`/projects/add?clientId=${selectedClient._id}&prefill=true`)}
                disabled={actionLoading}
              >
                <FolderPlus className="mr-2 h-4 w-4" />
                Create Project
              </Button>
            )}
            <Button
              variant="outline"
              onClick={handleCancel}
              disabled={isNavigating || actionLoading}
            >
              <ArrowLeft className={`h-4 w-4 mr-2 ${isNavigating ? 'animate-spin' : ''}`} />
              {isNavigating ? 'Going back...' : 'Back to Clients'}
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
          submitText="Update Client"
          cancelText="Cancel"
        />
      </div>
    </div>
  );
}