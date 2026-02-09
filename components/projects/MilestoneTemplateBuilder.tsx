"use client"

import React, { useState, useCallback, useEffect } from 'react'
import { useForm, useFieldArray } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import CustomModal from '@/components/shared/custom-modal'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Separator } from '@/components/ui/separator'
import { useToast } from '@/hooks/use-toast'
import { useDepartments } from '@/hooks/use-departments'
import { useRoles } from '@/hooks/use-roles'
import { 
  Plus, 
  Trash2, 
  Copy, 
  Eye, 
  Edit3, 
  Save, 
  X, 
  ChevronDown, 
  ChevronRight,
  Calendar,
  Clock,
  DollarSign,
  Users,
  Target,
  CheckCircle,
  AlertTriangle,
  Workflow,
  Lightbulb,
  BookTemplateIcon
} from 'lucide-react'

// Validation Schema
const milestoneItemSchema = z.object({
  title: z.string().min(2).max(200),
  description: z.string().max(1000).optional(),
  durationDays: z.number().min(1).max(365),
  dependencies: z.array(z.string()).default([]),
  deliverables: z.array(z.string()).min(1),
  successCriteria: z.array(z.string()).min(1),
  priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
  requiredApprovals: z.array(z.string()).default([]),
  estimatedBudget: z.number().min(0).optional(),
  estimatedHours: z.number().min(0).optional()
})

const approvalStageSchema = z.object({
  stageName: z.string().min(2).max(100),
  requiredRoles: z.array(z.string()).min(1),
  isOptional: z.boolean().default(false),
  order: z.number().min(0)
})

const templateSchema = z.object({
  name: z.string().min(2).max(100),
  description: z.string().max(500).optional(),
  category: z.enum(['design', 'development', 'marketing', 'hr', 'finance', 'operations', 'generic']).default('generic'),
  milestones: z.array(milestoneItemSchema).min(1).max(20),
  workflowConfig: z.object({
    requiresApproval: z.boolean().default(false),
    approvalStages: z.array(approvalStageSchema).default([]),
    autoProgressRules: z.array(z.object({
      condition: z.string(),
      action: z.string()
    })).default([])
  }),
  isPublic: z.boolean().default(false),
  tags: z.array(z.string()).default([])
})

type TemplateFormData = z.infer<typeof templateSchema>

interface TemplateData {
  _id?: string
  name: string
  description?: string
  category: 'design' | 'development' | 'marketing' | 'hr' | 'finance' | 'operations' | 'generic'
  milestones: {
    title: string
    description?: string
    durationDays: number
    dependencies?: string[]
    deliverables: string[]
    successCriteria: string[]
    priority: 'low' | 'medium' | 'high' | 'urgent'
    requiredApprovals?: string[]
    estimatedBudget?: number
    estimatedHours?: number
  }[]
  workflowConfig: {
    requiresApproval: boolean
    approvalStages: {
      stageName: string
      requiredRoles: string[]
      isOptional: boolean
      order: number
    }[]
    autoProgressRules?: {
      condition: string
      action: string
    }[]
  }
  isPublic: boolean
  tags: string[]
}

interface MilestoneTemplateBuilderProps {
  isOpen: boolean
  onClose: () => void
  template?: TemplateData
  mode: 'create' | 'edit' | 'view'
  onSave?: (template: TemplateData) => void
}

// Category configurations with pre-built templates
const CATEGORY_TEMPLATES = {
  design: {
    name: 'UI/UX Design Project',
    description: 'Standard design workflow with research, wireframes, prototyping, and final design',
    milestones: [
      {
        title: 'Research & Discovery',
        description: 'User research, competitive analysis, and requirements gathering',
        durationDays: 7,
        dependencies: [],
        deliverables: ['User personas', 'Competitive analysis report', 'Requirements document'],
        successCriteria: ['User needs identified', 'Business goals clarified', 'Technical constraints documented'],
        priority: 'high' as const,
        requiredApprovals: ['project-manager', 'client'],
        estimatedHours: 40
      },
      {
        title: 'Wireframing & Information Architecture',
        description: 'Create wireframes and define information architecture',
        durationDays: 5,
        dependencies: ['Research & Discovery'],
        deliverables: ['Wireframes', 'Site map', 'User flow diagrams'],
        successCriteria: ['Navigation structure approved', 'Content hierarchy defined', 'User flows validated'],
        priority: 'high' as const,
        requiredApprovals: [],
        estimatedHours: 30
      },
      {
        title: 'Visual Design & Prototyping',
        description: 'Create high-fidelity designs and interactive prototypes',
        durationDays: 10,
        dependencies: ['Wireframing & Information Architecture'],
        deliverables: ['High-fidelity mockups', 'Interactive prototype', 'Design system components'],
        successCriteria: ['Visual design approved', 'Prototype functionality validated', 'Brand guidelines followed'],
        priority: 'high' as const,
        requiredApprovals: [],
        estimatedHours: 60
      },
      {
        title: 'Design Review & Handoff',
        description: 'Final design review and developer handoff',
        durationDays: 3,
        dependencies: ['Visual Design & Prototyping'],
        deliverables: ['Final design assets', 'Developer specifications', 'Asset library'],
        successCriteria: ['All designs approved', 'Developer documentation complete', 'Assets organized and delivered'],
        priority: 'medium' as const,
        requiredApprovals: [],
        estimatedHours: 20
      }
    ]
  },
  development: {
    name: 'Software Development Sprint',
    description: 'Agile development workflow with planning, development, testing, and deployment',
    milestones: [
      {
        title: 'Sprint Planning & Setup',
        description: 'Define sprint goals, tasks, and technical setup',
        durationDays: 2,
        dependencies: [],
        deliverables: ['Sprint backlog', 'Technical specifications', 'Development environment setup'],
        successCriteria: ['Team aligned on goals', 'Tasks estimated and assigned', 'Environment ready'],
        priority: 'high' as const,
        requiredApprovals: [],
        estimatedHours: 16
      },
      {
        title: 'Core Development',
        description: 'Implement main features and functionality',
        durationDays: 8,
        dependencies: ['Sprint Planning & Setup'],
        deliverables: ['Feature implementations', 'Code documentation', 'Unit tests'],
        successCriteria: ['Features meet requirements', 'Code review passed', 'Tests passing'],
        priority: 'high' as const,
        requiredApprovals: [],
        estimatedHours: 64
      },
      {
        title: 'Integration & Testing',
        description: 'Integration testing and bug fixes',
        durationDays: 3,
        dependencies: ['Core Development'],
        deliverables: ['Integration test results', 'Bug fixes', 'Performance optimization'],
        successCriteria: ['All tests passing', 'Performance acceptable', 'No critical bugs'],
        priority: 'high' as const,
        requiredApprovals: [],
        estimatedHours: 24
      },
      {
        title: 'Deployment & Review',
        description: 'Deploy to production and conduct sprint review',
        durationDays: 2,
        dependencies: ['Integration & Testing'],
        deliverables: ['Production deployment', 'Sprint review presentation', 'Retrospective notes'],
        successCriteria: ['Successfully deployed', 'Stakeholders satisfied', 'Lessons learned documented'],
        priority: 'medium' as const,
        requiredApprovals: [],
        estimatedHours: 16
      }
    ]
  },
  marketing: {
    name: 'Marketing Campaign Launch',
    description: 'Complete marketing campaign from planning to execution and analysis',
    milestones: [
      {
        title: 'Campaign Strategy & Planning',
        description: 'Define campaign objectives, target audience, and strategy',
        durationDays: 5,
        dependencies: [],
        deliverables: ['Campaign strategy document', 'Target audience analysis', 'Budget allocation plan'],
        successCriteria: ['Goals clearly defined', 'Audience segments identified', 'Budget approved'],
        priority: 'high' as const,
        requiredApprovals: [],
        estimatedBudget: 5000,
        estimatedHours: 32
      },
      {
        title: 'Content Creation & Asset Development',
        description: 'Create all campaign assets and content',
        durationDays: 10,
        dependencies: ['Campaign Strategy & Planning'],
        deliverables: ['Marketing copy', 'Visual assets', 'Landing pages', 'Email templates'],
        successCriteria: ['Content aligns with strategy', 'Brand guidelines followed', 'Assets optimized for channels'],
        priority: 'high' as const,
        requiredApprovals: [],
        estimatedBudget: 8000,
        estimatedHours: 50
      },
      {
        title: 'Campaign Launch & Monitoring',
        description: 'Launch campaign across all channels and monitor performance',
        durationDays: 7,
        dependencies: ['Content Creation & Asset Development'],
        deliverables: ['Campaign activation', 'Performance dashboards', 'Daily monitoring reports'],
        successCriteria: ['Campaign live on all channels', 'Tracking implemented', 'Initial metrics positive'],
        priority: 'urgent' as const,
        requiredApprovals: [],
        estimatedBudget: 15000,
        estimatedHours: 35
      },
      {
        title: 'Analysis & Optimization',
        description: 'Analyze campaign performance and implement optimizations',
        durationDays: 5,
        dependencies: ['Campaign Launch & Monitoring'],
        deliverables: ['Performance analysis report', 'Optimization recommendations', 'ROI calculation'],
        successCriteria: ['KPIs analyzed', 'Optimizations identified', 'Future recommendations provided'],
        priority: 'medium' as const,
        requiredApprovals: [],
        estimatedHours: 25
      }
    ]
  }
}

const ROLE_OPTIONS = [
  'super-administrator',
  'project-manager', 
  'department-head',
  'team-lead',
  'senior-executive',
  'executive',
  'client'
]

export function MilestoneTemplateBuilder({
  isOpen,
  onClose,
  template,
  mode = 'create',
  onSave
}: MilestoneTemplateBuilderProps) {
  const { toast } = useToast()
  const { departments } = useDepartments()
  const [loading, setLoading] = useState(false)
  const [selectedCategory, setSelectedCategory] = useState<string>('')
  const [expandedMilestones, setExpandedMilestones] = useState<Set<number>>(new Set())
  const [newTag, setNewTag] = useState('')

  const form = useForm<TemplateFormData>({
    resolver: zodResolver(templateSchema),
    defaultValues: {
      name: '',
      description: '',
      category: 'generic',
      milestones: [
        {
          title: '',
          description: '',
          durationDays: 7,
          dependencies: [],
          deliverables: [''],
          successCriteria: [''],
          priority: 'medium',
          requiredApprovals: [],
          estimatedHours: 0
        }
      ],
      workflowConfig: {
        requiresApproval: false,
        approvalStages: [],
        autoProgressRules: []
      },
      isPublic: false,
      tags: []
    }
  })

  const { 
    fields: milestoneFields, 
    append: appendMilestone, 
    remove: removeMilestone 
  } = useFieldArray({
    control: form.control,
    name: 'milestones'
  })

  const {
    fields: approvalStageFields,
    append: appendApprovalStage,
    remove: removeApprovalStage
  } = useFieldArray({
    control: form.control,
    name: 'workflowConfig.approvalStages'
  })

  // Load template data when editing
  useEffect(() => {
    if (template && mode !== 'create') {
      form.reset({
        name: template.name,
        description: template.description || '',
        category: template.category,
        milestones: template.milestones || [],
        workflowConfig: template.workflowConfig || {
          requiresApproval: false,
          approvalStages: [],
          autoProgressRules: []
        },
        isPublic: template.isPublic || false,
        tags: template.tags || []
      })
    }
  }, [template, mode, form])

  // Load category template
  const loadCategoryTemplate = useCallback((category: string) => {
    const categoryTemplate = CATEGORY_TEMPLATES[category as keyof typeof CATEGORY_TEMPLATES]
    if (categoryTemplate) {
      form.setValue('name', categoryTemplate.name)
      form.setValue('description', categoryTemplate.description)
      form.setValue('milestones', categoryTemplate.milestones)
      form.setValue('category', category as any)
      
      toast({
        title: "Template Loaded",
        description: `${categoryTemplate.name} template has been loaded with ${categoryTemplate.milestones.length} milestones.`
      })
    }
  }, [form, toast])

  // Add milestone
  const addMilestone = useCallback(() => {
    appendMilestone({
      title: '',
      description: '',
      durationDays: 7,
      dependencies: [],
      deliverables: [''],
      successCriteria: [''],
      priority: 'medium',
      requiredApprovals: [],
      estimatedHours: 0
    })
  }, [appendMilestone])

  // Add approval stage
  const addApprovalStage = useCallback(() => {
    const currentStages = form.getValues('workflowConfig.approvalStages')
    appendApprovalStage({
      stageName: `Stage ${currentStages.length + 1}`,
      requiredRoles: [],
      isOptional: false,
      order: currentStages.length
    })
  }, [appendApprovalStage, form])

  // Add tag
  const addTag = useCallback(() => {
    if (newTag.trim()) {
      const currentTags = form.getValues('tags')
      if (!currentTags.includes(newTag.trim())) {
        form.setValue('tags', [...currentTags, newTag.trim()])
        setNewTag('')
      }
    }
  }, [newTag, form])

  // Remove tag
  const removeTag = useCallback((tagToRemove: string) => {
    const currentTags = form.getValues('tags')
    form.setValue('tags', currentTags.filter(tag => tag !== tagToRemove))
  }, [form])

  // Toggle milestone expansion
  const toggleMilestone = useCallback((index: number) => {
    setExpandedMilestones(prev => {
      const newSet = new Set(prev)
      if (newSet.has(index)) {
        newSet.delete(index)
      } else {
        newSet.add(index)
      }
      return newSet
    })
  }, [])

  // Handle form submission
  const onSubmit = async (data: TemplateFormData) => {
    try {
      setLoading(true)
      
      // Validate milestone dependencies
      const milestoneNames = data.milestones.map(m => m.title)
      for (const milestone of data.milestones) {
        for (const dep of milestone.dependencies) {
          if (!milestoneNames.includes(dep)) {
            toast({
              title: "Invalid Dependencies",
              description: `Milestone "${milestone.title}" has invalid dependency "${dep}"`,
              variant: "destructive"
            })
            return
          }
        }
      }

      // Call API to save template
      const url = mode === 'edit' && template?._id 
        ? `/api/milestone-templates/${template._id}` 
        : '/api/milestone-templates'
      
      const method = mode === 'edit' ? 'PUT' : 'POST'
      
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to save template')
      }

      toast({
        title: "Template Saved",
        description: `Milestone template "${data.name}" has been ${mode === 'edit' ? 'updated' : 'created'} successfully.`
      })

      onSave?.(result.data)
      onClose()

    } catch (error: any) {
      console.error('Error saving template:', error)
      toast({
        title: "Error",
        description: error.message || 'Failed to save template',
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  const totalDuration = form.watch('milestones').reduce((sum, milestone) => sum + (milestone.durationDays || 0), 0)
  const totalBudget = form.watch('milestones').reduce((sum, milestone) => sum + (milestone.estimatedBudget || 0), 0)
  const totalHours = form.watch('milestones').reduce((sum, milestone) => sum + (milestone.estimatedHours || 0), 0)

  return (
    <CustomModal
      isOpen={isOpen}
      onClose={onClose}
      title={mode === 'create' ? 'Create Milestone Template' : 
             mode === 'edit' ? 'Edit Milestone Template' : 'View Milestone Template'}
      modalSize="xl"
    >

        <form onSubmit={form.handleSubmit(onSubmit)} className="flex-1 overflow-hidden">
          <Tabs defaultValue="basic" className="flex flex-col h-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="basic">Basic Info</TabsTrigger>
              <TabsTrigger value="milestones">Milestones ({milestoneFields.length})</TabsTrigger>
              <TabsTrigger value="workflow">Workflow & Approvals</TabsTrigger>
              <TabsTrigger value="preview">Preview & Summary</TabsTrigger>
            </TabsList>

            <div className="flex-1 overflow-auto">
              {/* Basic Information Tab */}
              <TabsContent value="basic" className="space-y-6 p-1">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="name">Template Name</Label>
                      <Input
                        id="name"
                        {...form.register('name')}
                        placeholder="e.g., Website Redesign Project"
                        disabled={mode === 'view'}
                      />
                      {form.formState.errors.name && (
                        <p className="text-sm text-red-600">{form.formState.errors.name.message}</p>
                      )}
                    </div>

                    <div>
                      <Label htmlFor="description">Description</Label>
                      <Textarea
                        id="description"
                        {...form.register('description')}
                        placeholder="Describe what this template is for and when to use it..."
                        rows={3}
                        disabled={mode === 'view'}
                      />
                    </div>

                    <div>
                      <Label htmlFor="category">Category</Label>
                      <Select
                        value={form.watch('category')}
                        onValueChange={(value) => form.setValue('category', value as any)}
                        disabled={mode === 'view'}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="design">Design</SelectItem>
                          <SelectItem value="development">Development</SelectItem>
                          <SelectItem value="marketing">Marketing</SelectItem>
                          <SelectItem value="hr">HR</SelectItem>
                          <SelectItem value="finance">Finance</SelectItem>
                          <SelectItem value="operations">Operations</SelectItem>
                          <SelectItem value="generic">Generic</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="flex items-center space-x-2">
                      <Switch
                        id="isPublic"
                        checked={form.watch('isPublic')}
                        onCheckedChange={(checked) => form.setValue('isPublic', checked)}
                        disabled={mode === 'view'}
                      />
                      <Label htmlFor="isPublic">Make template public (available to all departments)</Label>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <Label>Quick Start Templates</Label>
                      <div className="grid grid-cols-1 gap-2">
                        {Object.entries(CATEGORY_TEMPLATES).map(([key, template]) => (
                          <Button
                            key={key}
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => loadCategoryTemplate(key)}
                            disabled={mode === 'view'}
                            className="justify-start"
                          >
                            <Lightbulb className="h-4 w-4 mr-2" />
                            {template.name}
                          </Button>
                        ))}
                      </div>
                    </div>

                    <div>
                      <Label>Tags</Label>
                      <div className="space-y-2">
                        <div className="flex gap-2">
                          <Input
                            value={newTag}
                            onChange={(e) => setNewTag(e.target.value)}
                            placeholder="Add tag..."
                            disabled={mode === 'view'}
                            onKeyPress={(e) => {
                              if (e.key === 'Enter') {
                                e.preventDefault()
                                addTag()
                              }
                            }}
                          />
                          <Button
                            type="button"
                            onClick={addTag}
                            size="sm"
                            disabled={mode === 'view'}
                          >
                            <Plus className="h-4 w-4" />
                          </Button>
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {form.watch('tags').map((tag, index) => (
                            <Badge key={index} variant="secondary" className="flex items-center gap-1">
                              {tag}
                              {mode !== 'view' && (
                                <button
                                  type="button"
                                  onClick={() => removeTag(tag)}
                                  className="ml-1 hover:bg-red-100 rounded-full p-0.5"
                                >
                                  <X className="h-3 w-3" />
                                </button>
                              )}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>

                    <Card className="p-4">
                      <h4 className="font-medium mb-2 flex items-center gap-2">
                        <Target className="h-4 w-4" />
                        Template Overview
                      </h4>
                      <div className="grid grid-cols-3 gap-4 text-sm">
                        <div className="text-center">
                          <div className="font-semibold text-lg">{milestoneFields.length}</div>
                          <div className="text-gray-600">Milestones</div>
                        </div>
                        <div className="text-center">
                          <div className="font-semibold text-lg">{totalDuration}</div>
                          <div className="text-gray-600">Days</div>
                        </div>
                        <div className="text-center">
                          <div className="font-semibold text-lg">{totalHours}</div>
                          <div className="text-gray-600">Hours</div>
                        </div>
                      </div>
                    </Card>
                  </div>
                </div>
              </TabsContent>

              {/* Milestones Tab */}
              <TabsContent value="milestones" className="space-y-4 p-1">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-medium">Milestones Configuration</h3>
                  {mode !== 'view' && (
                    <Button type="button" onClick={addMilestone} size="sm">
                      <Plus className="h-4 w-4 mr-2" />
                      Add Milestone
                    </Button>
                  )}
                </div>

                <div className="space-y-4">
                  {milestoneFields.map((field, index) => {
                    const isExpanded = expandedMilestones.has(index)
                    return (
                      <Card key={field.id} className="overflow-hidden">
                        <CardHeader 
                          className="pb-3 cursor-pointer"
                          onClick={() => toggleMilestone(index)}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              {isExpanded ? (
                                <ChevronDown className="h-4 w-4" />
                              ) : (
                                <ChevronRight className="h-4 w-4" />
                              )}
                              <CardTitle className="text-base">
                                {form.watch(`milestones.${index}.title`) || `Milestone ${index + 1}`}
                              </CardTitle>
                              <Badge variant={
                                form.watch(`milestones.${index}.priority`) === 'urgent' ? 'destructive' :
                                form.watch(`milestones.${index}.priority`) === 'high' ? 'default' :
                                'secondary'
                              }>
                                {form.watch(`milestones.${index}.priority`)}
                              </Badge>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant="outline">
                                <Clock className="h-3 w-3 mr-1" />
                                {form.watch(`milestones.${index}.durationDays`)} days
                              </Badge>
                              {mode !== 'view' && (
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="sm"
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    removeMilestone(index)
                                  }}
                                  className="text-red-600 hover:text-red-800"
                                >
                                  <Trash2 className="h-4 w-4" />
                                </Button>
                              )}
                            </div>
                          </div>
                        </CardHeader>

                        {isExpanded && (
                          <CardContent className="space-y-4">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div>
                                <Label>Title</Label>
                                <Input
                                  {...form.register(`milestones.${index}.title`)}
                                  placeholder="Milestone title"
                                  disabled={mode === 'view'}
                                />
                              </div>
                              <div>
                                <Label>Duration (Days)</Label>
                                <Input
                                  type="number"
                                  {...form.register(`milestones.${index}.durationDays`, { valueAsNumber: true })}
                                  min="1"
                                  max="365"
                                  disabled={mode === 'view'}
                                />
                              </div>
                            </div>

                            <div>
                              <Label>Description</Label>
                              <Textarea
                                {...form.register(`milestones.${index}.description`)}
                                placeholder="Describe what this milestone involves..."
                                rows={2}
                                disabled={mode === 'view'}
                              />
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div>
                                <Label>Priority</Label>
                                <Select
                                  value={form.watch(`milestones.${index}.priority`)}
                                  onValueChange={(value) => form.setValue(`milestones.${index}.priority`, value as any)}
                                  disabled={mode === 'view'}
                                >
                                  <SelectTrigger>
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent>
                                    <SelectItem value="low">Low</SelectItem>
                                    <SelectItem value="medium">Medium</SelectItem>
                                    <SelectItem value="high">High</SelectItem>
                                    <SelectItem value="urgent">Urgent</SelectItem>
                                  </SelectContent>
                                </Select>
                              </div>
                              <div>
                                <Label>Estimated Hours</Label>
                                <Input
                                  type="number"
                                  {...form.register(`milestones.${index}.estimatedHours`, { valueAsNumber: true })}
                                  min="0"
                                  placeholder="0"
                                  disabled={mode === 'view'}
                                />
                              </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div>
                                <Label>Estimated Budget</Label>
                                <Input
                                  type="number"
                                  {...form.register(`milestones.${index}.estimatedBudget`, { valueAsNumber: true })}
                                  min="0"
                                  placeholder="0"
                                  disabled={mode === 'view'}
                                />
                              </div>
                              <div>
                                <Label>Dependencies</Label>
                                <Select
                                  value=""
                                  onValueChange={(value) => {
                                    const current = form.getValues(`milestones.${index}.dependencies`) || []
                                    if (!current.includes(value)) {
                                      form.setValue(`milestones.${index}.dependencies`, [...current, value])
                                    }
                                  }}
                                  disabled={mode === 'view'}
                                >
                                  <SelectTrigger>
                                    <SelectValue placeholder="Add dependency..." />
                                  </SelectTrigger>
                                  <SelectContent>
                                    {milestoneFields
                                      .filter((_, i) => i !== index)
                                      .map((_, i) => {
                                        const adjustedIndex = i >= index ? i + 1 : i
                                        const title = form.watch(`milestones.${adjustedIndex}.title`)
                                        return title ? (
                                          <SelectItem key={adjustedIndex} value={title}>
                                            {title}
                                          </SelectItem>
                                        ) : null
                                      })}
                                  </SelectContent>
                                </Select>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {(form.watch(`milestones.${index}.dependencies`) || []).map((dep, depIndex) => (
                                    <Badge key={depIndex} variant="outline" className="text-xs">
                                      {dep}
                                      {mode !== 'view' && (
                                        <button
                                          type="button"
                                          onClick={() => {
                                            const current = form.getValues(`milestones.${index}.dependencies`)
                                            form.setValue(
                                              `milestones.${index}.dependencies`,
                                              current.filter((_, i) => i !== depIndex)
                                            )
                                          }}
                                          className="ml-1 hover:bg-red-100 rounded-full p-0.5"
                                        >
                                          <X className="h-2 w-2" />
                                        </button>
                                      )}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            </div>

                            <Separator />

                            <div>
                              <Label>Deliverables</Label>
                              <DeliverablesList
                                value={form.watch(`milestones.${index}.deliverables`) || ['']}
                                onChange={(deliverables) => form.setValue(`milestones.${index}.deliverables`, deliverables)}
                                disabled={mode === 'view'}
                              />
                            </div>

                            <div>
                              <Label>Success Criteria</Label>
                              <SuccessCriteriaList
                                value={form.watch(`milestones.${index}.successCriteria`) || ['']}
                                onChange={(criteria) => form.setValue(`milestones.${index}.successCriteria`, criteria)}
                                disabled={mode === 'view'}
                              />
                            </div>
                          </CardContent>
                        )}
                      </Card>
                    )
                  })}
                </div>
              </TabsContent>

              {/* Workflow & Approvals Tab */}
              <TabsContent value="workflow" className="space-y-6 p-1">
                <div>
                  <h3 className="text-lg font-medium mb-4">Approval Workflow Configuration</h3>
                  
                  <div className="space-y-4">
                    <div className="flex items-center space-x-2">
                      <Switch
                        id="requiresApproval"
                        checked={form.watch('workflowConfig.requiresApproval')}
                        onCheckedChange={(checked) => form.setValue('workflowConfig.requiresApproval', checked)}
                        disabled={mode === 'view'}
                      />
                      <Label htmlFor="requiresApproval">Require approval workflow for milestones created from this template</Label>
                    </div>

                    {form.watch('workflowConfig.requiresApproval') && (
                      <Card className="p-4">
                        <div className="flex justify-between items-center mb-4">
                          <h4 className="font-medium">Approval Stages</h4>
                          {mode !== 'view' && (
                            <Button type="button" onClick={addApprovalStage} size="sm" variant="outline">
                              <Plus className="h-4 w-4 mr-2" />
                              Add Stage
                            </Button>
                          )}
                        </div>

                        <div className="space-y-3">
                          {approvalStageFields.map((field, index) => (
                            <Card key={field.id} className="p-3">
                              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
                                <div>
                                  <Label>Stage Name</Label>
                                  <Input
                                    {...form.register(`workflowConfig.approvalStages.${index}.stageName`)}
                                    placeholder="e.g., Manager Review"
                                    disabled={mode === 'view'}
                                  />
                                </div>
                                
                                <div>
                                  <Label>Required Roles</Label>
                                  <Select
                                    value=""
                                    onValueChange={(value) => {
                                      const current = form.getValues(`workflowConfig.approvalStages.${index}.requiredRoles`) || []
                                      if (!current.includes(value)) {
                                        form.setValue(
                                          `workflowConfig.approvalStages.${index}.requiredRoles`,
                                          [...current, value]
                                        )
                                      }
                                    }}
                                    disabled={mode === 'view'}
                                  >
                                    <SelectTrigger>
                                      <SelectValue placeholder="Add role..." />
                                    </SelectTrigger>
                                    <SelectContent>
                                      {ROLE_OPTIONS.map(role => (
                                        <SelectItem key={role} value={role}>
                                          {role.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                                        </SelectItem>
                                      ))}
                                    </SelectContent>
                                  </Select>
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {(form.watch(`workflowConfig.approvalStages.${index}.requiredRoles`) || []).map((role, roleIndex) => (
                                      <Badge key={roleIndex} variant="outline" className="text-xs">
                                        {role.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                                        {mode !== 'view' && (
                                          <button
                                            type="button"
                                            onClick={() => {
                                              const current = form.getValues(`workflowConfig.approvalStages.${index}.requiredRoles`)
                                              form.setValue(
                                                `workflowConfig.approvalStages.${index}.requiredRoles`,
                                                current.filter((_, i) => i !== roleIndex)
                                              )
                                            }}
                                            className="ml-1 hover:bg-red-100 rounded-full p-0.5"
                                          >
                                            <X className="h-2 w-2" />
                                          </button>
                                        )}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>

                                <div>
                                  <Label>Order</Label>
                                  <Input
                                    type="number"
                                    {...form.register(`workflowConfig.approvalStages.${index}.order`, { valueAsNumber: true })}
                                    min="0"
                                    disabled={mode === 'view'}
                                  />
                                </div>

                                <div className="flex items-center gap-2">
                                  <div className="flex items-center space-x-2">
                                    <Switch
                                      id={`optional-${index}`}
                                      checked={form.watch(`workflowConfig.approvalStages.${index}.isOptional`)}
                                      onCheckedChange={(checked) => 
                                        form.setValue(`workflowConfig.approvalStages.${index}.isOptional`, checked)
                                      }
                                      disabled={mode === 'view'}
                                    />
                                    <Label htmlFor={`optional-${index}`} className="text-sm">Optional</Label>
                                  </div>
                                  
                                  {mode !== 'view' && (
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => removeApprovalStage(index)}
                                      className="text-red-600 hover:text-red-800"
                                    >
                                      <Trash2 className="h-4 w-4" />
                                    </Button>
                                  )}
                                </div>
                              </div>
                            </Card>
                          ))}

                          {approvalStageFields.length === 0 && (
                            <div className="text-center py-8 text-gray-500">
                              <Workflow className="h-8 w-8 mx-auto mb-2" />
                              <p>No approval stages configured</p>
                              {mode !== 'view' && (
                                <p className="text-sm">Click "Add Stage" to create approval workflow</p>
                              )}
                            </div>
                          )}
                        </div>
                      </Card>
                    )}
                  </div>
                </div>
              </TabsContent>

              {/* Preview & Summary Tab */}
              <TabsContent value="preview" className="space-y-6 p-1">
                <div>
                  <h3 className="text-lg font-medium mb-4">Template Preview & Summary</h3>
                  
                  {/* Summary Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    <Card className="p-4 text-center">
                      <div className="text-2xl font-bold text-blue-600">{milestoneFields.length}</div>
                      <div className="text-sm text-gray-600">Milestones</div>
                    </Card>
                    <Card className="p-4 text-center">
                      <div className="text-2xl font-bold text-green-600">{totalDuration}</div>
                      <div className="text-sm text-gray-600">Total Days</div>
                    </Card>
                    <Card className="p-4 text-center">
                      <div className="text-2xl font-bold text-orange-600">{totalHours}</div>
                      <div className="text-sm text-gray-600">Total Hours</div>
                    </Card>
                    <Card className="p-4 text-center">
                      <div className="text-2xl font-bold text-purple-600">
                        {totalBudget > 0 ? `$${totalBudget.toLocaleString()}` : '-'}
                      </div>
                      <div className="text-sm text-gray-600">Est. Budget</div>
                    </Card>
                  </div>

                  {/* Timeline Preview */}
                  <Card className="p-4">
                    <h4 className="font-medium mb-3">Timeline Preview</h4>
                    <div className="space-y-2">
                      {milestoneFields.map((_, index) => {
                        const milestone = form.watch(`milestones.${index}`)
                        const startDay = milestoneFields.slice(0, index).reduce((sum, _, i) => 
                          sum + (form.watch(`milestones.${i}.durationDays`) || 0), 0
                        )
                        const endDay = startDay + (milestone.durationDays || 0)
                        
                        return (
                          <div key={index} className="flex items-center gap-3 p-2 rounded border">
                            <div className="w-4 h-4 rounded-full bg-blue-500 flex-shrink-0"></div>
                            <div className="flex-1">
                              <div className="font-medium">{milestone.title || `Milestone ${index + 1}`}</div>
                              <div className="text-sm text-gray-600">
                                Day {startDay + 1} - {endDay} ({milestone.durationDays} days)
                              </div>
                            </div>
                            <Badge variant={
                              milestone.priority === 'urgent' ? 'destructive' :
                              milestone.priority === 'high' ? 'default' :
                              'secondary'
                            }>
                              {milestone.priority}
                            </Badge>
                          </div>
                        )
                      })}
                    </div>
                  </Card>

                  {/* Approval Workflow Preview */}
                  {form.watch('workflowConfig.requiresApproval') && approvalStageFields.length > 0 && (
                    <Card className="p-4">
                      <h4 className="font-medium mb-3">Approval Workflow</h4>
                      <div className="space-y-2">
                        {approvalStageFields
                          .sort((a, b) => form.watch(`workflowConfig.approvalStages.${approvalStageFields.indexOf(a)}.order`) - 
                                         form.watch(`workflowConfig.approvalStages.${approvalStageFields.indexOf(b)}.order`))
                          .map((field, index) => {
                            const stage = form.watch(`workflowConfig.approvalStages.${index}`)
                            return (
                              <div key={field.id} className="flex items-center gap-3 p-2 rounded border">
                                <div className="w-6 h-6 rounded-full bg-gray-200 flex items-center justify-center text-sm font-medium">
                                  {stage.order + 1}
                                </div>
                                <div className="flex-1">
                                  <div className="font-medium">{stage.stageName}</div>
                                  <div className="text-sm text-gray-600">
                                    Required roles: {stage.requiredRoles?.join(', ') || 'None'}
                                  </div>
                                </div>
                                {stage.isOptional && (
                                  <Badge variant="outline">Optional</Badge>
                                )}
                              </div>
                            )
                          })}
                      </div>
                    </Card>
                  )}
                </div>
              </TabsContent>
            </div>
          </Tabs>

          {/* Footer Actions */}
          <div className="flex justify-end gap-2 pt-4 border-t">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            {mode !== 'view' && (
              <Button type="submit" disabled={loading}>
                {loading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Saving...
                  </>
                ) : (
                  <>
                    <Save className="h-4 w-4 mr-2" />
                    {mode === 'edit' ? 'Update Template' : 'Create Template'}
                  </>
                )}
              </Button>
            )}
          </div>
        </form>
    </CustomModal>
  )
}

// Helper Components
function DeliverablesList({ 
  value, 
  onChange, 
  disabled 
}: { 
  value: string[]
  onChange: (value: string[]) => void
  disabled?: boolean 
}) {
  const addDeliverable = () => {
    onChange([...value, ''])
  }

  const removeDeliverable = (index: number) => {
    onChange(value.filter((_, i) => i !== index))
  }

  const updateDeliverable = (index: number, newValue: string) => {
    const updated = [...value]
    updated[index] = newValue
    onChange(updated)
  }

  return (
    <div className="space-y-2">
      {value.map((deliverable, index) => (
        <div key={index} className="flex gap-2">
          <Input
            value={deliverable}
            onChange={(e) => updateDeliverable(index, e.target.value)}
            placeholder={`Deliverable ${index + 1}`}
            disabled={disabled}
          />
          {!disabled && value.length > 1 && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => removeDeliverable(index)}
              className="text-red-600 hover:text-red-800"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      ))}
      {!disabled && (
        <Button type="button" onClick={addDeliverable} size="sm" variant="outline">
          <Plus className="h-4 w-4 mr-2" />
          Add Deliverable
        </Button>
      )}
    </div>
  )
}

function SuccessCriteriaList({ 
  value, 
  onChange, 
  disabled 
}: { 
  value: string[]
  onChange: (value: string[]) => void
  disabled?: boolean 
}) {
  const addCriteria = () => {
    onChange([...value, ''])
  }

  const removeCriteria = (index: number) => {
    onChange(value.filter((_, i) => i !== index))
  }

  const updateCriteria = (index: number, newValue: string) => {
    const updated = [...value]
    updated[index] = newValue
    onChange(updated)
  }

  return (
    <div className="space-y-2">
      {value.map((criteria, index) => (
        <div key={index} className="flex gap-2">
          <Input
            value={criteria}
            onChange={(e) => updateCriteria(index, e.target.value)}
            placeholder={`Success criteria ${index + 1}`}
            disabled={disabled}
          />
          {!disabled && value.length > 1 && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => removeCriteria(index)}
              className="text-red-600 hover:text-red-800"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
        </div>
      ))}
      {!disabled && (
        <Button type="button" onClick={addCriteria} size="sm" variant="outline">
          <Plus className="h-4 w-4 mr-2" />
          Add Success Criteria
        </Button>
      )}
    </div>
  )
}

export default MilestoneTemplateBuilder