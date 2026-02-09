"use client"

import React, { useState, useCallback, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import CustomModal from '@/components/shared/custom-modal'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Switch } from '@/components/ui/switch'
import { useToast } from '@/hooks/use-toast'
import { MilestoneTemplateBuilder } from './MilestoneTemplateBuilder'
import {
    Plus,
    Search,
    Filter,
    Eye,
    Edit3,
    Copy,
    Trash2,
    Clock,
    Target,
    Users,
    DollarSign,
    Calendar,
    TrendingUp,
    Star,
    Lightbulb,
    Rocket,
    CheckCircle,
    Workflow,
    Download,
    BookTemplateIcon
} from 'lucide-react'

interface MilestoneTemplateGalleryProps {
    isOpen: boolean
    onClose: () => void
    onTemplateSelect?: (templateId: string) => void
    projectId?: string
    phaseId?: string
    onApplyTemplate?: (result: any) => void
}

interface TemplateItem {
    _id: string
    name: string
    description?: string
    category: string
    milestones: Array<{
        title: string
        durationDays: number
        priority: string
        estimatedBudget?: number
        estimatedHours?: number
    }> | null
    workflowConfig: {
        requiresApproval: boolean
        approvalStages: any[]
    } | null
    isPublic: boolean
    usageCount: number
    tags: string[] | null
    createdBy: {
        firstName: string
        lastName: string
    } | null
    departmentId?: {
        name: string
    } | null
    milestoneCount: number
    estimatedTotalDuration: number
    createdAt: string
}

interface ApplyTemplateForm {
    startDate: string
    adjustments: {
        milestones: Array<{
            originalTitle: string
            title?: string
            durationDays?: number
            priority?: string
        }>
    }
}

const CATEGORY_COLORS = {
    design: 'bg-purple-100 text-purple-800',
    development: 'bg-blue-100 text-blue-800',
    marketing: 'bg-green-100 text-green-800',
    hr: 'bg-orange-100 text-orange-800',
    finance: 'bg-yellow-100 text-yellow-800',
    operations: 'bg-gray-100 text-gray-800',
    generic: 'bg-indigo-100 text-indigo-800'
}

const CATEGORY_ICONS = {
    design: '🎨',
    development: '💻',
    marketing: '📢',
    hr: '👥',
    finance: '💰',
    operations: '⚙️',
    generic: '📋'
}

export function MilestoneTemplateGallery({
    isOpen,
    onClose,
    onTemplateSelect,
    projectId,
    phaseId,
    onApplyTemplate
}: MilestoneTemplateGalleryProps) {
    const { toast } = useToast()
    const [templates, setTemplates] = useState<TemplateItem[]>([])
    const [loading, setLoading] = useState(true)
    const [searchTerm, setSearchTerm] = useState('')
    const [selectedCategory, setSelectedCategory] = useState<string>('all')
    const [sortBy, setSortBy] = useState<string>('usage')
    const [showTemplateBuilder, setShowTemplateBuilder] = useState(false)
    const [selectedTemplate, setSelectedTemplate] = useState<TemplateItem | null>(null)
    const [templateBuilderMode, setTemplateBuilderMode] = useState<'create' | 'edit' | 'view'>('create')
    const [showApplyModal, setShowApplyModal] = useState(false)
    const [applyLoading, setApplyLoading] = useState(false)

    const [applyForm, setApplyForm] = useState<ApplyTemplateForm>({
        startDate: new Date().toISOString().split('T')[0],
        adjustments: { milestones: [] }
    })

    // Fetch templates
    const fetchTemplates = useCallback(async () => {
        try {
            setLoading(true)
            const params = new URLSearchParams()

            if (selectedCategory !== 'all') params.append('category', selectedCategory)
            if (searchTerm) params.append('search', searchTerm)

            const response = await fetch(`/api/milestone-templates?${params}`)
            const result = await response.json()

            if (!response.ok) {
                throw new Error(result.error || 'Failed to fetch templates')
            }

            setTemplates(result.data || [])
        } catch (error: any) {
            console.error('Error fetching templates:', error)
            toast({
                title: "Error",
                description: error.message || 'Failed to fetch milestone templates',
                variant: "destructive"
            })
        } finally {
            setLoading(false)
        }
    }, [searchTerm, selectedCategory, toast])

    useEffect(() => {
        if (isOpen) {
            fetchTemplates()
        }
    }, [isOpen, fetchTemplates])

    // Sort templates
    const sortedTemplates = React.useMemo(() => {
        return [...templates].sort((a, b) => {
            switch (sortBy) {
                case 'usage':
                    return b.usageCount - a.usageCount
                case 'newest':
                    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
                case 'name':
                    return a.name.localeCompare(b.name)
                case 'duration':
                    return (a.estimatedTotalDuration || 0) - (b.estimatedTotalDuration || 0)
                default:
                    return b.usageCount - a.usageCount
            }
        })
    }, [templates, sortBy])

    // Apply template
    const handleApplyTemplate = async (templateId: string) => {
        if (!projectId) {
            toast({
                title: "Error",
                description: "Project ID is required to apply template",
                variant: "destructive"
            })
            return
        }

        try {
            setApplyLoading(true)

            const response = await fetch(`/api/milestone-templates/${templateId}/apply`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    projectId,
                    phaseId,
                    startDate: applyForm.startDate,
                    adjustments: applyForm.adjustments
                })
            })

            // Check if response is JSON
            const contentType = response.headers.get('content-type')
            if (!contentType?.includes('application/json')) {
                const text = await response.text()
                throw new Error(`Server returned non-JSON response: ${response.status} ${response.statusText}`)
            }

            const result = await response.json()

            if (!response.ok) {
                throw new Error(result.error || 'Failed to apply template')
            }

            toast({
                title: "Template Applied",
                description: result.message || 'Milestone template applied successfully',
            })

            onApplyTemplate?.(result.data)
            setShowApplyModal(false)
            onClose()

        } catch (error: any) {
            console.error('Error applying template:', error)
            toast({
                title: "Error",
                description: error.message || 'Failed to apply template',
                variant: "destructive"
            })
        } finally {
            setApplyLoading(false)
        }
    }

    // Open apply modal
    const openApplyModal = (template: TemplateItem) => {
        setSelectedTemplate(template)
        setApplyForm({
            startDate: new Date().toISOString().split('T')[0],
            adjustments: {
                milestones: (template.milestones || []).map(m => ({
                    originalTitle: m.title,
                    title: m.title,
                    durationDays: m.durationDays,
                    priority: m.priority
                }))
            }
        })
        setShowApplyModal(true)
    }

    // Calculate template stats
    const getTemplateStats = (template: TemplateItem) => {
        const milestones = template.milestones || []
        const totalBudget = milestones.reduce((sum, m) => sum + (m.estimatedBudget || 0), 0)
        const totalHours = milestones.reduce((sum, m) => sum + (m.estimatedHours || 0), 0)
        const avgPriority = milestones.filter(m => m.priority === 'high' || m.priority === 'urgent').length

        return { totalBudget, totalHours, highPriorityCount: avgPriority }
    }

    return (
        <>
            <CustomModal
                isOpen={isOpen}
                onClose={onClose}
                title="Milestone Template Gallery"
                modalSize="xl"
            >

                <div className="flex-1 overflow-hidden">
                    <Tabs defaultValue="gallery" className="flex flex-col h-full">
                        <TabsList className="grid w-full grid-cols-2">
                            <TabsTrigger value="gallery">Browse Templates</TabsTrigger>
                            <TabsTrigger value="create">Create New Template</TabsTrigger>
                        </TabsList>

                        <TabsContent value="gallery" className="flex-1 overflow-hidden">
                            {/* Search and Filters */}
                            <div className="flex flex-col sm:flex-row gap-4 mb-6">
                                <div className="flex-1">
                                    <div className="relative">
                                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                                        <Input
                                            placeholder="Search templates..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                            className="pl-9"
                                        />
                                    </div>
                                </div>

                                <Select value={selectedCategory} onValueChange={setSelectedCategory}>
                                    <SelectTrigger className="w-48">
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="all">All Categories</SelectItem>
                                        <SelectItem value="design">Design</SelectItem>
                                        <SelectItem value="development">Development</SelectItem>
                                        <SelectItem value="marketing">Marketing</SelectItem>
                                        <SelectItem value="hr">HR</SelectItem>
                                        <SelectItem value="finance">Finance</SelectItem>
                                        <SelectItem value="operations">Operations</SelectItem>
                                        <SelectItem value="generic">Generic</SelectItem>
                                    </SelectContent>
                                </Select>

                                <Select value={sortBy} onValueChange={setSortBy}>
                                    <SelectTrigger className="w-48">
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="usage">Most Used</SelectItem>
                                        <SelectItem value="newest">Newest</SelectItem>
                                        <SelectItem value="name">Name A-Z</SelectItem>
                                        <SelectItem value="duration">Duration</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>

                            {/* Templates Grid */}
                            <div className="flex-1 overflow-auto">
                                {loading ? (
                                    <div className="flex items-center justify-center h-40">
                                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mr-2"></div>
                                        Loading templates...
                                    </div>
                                ) : sortedTemplates.length === 0 ? (
                                    <div className="text-center py-12">
                                        <BookTemplateIcon className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                                        <h3 className="text-lg font-medium mb-2">No Templates Found</h3>
                                        <p className="text-gray-600 mb-4">
                                            {templates.length === 0
                                                ? "No milestone templates have been created yet."
                                                : "No templates match your search criteria."
                                            }
                                        </p>
                                        <Button
                                            onClick={() => {
                                                setTemplateBuilderMode('create')
                                                setSelectedTemplate(null)
                                                setShowTemplateBuilder(true)
                                            }}
                                        >
                                            <Plus className="h-4 w-4 mr-2" />
                                            Create First Template
                                        </Button>
                                    </div>
                                ) : (
                                    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
                                        {sortedTemplates.map((template) => {
                                            const stats = getTemplateStats(template)
                                            return (
                                                <Card key={template._id} className="hover:shadow-lg transition-shadow">
                                                    <CardHeader className="pb-3">
                                                        <div className="flex items-start justify-between">
                                                            <div className="flex-1">
                                                                <div className="flex items-center gap-2 mb-2">
                                                                    <span className="text-lg">{CATEGORY_ICONS[template.category as keyof typeof CATEGORY_ICONS]}</span>
                                                                    <CardTitle className="text-lg leading-tight">{template.name}</CardTitle>
                                                                </div>

                                                                <div className="flex items-center gap-2 mb-3">
                                                                    <Badge className={CATEGORY_COLORS[template.category as keyof typeof CATEGORY_COLORS]}>
                                                                        {template.category}
                                                                    </Badge>
                                                                    {template.isPublic && (
                                                                        <Badge variant="outline">Public</Badge>
                                                                    )}
                                                                    {template.workflowConfig?.requiresApproval && (
                                                                        <Badge variant="secondary" className="flex items-center gap-1">
                                                                            <Workflow className="h-3 w-3" />
                                                                            Approval
                                                                        </Badge>
                                                                    )}
                                                                </div>
                                                            </div>

                                                            <div className="flex items-center gap-1 text-sm text-gray-500">
                                                                <TrendingUp className="h-4 w-4" />
                                                                {template.usageCount}
                                                            </div>
                                                        </div>

                                                        {template.description && (
                                                            <p className="text-sm text-gray-600 mb-3 line-clamp-2">
                                                                {template.description}
                                                            </p>
                                                        )}

                                                        {/* Template Stats */}
                                                        <div className="grid grid-cols-3 gap-3 text-center">
                                                            <div>
                                                                <div className="font-semibold text-blue-600">{template.milestoneCount}</div>
                                                                <div className="text-xs text-gray-600">Milestones</div>
                                                            </div>
                                                            <div>
                                                                <div className="font-semibold text-green-600">{template.estimatedTotalDuration}</div>
                                                                <div className="text-xs text-gray-600">Days</div>
                                                            </div>
                                                            <div>
                                                                <div className="font-semibold text-orange-600">{stats.highPriorityCount}</div>
                                                                <div className="text-xs text-gray-600">High Priority</div>
                                                            </div>
                                                        </div>
                                                    </CardHeader>

                                                    <CardContent className="pt-0">
                                                        {/* Tags */}
                                                        {template.tags && template.tags.length > 0 && (
                                                            <div className="flex flex-wrap gap-1 mb-4">
                                                                {template.tags.slice(0, 3).map((tag, index) => (
                                                                    <Badge key={index} variant="outline" className="text-xs">
                                                                        {tag}
                                                                    </Badge>
                                                                ))}
                                                                {template.tags.length > 3 && (
                                                                    <Badge variant="outline" className="text-xs">
                                                                        +{template.tags.length - 3} more
                                                                    </Badge>
                                                                )}
                                                            </div>
                                                        )}

                                                        {/* Creator Info */}
                                                        <div className="text-xs text-gray-500 mb-4">
                                                            Created by {template.createdBy?.firstName || 'Unknown'} {template.createdBy?.lastName || 'User'}
                                                            {template.departmentId?.name && ` • ${template.departmentId.name}`}
                                                        </div>

                                                        {/* Action Buttons */}
                                                        <div className="flex gap-2">
                                                            <Button
                                                                size="sm"
                                                                onClick={() => openApplyModal(template)}
                                                                className="flex-1"
                                                                disabled={!projectId}
                                                            >
                                                                <Rocket className="h-4 w-4 mr-2" />
                                                                Use Template
                                                            </Button>
                                                            <Button
                                                                variant="outline"
                                                                size="sm"
                                                                onClick={() => {
                                                                    setSelectedTemplate(template)
                                                                    setTemplateBuilderMode('view')
                                                                    setShowTemplateBuilder(true)
                                                                }}
                                                            >
                                                                <Eye className="h-4 w-4" />
                                                            </Button>
                                                        </div>
                                                    </CardContent>
                                                </Card>
                                            )
                                        })}
                                    </div>
                                )}
                            </div>
                        </TabsContent>

                        <TabsContent value="create" className="flex-1">
                            <div className="flex items-center justify-center h-full">
                                <div className="text-center">
                                    <BookTemplateIcon className="h-16 w-16 mx-auto mb-4 text-gray-400" />
                                    <h3 className="text-lg font-medium mb-2">Create New Template</h3>
                                    <p className="text-gray-600 mb-6">
                                        Build a reusable milestone template for your team
                                    </p>
                                    <Button
                                        onClick={() => {
                                            setTemplateBuilderMode('create')
                                            setSelectedTemplate(null)
                                            setShowTemplateBuilder(true)
                                        }}
                                        size="lg"
                                    >
                                        <Plus className="h-5 w-5 mr-2" />
                                        Create Template
                                    </Button>
                                </div>
                            </div>
                        </TabsContent>
                    </Tabs>
                </div>
            </CustomModal>
            <MilestoneTemplateBuilder
                isOpen={showTemplateBuilder}
                onClose={() => setShowTemplateBuilder(false)}
                template={(() => {
                    if (!selectedTemplate) return undefined;

                    const milestones = selectedTemplate.milestones || [];
                    const workflowConfig = selectedTemplate.workflowConfig || {
                        requiresApproval: false,
                        approvalStages: []
                    };

                    return {
                        _id: selectedTemplate._id,
                        name: selectedTemplate.name,
                        description: selectedTemplate.description,
                        category: selectedTemplate.category as any,
                        milestones: milestones.map(m => ({
                            title: m.title,
                            durationDays: m.durationDays,
                            priority: m.priority as any,
                            deliverables: [],
                            successCriteria: [],
                            dependencies: [],
                            requiredApprovals: [],
                            estimatedBudget: m.estimatedBudget,
                            estimatedHours: m.estimatedHours
                        })),
                        workflowConfig: {
                            requiresApproval: workflowConfig.requiresApproval,
                            approvalStages: workflowConfig.approvalStages || [],
                            autoProgressRules: []
                        },
                        isPublic: selectedTemplate.isPublic,
                        tags: selectedTemplate.tags || []
                    };
                })()}
                mode={templateBuilderMode}
                onSave={() => {
                    fetchTemplates()
                    setShowTemplateBuilder(false)
                }}
            />

            {/* Apply Template Modal */}
            <CustomModal
                isOpen={showApplyModal}
                onClose={() => setShowApplyModal(false)}
                title={`Apply Template: ${selectedTemplate?.name}`}
                modalSize="lg"
            >

                {selectedTemplate && (
                    <div className="space-y-6">
                        {/* Template Info */}
                        <div className="bg-gray-50 p-4 rounded-lg">
                            <h4 className="font-medium mb-2">Template Overview</h4>
                            <div className="grid grid-cols-3 gap-4 text-sm">
                                <div className="text-center">
                                    <div className="font-semibold text-lg">{selectedTemplate.milestoneCount}</div>
                                    <div className="text-gray-600">Milestones</div>
                                </div>
                                <div className="text-center">
                                    <div className="font-semibold text-lg">{selectedTemplate.estimatedTotalDuration}</div>
                                    <div className="text-gray-600">Days</div>
                                </div>
                                <div className="text-center">
                                    <div className="font-semibold text-lg">
                                        {selectedTemplate.workflowConfig?.approvalStages?.length || 0}
                                    </div>
                                    <div className="text-gray-600">Approval Stages</div>
                                </div>
                            </div>
                        </div>

                        {/* Configuration */}
                        <div className="space-y-4">
                            <div>
                                <Label>Start Date</Label>
                                <Input
                                    type="date"
                                    value={applyForm.startDate}
                                    onChange={(e) => setApplyForm(prev => ({
                                        ...prev,
                                        startDate: e.target.value
                                    }))}
                                />
                            </div>

                            {/* Milestone Adjustments */}
                            <div>
                                <Label>Milestone Adjustments (Optional)</Label>
                                <div className="space-y-3 max-h-60 overflow-y-auto">
                                    {applyForm.adjustments.milestones.map((milestone, index) => (
                                        <Card key={index} className="p-3">
                                            <div className="grid grid-cols-2 gap-3">
                                                <div>
                                                    <Label className="text-sm">Title</Label>
                                                    <Input
                                                        value={milestone.title || milestone.originalTitle}
                                                        onChange={(e) => {
                                                            const newAdjustments = [...applyForm.adjustments.milestones]
                                                            newAdjustments[index] = {
                                                                ...newAdjustments[index],
                                                                title: e.target.value
                                                            }
                                                            setApplyForm(prev => ({
                                                                ...prev,
                                                                adjustments: { milestones: newAdjustments }
                                                            }))
                                                        }}
                                                        className="text-sm"
                                                    />
                                                </div>
                                                <div>
                                                    <Label className="text-sm">Duration (Days)</Label>
                                                    <Input
                                                        type="number"
                                                        min="1"
                                                        value={milestone.durationDays}
                                                        onChange={(e) => {
                                                            const newAdjustments = [...applyForm.adjustments.milestones]
                                                            newAdjustments[index] = {
                                                                ...newAdjustments[index],
                                                                durationDays: parseInt(e.target.value) || 1
                                                            }
                                                            setApplyForm(prev => ({
                                                                ...prev,
                                                                adjustments: { milestones: newAdjustments }
                                                            }))
                                                        }}
                                                        className="text-sm"
                                                    />
                                                </div>
                                            </div>
                                        </Card>
                                    ))}
                                </div>
                            </div>
                        </div>

                        <div className="flex justify-end gap-2">
                            <Button
                                variant="outline"
                                onClick={() => setShowApplyModal(false)}
                            >
                                Cancel
                            </Button>
                            <Button
                                onClick={() => handleApplyTemplate(selectedTemplate._id)}
                                disabled={applyLoading}
                            >
                                {applyLoading ? (
                                    <>
                                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                                        Applying...
                                    </>
                                ) : (
                                    <>
                                        <CheckCircle className="h-4 w-4 mr-2" />
                                        Apply Template
                                    </>
                                )}
                            </Button>
                        </div>
                    </div>
                )}
            </CustomModal>
        </>
    )
}

export default MilestoneTemplateGallery