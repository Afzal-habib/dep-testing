"use client"

import React, { useState, useCallback, useEffect } from 'react'
import { useForm } from 'react-hook-form'
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useToast } from '@/hooks/use-toast'
import { 
  CheckCircle, 
  XCircle, 
  Clock, 
  AlertTriangle,
  User,
  Calendar,
  MessageSquare,
  Send,
  UserCheck,
  Users,
  ArrowRight,
  FileText,
  Target,
  Workflow,
  Timer,
  TrendingUp,
  Filter,
  Search,
  Eye
} from 'lucide-react'

const approvalActionSchema = z.object({
  action: z.enum(['approve', 'reject', 'delegate']),
  comments: z.string().max(1000).optional(),
  delegateToUserId: z.string().optional()
})

type ApprovalActionFormData = z.infer<typeof approvalActionSchema>

interface MilestoneApprovalManagerProps {
  projectId?: string
  milestoneId?: string
  userId?: string
  onApprovalUpdate?: () => void
}

interface ApprovalRecord {
  _id: string
  milestoneId: {
    _id: string
    title: string
    description?: string
    priority: string
    dueDate: string
  }
  projectId: {
    _id: string
    title: string
    client?: string
  }
  currentStage: string
  stages: Array<{
    stageName: string
    requiredRoles: string[]
    approvals: Array<{
      userId: {
        _id: string
        firstName: string
        lastName: string
        email: string
        role: string
      }
      userRole: string
      status: 'pending' | 'approved' | 'rejected' | 'delegated'
      comments?: string
      approvedAt?: string
      delegatedTo?: {
        _id: string
        firstName: string
        lastName: string
      }
    }>
    stageStatus: 'pending' | 'in-review' | 'approved' | 'rejected'
    completedAt?: string
    isOptional: boolean
    order: number
  }>
  overallStatus: 'pending' | 'in-review' | 'approved' | 'rejected' | 'cancelled'
  submittedBy: {
    _id: string
    firstName: string
    lastName: string
    email: string
  }
  submittedAt: string
  completionDeadline?: string
  submissionComments?: string
  rejectionReason?: string
  isOverdue?: boolean
}

export function MilestoneApprovalManager({ 
  projectId, 
  milestoneId, 
  userId, 
  onApprovalUpdate 
}: MilestoneApprovalManagerProps) {
  const { toast } = useToast()
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [selectedApproval, setSelectedApproval] = useState<ApprovalRecord | null>(null)
  const [showApprovalModal, setShowApprovalModal] = useState(false)
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [searchTerm, setSearchTerm] = useState('')
  
  const form = useForm<ApprovalActionFormData>({
    resolver: zodResolver(approvalActionSchema),
    defaultValues: {
      action: 'approve',
      comments: '',
      delegateToUserId: ''
    }
  })

  // Fetch approvals
  const fetchApprovals = useCallback(async () => {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      
      if (projectId) params.append('projectId', projectId)
      if (milestoneId) params.append('milestoneId', milestoneId)
      if (userId) params.append('assignedToMe', 'true')
      
      const response = await fetch(`/api/milestone-approvals?${params}`)
      const result = await response.json()
      
      if (!response.ok) {
        throw new Error(result.error || 'Failed to fetch approvals')
      }
      
      setApprovals(result.data || [])
    } catch (error: any) {
      console.error('Error fetching approvals:', error)
      toast({
        title: "Error",
        description: error.message || 'Failed to fetch milestone approvals',
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }, [projectId, milestoneId, userId, toast])

  useEffect(() => {
    fetchApprovals()
  }, [fetchApprovals])

  // Process approval action
  const handleApprovalAction = async (approvalId: string, data: ApprovalActionFormData) => {
    try {
      setActionLoading(approvalId)
      
      const response = await fetch('/api/milestone-approvals', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          approvalId,
          action: data.action,
          comments: data.comments,
          delegateToUserId: data.delegateToUserId
        })
      })

      const result = await response.json()

      if (!response.ok) {
        throw new Error(result.error || 'Failed to process approval')
      }

      toast({
        title: "Approval Processed",
        description: `Milestone approval ${data.action} processed successfully.`,
      })

      // Refresh approvals
      await fetchApprovals()
      onApprovalUpdate?.()
      
      // Close modal and reset form
      setShowApprovalModal(false)
      setSelectedApproval(null)
      form.reset()

    } catch (error: any) {
      console.error('Error processing approval:', error)
      toast({
        title: "Error",
        description: error.message || 'Failed to process approval',
        variant: "destructive"
      })
    } finally {
      setActionLoading(null)
    }
  }

  // Open approval action modal
  const openApprovalModal = (approval: ApprovalRecord) => {
    setSelectedApproval(approval)
    setShowApprovalModal(true)
    form.reset({ action: 'approve', comments: '' })
  }

  // Filter and search approvals
  const filteredApprovals = approvals.filter(approval => {
    const matchesStatus = filterStatus === 'all' || approval.overallStatus === filterStatus
    const matchesSearch = !searchTerm || 
      approval.milestoneId.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      approval.projectId.title.toLowerCase().includes(searchTerm.toLowerCase())
    
    return matchesStatus && matchesSearch
  })

  // Get status color
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'approved': return 'bg-green-100 text-green-800'
      case 'rejected': return 'bg-red-100 text-red-800'
      case 'in-review': return 'bg-blue-100 text-blue-800'
      case 'pending': return 'bg-yellow-100 text-yellow-800'
      case 'cancelled': return 'bg-gray-100 text-gray-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  // Get user's pending approval in current stage
  const getUserPendingApproval = (approval: ApprovalRecord, userId: string) => {
    const currentStage = approval.stages.find(stage => stage.stageName === approval.currentStage)
    if (!currentStage) return null
    
    return currentStage.approvals.find(
      app => app.userId._id === userId && app.status === 'pending'
    )
  }

  if (loading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mr-2"></div>
            Loading milestone approvals...
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header with filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Workflow className="h-5 w-5" />
            Milestone Approvals
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search milestones or projects..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-9"
                />
              </div>
            </div>
            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="in-review">In Review</SelectItem>
                <SelectItem value="approved">Approved</SelectItem>
                <SelectItem value="rejected">Rejected</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Approvals List */}
      {filteredApprovals.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center">
            <Workflow className="h-12 w-12 mx-auto mb-4 text-gray-400" />
            <h3 className="text-lg font-medium mb-2">No Milestone Approvals</h3>
            <p className="text-gray-600">
              {approvals.length === 0 
                ? "No milestone approvals have been submitted yet."
                : "No approvals match your current filters."
              }
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {filteredApprovals.map((approval) => {
            const userPendingApproval = userId ? getUserPendingApproval(approval, userId) : null
            const currentStage = approval.stages.find(stage => stage.stageName === approval.currentStage)
            const isOverdue = approval.completionDeadline && 
              new Date(approval.completionDeadline) < new Date() && 
              !['approved', 'rejected', 'cancelled'].includes(approval.overallStatus)

            return (
              <Card key={approval._id} className={`transition-shadow hover:shadow-md ${isOverdue ? 'border-red-200' : ''}`}>
                <CardContent className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-lg font-semibold">{approval.milestoneId.title}</h3>
                        <Badge className={getStatusColor(approval.overallStatus)}>
                          {approval.overallStatus.replace('-', ' ')}
                        </Badge>
                        {isOverdue && (
                          <Badge variant="destructive" className="flex items-center gap-1">
                            <Timer className="h-3 w-3" />
                            Overdue
                          </Badge>
                        )}
                      </div>
                      
                      <div className="flex items-center gap-4 text-sm text-gray-600 mb-3">
                        <span className="flex items-center gap-1">
                          <Target className="h-4 w-4" />
                          {approval.projectId.title}
                        </span>
                        <span className="flex items-center gap-1">
                          <User className="h-4 w-4" />
                          {approval.submittedBy.firstName} {approval.submittedBy.lastName}
                        </span>
                        <span className="flex items-center gap-1">
                          <Calendar className="h-4 w-4" />
                          {new Date(approval.submittedAt).toLocaleDateString()}
                        </span>
                        {approval.completionDeadline && (
                          <span className={`flex items-center gap-1 ${isOverdue ? 'text-red-600' : ''}`}>
                            <Clock className="h-4 w-4" />
                            Due: {new Date(approval.completionDeadline).toLocaleDateString()}
                          </span>
                        )}
                      </div>

                      {approval.milestoneId.description && (
                        <p className="text-gray-700 mb-4">{approval.milestoneId.description}</p>
                      )}

                      {approval.submissionComments && (
                        <div className="bg-gray-50 p-3 rounded-lg mb-4">
                          <div className="flex items-center gap-2 mb-1">
                            <MessageSquare className="h-4 w-4 text-gray-500" />
                            <span className="font-medium text-sm">Submission Comments</span>
                          </div>
                          <p className="text-sm text-gray-700">{approval.submissionComments}</p>
                        </div>
                      )}

                      {/* Current Stage Progress */}
                      {currentStage && (
                        <div className="mb-4">
                          <div className="flex items-center gap-2 mb-2">
                            <Workflow className="h-4 w-4" />
                            <span className="font-medium">Current Stage: {currentStage.stageName}</span>
                            <Badge variant={currentStage.stageStatus === 'approved' ? 'default' : 'secondary'}>
                              {currentStage.stageStatus}
                            </Badge>
                          </div>
                          
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                            {currentStage.approvals.map((approvalItem, index) => (
                              <div key={index} className="flex items-center gap-3 p-2 bg-gray-50 rounded">
                                <Avatar className="h-8 w-8">
                                  <AvatarFallback>
                                    {approvalItem.userId.firstName[0]}{approvalItem.userId.lastName[0]}
                                  </AvatarFallback>
                                </Avatar>
                                <div className="flex-1 min-w-0">
                                  <div className="font-medium text-sm truncate">
                                    {approvalItem.userId.firstName} {approvalItem.userId.lastName}
                                  </div>
                                  <div className="text-xs text-gray-500">{approvalItem.userRole}</div>
                                </div>
                                <div className="flex items-center gap-1">
                                  {approvalItem.status === 'approved' && <CheckCircle className="h-4 w-4 text-green-600" />}
                                  {approvalItem.status === 'rejected' && <XCircle className="h-4 w-4 text-red-600" />}
                                  {approvalItem.status === 'pending' && <Clock className="h-4 w-4 text-yellow-600" />}
                                  {approvalItem.status === 'delegated' && <ArrowRight className="h-4 w-4 text-blue-600" />}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Approval Stages Timeline */}
                      <div className="mb-4">
                        <h4 className="font-medium mb-2">Approval Timeline</h4>
                        <div className="flex items-center gap-2 overflow-x-auto pb-2">
                          {approval.stages
                            .sort((a, b) => a.order - b.order)
                            .map((stage, index) => (
                              <React.Fragment key={stage.order}>
                                <div className={`flex items-center gap-2 px-3 py-2 rounded-lg whitespace-nowrap ${
                                  stage.stageName === approval.currentStage 
                                    ? 'bg-blue-100 text-blue-800 border-2 border-blue-300'
                                    : stage.stageStatus === 'approved'
                                    ? 'bg-green-100 text-green-800'
                                    : stage.stageStatus === 'rejected'
                                    ? 'bg-red-100 text-red-800'
                                    : 'bg-gray-100 text-gray-600'
                                }`}>
                                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-medium ${
                                    stage.stageStatus === 'approved' ? 'bg-green-600 text-white' :
                                    stage.stageStatus === 'rejected' ? 'bg-red-600 text-white' :
                                    stage.stageName === approval.currentStage ? 'bg-blue-600 text-white' :
                                    'bg-gray-400 text-white'
                                  }`}>
                                    {stage.stageStatus === 'approved' ? <CheckCircle className="h-3 w-3" /> :
                                     stage.stageStatus === 'rejected' ? <XCircle className="h-3 w-3" /> :
                                     stage.order + 1}
                                  </div>
                                  <span className="text-sm">{stage.stageName}</span>
                                  {stage.isOptional && <Badge variant="outline" className="text-xs">Optional</Badge>}
                                </div>
                                {index < approval.stages.length - 1 && (
                                  <ArrowRight className="h-4 w-4 text-gray-400 flex-shrink-0" />
                                )}
                              </React.Fragment>
                            ))}
                        </div>
                      </div>

                      {approval.rejectionReason && (
                        <div className="bg-red-50 p-3 rounded-lg border border-red-200">
                          <div className="flex items-center gap-2 mb-1">
                            <XCircle className="h-4 w-4 text-red-600" />
                            <span className="font-medium text-sm text-red-800">Rejection Reason</span>
                          </div>
                          <p className="text-sm text-red-700">{approval.rejectionReason}</p>
                        </div>
                      )}
                    </div>

                    <div className="flex flex-col gap-2 ml-4">
                      {userPendingApproval && (
                        <Button
                          onClick={() => openApprovalModal(approval)}
                          disabled={actionLoading === approval._id}
                          className="whitespace-nowrap"
                        >
                          <UserCheck className="h-4 w-4 mr-2" />
                          Review
                        </Button>
                      )}
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setSelectedApproval(approval)
                          setShowApprovalModal(true)
                          form.setValue('action', 'approve')
                        }}
                      >
                        <Eye className="h-4 w-4 mr-2" />
                        View Details
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}

      {/* Approval Action Modal */}
    <CustomModal
      isOpen={showApprovalModal}
      onClose={() => setShowApprovalModal(false)}
      title={selectedApproval ? `Review: ${selectedApproval.milestoneId.title}` : 'Approval Details'}
      modalSize="lg"
    >

          {selectedApproval && (
            <form onSubmit={form.handleSubmit((data) => handleApprovalAction(selectedApproval._id, data))}>
              <div className="space-y-6">
                {/* Milestone Info */}
                <div className="bg-gray-50 p-4 rounded-lg">
                  <h4 className="font-medium mb-2">Milestone Information</h4>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-600">Project:</span>
                      <div className="font-medium">{selectedApproval.projectId.title}</div>
                    </div>
                    <div>
                      <span className="text-gray-600">Priority:</span>
                      <Badge className="ml-2">{selectedApproval.milestoneId.priority}</Badge>
                    </div>
                    <div>
                      <span className="text-gray-600">Due Date:</span>
                      <div className="font-medium">
                        {new Date(selectedApproval.milestoneId.dueDate).toLocaleDateString()}
                      </div>
                    </div>
                    <div>
                      <span className="text-gray-600">Submitted By:</span>
                      <div className="font-medium">
                        {selectedApproval.submittedBy.firstName} {selectedApproval.submittedBy.lastName}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Approval Action Form */}
                {userId && getUserPendingApproval(selectedApproval, userId) && (
                  <>
                    <div>
                      <Label>Action</Label>
                      <Select
                        value={form.watch('action')}
                        onValueChange={(value) => form.setValue('action', value as any)}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="approve">Approve</SelectItem>
                          <SelectItem value="reject">Reject</SelectItem>
                          <SelectItem value="delegate">Delegate</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label>Comments</Label>
                      <Textarea
                        {...form.register('comments')}
                        placeholder="Add your comments (optional)..."
                        rows={3}
                      />
                    </div>

                    {form.watch('action') === 'delegate' && (
                      <div>
                        <Label>Delegate To</Label>
                        <Input
                          {...form.register('delegateToUserId')}
                          placeholder="Enter user ID to delegate to..."
                        />
                      </div>
                    )}
                  </>
                )}

                {/* Previous Comments */}
                <div>
                  <h4 className="font-medium mb-3">Approval History</h4>
                  <ScrollArea className="h-40">
                    <div className="space-y-3">
                      {selectedApproval.stages.map((stage) => 
                        stage.approvals
                          .filter(app => app.comments)
                          .map((approval, index) => (
                            <div key={index} className="border-l-2 border-gray-200 pl-4">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="font-medium text-sm">
                                  {approval.userId.firstName} {approval.userId.lastName}
                                </span>
                                <Badge variant={approval.status === 'approved' ? 'default' : 
                                             approval.status === 'rejected' ? 'destructive' : 'secondary'}>
                                  {approval.status}
                                </Badge>
                                {approval.approvedAt && (
                                  <span className="text-xs text-gray-500">
                                    {new Date(approval.approvedAt).toLocaleString()}
                                  </span>
                                )}
                              </div>
                              {approval.comments && (
                                <p className="text-sm text-gray-700">{approval.comments}</p>
                              )}
                            </div>
                          ))
                      )}
                    </div>
                  </ScrollArea>
                </div>
              </div>

              <div className="flex justify-end gap-2 mt-6">
                <Button 
                  type="button" 
                  variant="outline" 
                  onClick={() => setShowApprovalModal(false)}
                >
                  Close
                </Button>
                {userId && getUserPendingApproval(selectedApproval, userId) && (
                  <Button 
                    type="submit" 
                    disabled={actionLoading === selectedApproval._id}
                  >
                    {actionLoading === selectedApproval._id ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                        Processing...
                      </>
                    ) : (
                      <>
                        <Send className="h-4 w-4 mr-2" />
                        Submit {form.watch('action')}
                      </>
                    )}
                  </Button>
                )}
              </div>
            </form>
          )}
      </CustomModal>
    </div>
  )
}

export default MilestoneApprovalManager