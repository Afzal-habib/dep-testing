"use client"

import { useState, useEffect } from 'react'
import CustomModal from '@/components/shared/custom-modal'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Loader2, Users, Building, FolderKanban, UserCheck, Hash, Check, RefreshCw, UserPlus, MessageSquareOff, UserCog } from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import { useDepartments } from "@/hooks/use-departments";
import { useProjects } from "@/hooks/use-projects";
import { useUsers } from "@/hooks/use-users";
import { useClients } from '@/hooks/use-clients'
import { communicationLogger as logger } from "@/lib/logger"

type ChannelType = 'group' | 'department' | 'department-category' | 'multi-category' | 'project' | 'client-support' | 'dm'
type DepartmentCategory = 'sales' | 'support' | 'it' | 'management'

interface CreateChannelModalProps {
  isOpen: boolean
  onClose: () => void
  onChannelCreated?: (channel: any) => void
  onChannelCreatedRaw?: (channel: any) => Promise<void> // Alternative callback for parent to add to store
}

export function CreateChannelModal({
  isOpen,
  onClose,
  onChannelCreated,
  onChannelCreatedRaw,
}: CreateChannelModalProps) {
  const [channelType, setChannelType] = useState<ChannelType>('group')
  const [channelName, setChannelName] = useState('')
  const [isPrivate, setIsPrivate] = useState(true)
  const [selectedDepartment, setSelectedDepartment] = useState('')
  const [selectedCategory, setSelectedCategory] = useState<DepartmentCategory>('sales')
  const [selectedCategories, setSelectedCategories] = useState<DepartmentCategory[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [selectedClient, setSelectedClient] = useState('')
  const [selectedMembers, setSelectedMembers] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const { toast } = useToast()

  // Channel settings
  const [autoSyncEnabled, setAutoSyncEnabled] = useState(true)
  const [allowExternalMembers, setAllowExternalMembers] = useState(false)
  const [adminOnlyPost, setAdminOnlyPost] = useState(false)
  const [adminOnlyAdd, setAdminOnlyAdd] = useState(false)

  // Use standard hooks for data
  const { allDepartments } = useDepartments();
  const { projects } = useProjects();
  const { users } = useUsers();
  const { clients } = useClients();

  const categories: DepartmentCategory[] = ['sales', 'support', 'it', 'management']

  const clientUsers = clients
  const regularUsers = users.filter(u => u.isClient !== true)

  const handleCategoryToggle = (category: DepartmentCategory) => {
    setSelectedCategories(prev =>
      prev.includes(category)
        ? prev.filter(c => c !== category)
        : [...prev, category]
    )
  }

  const handleMemberToggle = (userId: string) => {
    setSelectedMembers(prev =>
      prev.includes(userId)
        ? prev.filter(id => id !== userId)
        : [...prev, userId]
    )
  }

  const handleCreateChannel = async () => {
    try {
      setLoading(true)

      // Validation
      if (!channelType) {
        toast({ title: 'Error', description: 'Please select a channel type', variant: 'destructive' })
        return
      }

      const payload: any = {
        type: channelType,
        name: channelName || undefined,
        is_private: isPrivate,
        auto_sync_enabled: autoSyncEnabled,
        allow_external_members: allowExternalMembers,
        admin_only_post: adminOnlyPost,
        admin_only_add: adminOnlyAdd
      }

      // Add type-specific fields
      switch (channelType) {
        case 'group':
          if (selectedMembers.length === 0) {
            toast({ title: 'Error', description: 'Please select at least one member', variant: 'destructive' })
            return
          }
          payload.channel_members = selectedMembers
          break

        case 'department':
          if (!selectedDepartment) {
            toast({ title: 'Error', description: 'Please select a department', variant: 'destructive' })
            return
          }
          payload.mongo_department_id = selectedDepartment
          break

        case 'department-category':
          payload.category = selectedCategory
          break

        case 'multi-category':
          if (selectedCategories.length === 0) {
            toast({ title: 'Error', description: 'Please select at least one category', variant: 'destructive' })
            return
          }
          payload.categories = selectedCategories
          break

        case 'project':
          if (!selectedProject) {
            toast({ title: 'Error', description: 'Please select a project', variant: 'destructive' })
            return
          }
          payload.mongo_project_id = selectedProject
          break

        case 'client-support':
          if (!selectedClient) {
            toast({ title: 'Error', description: 'Please select a client', variant: 'destructive' })
            return
          }
          payload.client_id = selectedClient
          break
      }

      // Call API
      logger.debug('Creating channel with payload:', payload)
      const response = await fetch('/api/communication/channels', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Failed to create channel')
      }

      const data = await response.json()
      logger.debug('Channel created successfully:', data.data?.id)

      if (!data.success || !data.data) {
        throw new Error(data.error || 'Failed to create channel - invalid response')
      }

      toast({
        title: 'Success',
        description: data.message || 'Channel created successfully'
      })

      // Call raw callback first (to add to Redux store immediately - optimistic update)
      if (onChannelCreatedRaw) {
        try {
          await onChannelCreatedRaw(data.data)
          logger.debug('Channel added to Redux store via callback')
        } catch (storeError) {
          logger.warn('Failed to add channel to store:', storeError)
        }
      }

      // Call callback with the created channel data
      // The channel will be available in Redux store via:
      // 1. Optimistic update from onChannelCreatedRaw (immediate)
      // 2. OR realtime update via onChannelUpdate handler (backup)
      logger.debug('Calling onChannelCreated callback:', data.data.id)
      onChannelCreated?.(data.data)
      onClose()

      // Reset form
      setChannelName('')
      setIsPrivate(true)
      setSelectedDepartment('')
      setSelectedCategory('sales')
      setSelectedCategories([])
      setSelectedProject('')
      setSelectedClient('')
      setSelectedMembers([])
      setAutoSyncEnabled(true)
      setAllowExternalMembers(false)
      setAdminOnlyPost(false)
      setAdminOnlyAdd(false)

    } catch (error: any) {
      logger.error('Error creating channel:', error)
      toast({
        title: 'Error',
        description: error.message || 'Failed to create channel',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <CustomModal
      isOpen={isOpen}
      onClose={onClose}
      title="Create New Channel"
      modalSize="xl"
      actions={
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button onClick={handleCreateChannel} disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Create Channel
          </Button>
        </div>
      }
    >
      <div className="space-y-6">
        {/* Channel Type Selection */}
        <div className="space-y-3">
          <Label>Channel Type</Label>
          <div className="space-y-2">
            <div
              className={cn(
                "flex items-center gap-3 p-3 border rounded-lg cursor-pointer transition-colors",
                channelType === 'group' ? "bg-primary/10 border-primary" : "hover:bg-accent"
              )}
              onClick={() => setChannelType('group')}
            >
              <div className={cn(
                "w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0",
                channelType === 'group' ? "border-primary" : "border-muted-foreground"
              )}>
                {channelType === 'group' && <div className="w-3 h-3 rounded-full bg-primary" />}
              </div>
              <Users className="h-4 w-4 shrink-0" />
              <span className="font-normal text-sm">Group Channel - Select specific members</span>
            </div>

            <div
              className={cn(
                "flex items-center gap-3 p-3 border rounded-lg cursor-pointer transition-colors",
                channelType === 'department' ? "bg-primary/10 border-primary" : "hover:bg-accent"
              )}
              onClick={() => setChannelType('department')}
            >
              <div className={cn(
                "w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0",
                channelType === 'department' ? "border-primary" : "border-muted-foreground"
              )}>
                {channelType === 'department' && <div className="w-3 h-3 rounded-full bg-primary" />}
              </div>
              <Building className="h-4 w-4 shrink-0" />
              <span className="font-normal text-sm">Department Channel - All users in a department</span>
            </div>

            <div
              className={cn(
                "flex items-center gap-3 p-3 border rounded-lg cursor-pointer transition-colors",
                channelType === 'department-category' ? "bg-primary/10 border-primary" : "hover:bg-accent"
              )}
              onClick={() => setChannelType('department-category')}
            >
              <div className={cn(
                "w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0",
                channelType === 'department-category' ? "border-primary" : "border-muted-foreground"
              )}>
                {channelType === 'department-category' && <div className="w-3 h-3 rounded-full bg-primary" />}
              </div>
              <Hash className="h-4 w-4 shrink-0" />
              <span className="font-normal text-sm">Category Channel - All users with same category</span>
            </div>

            <div
              className={cn(
                "flex items-center gap-3 p-3 border rounded-lg cursor-pointer transition-colors",
                channelType === 'multi-category' ? "bg-primary/10 border-primary" : "hover:bg-accent"
              )}
              onClick={() => setChannelType('multi-category')}
            >
              <div className={cn(
                "w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0",
                channelType === 'multi-category' ? "border-primary" : "border-muted-foreground"
              )}>
                {channelType === 'multi-category' && <div className="w-3 h-3 rounded-full bg-primary" />}
              </div>
              <Hash className="h-4 w-4 shrink-0" />
              <span className="font-normal text-sm">Multi-Category Channel - Users from multiple categories</span>
            </div>

            <div
              className={cn(
                "flex items-center gap-3 p-3 border rounded-lg cursor-pointer transition-colors",
                channelType === 'project' ? "bg-primary/10 border-primary" : "hover:bg-accent"
              )}
              onClick={() => setChannelType('project')}
            >
              <div className={cn(
                "w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0",
                channelType === 'project' ? "border-primary" : "border-muted-foreground"
              )}>
                {channelType === 'project' && <div className="w-3 h-3 rounded-full bg-primary" />}
              </div>
              <FolderKanban className="h-4 w-4 shrink-0" />
              <span className="font-normal text-sm">Project Channel - All project collaborators</span>
            </div>

            <div
              className={cn(
                "flex items-center gap-3 p-3 border rounded-lg cursor-pointer transition-colors",
                channelType === 'client-support' ? "bg-primary/10 border-primary" : "hover:bg-accent"
              )}
              onClick={() => setChannelType('client-support')}
            >
              <div className={cn(
                "w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0",
                channelType === 'client-support' ? "border-primary" : "border-muted-foreground"
              )}>
                {channelType === 'client-support' && <div className="w-3 h-3 rounded-full bg-primary" />}
              </div>
              <UserCheck className="h-4 w-4 shrink-0" />
              <span className="font-normal text-sm">Client Support - Client + support team</span>
            </div>
          </div>
        </div>

        {/* Channel Name */}
        <div className="space-y-2">
          <Label htmlFor="name">Channel Name (Optional)</Label>
          <Input
            id="name"
            value={channelName}
            onChange={(e) => setChannelName(e.target.value)}
            placeholder="Leave empty for auto-generated name"
          />
        </div>

        {/* Privacy Setting */}
        {/* <div className="flex items-center space-x-2">
              <Checkbox
                id="private"
                checked={isPrivate}
                onCheckedChange={(checked) => setIsPrivate(checked as boolean)}
              />
              <Label htmlFor="private" className="cursor-pointer font-normal">
                Private Channel (hidden from non-members)
              </Label>
            </div> */}

        {/* Type-Specific Fields */}
        {channelType === 'group' && (
          <div className="space-y-2">
            <Label>Select Members ({selectedMembers.length} selected)</Label>
            <div className="border rounded-md p-4 max-h-60 overflow-y-auto space-y-2">
              {regularUsers.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-4">No users available</p>
              ) : (
                regularUsers.map(user => (
                  <div key={user._id} className="flex items-center space-x-2">
                    <Checkbox
                      id={`user-${user._id}`}
                      checked={selectedMembers.includes(user._id)}
                      onCheckedChange={() => handleMemberToggle(user._id)}
                    />
                    <Label htmlFor={`user-${user._id}`} className="cursor-pointer flex-1 font-normal">
                      {user.name} ({user.email})
                    </Label>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {channelType === 'department' && (
          <div className="space-y-2">
            <Label htmlFor="department">Select Department</Label>
            <Select value={selectedDepartment} onValueChange={setSelectedDepartment}>
              <SelectTrigger id="department">
                <SelectValue placeholder="Choose a department" />
              </SelectTrigger>
              <SelectContent>
                {allDepartments.length === 0 ? (
                  <div className="p-2 text-sm text-muted-foreground">No departments available</div>
                ) : (
                  allDepartments.map(dept => (
                    <SelectItem key={dept._id} value={dept._id}>
                      {dept.name}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
          </div>
        )}

        {channelType === 'department-category' && (
          <div className="space-y-2">
            <Label htmlFor="category">Select Category</Label>
            <Select value={selectedCategory} onValueChange={(val) => setSelectedCategory(val as DepartmentCategory)}>
              <SelectTrigger id="category">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {categories.map(cat => (
                  <SelectItem key={cat} value={cat}>
                    {cat.toUpperCase()}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}

        {channelType === 'multi-category' && (
          <div className="space-y-2">
            <Label>Select Categories ({selectedCategories.length} selected)</Label>
            <div className="border rounded-md p-4 space-y-2">
              {categories.map(cat => (
                <div key={cat} className="flex items-center space-x-2">
                  <Checkbox
                    id={`cat-${cat}`}
                    checked={selectedCategories.includes(cat)}
                    onCheckedChange={() => handleCategoryToggle(cat)}
                  />
                  <Label htmlFor={`cat-${cat}`} className="cursor-pointer font-normal">
                    {cat.toUpperCase()}
                  </Label>
                </div>
              ))}
            </div>
          </div>
        )}

        {channelType === 'project' && (
          <div className="space-y-2">
            <Label htmlFor="project">Select Project</Label>
            <Select value={selectedProject} onValueChange={setSelectedProject}>
              <SelectTrigger id="project">
                <SelectValue placeholder="Choose a project" />
              </SelectTrigger>
              <SelectContent>
                {projects.length === 0 ? (
                  <div className="p-2 text-sm text-muted-foreground">No projects available</div>
                ) : (
                  projects.map(proj => (
                    <SelectItem key={proj._id} value={proj._id}>
                      {proj.name}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
          </div>
        )}

        {channelType === 'client-support' && (
          <div className="space-y-2">
            <Label htmlFor="client">Select Client</Label>
            <Select value={selectedClient} onValueChange={setSelectedClient}>
              <SelectTrigger id="client">
                <SelectValue placeholder="Choose a client" />
              </SelectTrigger>
              <SelectContent>
                {clientUsers.length === 0 ? (
                  <div className="p-2 text-sm text-muted-foreground">No clients available</div>
                ) : (
                  clientUsers.map(client => (
                    <SelectItem key={client._id} value={client._id}>
                      {client.name} ({client.email})
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
          </div>
        )}

        {/* Channel Settings - Only show for applicable channel types */}
        {channelType !== 'dm' && (
          <div className="space-y-4">
            <div className="border-t pt-4">
              <h3 className="text-lg font-medium mb-4">Channel Settings</h3>

              {/* Auto Sync Setting */}
              <div className="flex items-center justify-between p-4 rounded-lg border mb-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-blue-500/10">
                    <RefreshCw className="h-5 w-5 text-blue-500" />
                  </div>
                  <div>
                    <Label className="text-sm font-medium">Auto-Sync Members</Label>
                    <p className="text-xs text-muted-foreground">
                      Automatically add new department members or project assignees
                    </p>
                  </div>
                </div>
                <Switch
                  checked={autoSyncEnabled}
                  onCheckedChange={setAutoSyncEnabled}
                />
              </div>

              {/* Allow External Members */}
              <div className="flex items-center justify-between p-4 rounded-lg border mb-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-green-500/10">
                    <UserPlus className="h-5 w-5 text-green-500" />
                  </div>
                  <div>
                    <Label className="text-sm font-medium">Allow External Members</Label>
                    <p className="text-xs text-muted-foreground">
                      Allow members from outside the department/project
                    </p>
                  </div>
                </div>
                <Switch
                  checked={allowExternalMembers}
                  onCheckedChange={setAllowExternalMembers}
                />
              </div>

              {/* Admin Only Post */}
              <div className="flex items-center justify-between p-4 rounded-lg border mb-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-amber-500/10">
                    <MessageSquareOff className="h-5 w-5 text-amber-500" />
                  </div>
                  <div>
                    <Label className="text-sm font-medium">Admin-Only Posting</Label>
                    <p className="text-xs text-muted-foreground">
                      Only admins can send messages (announcement mode)
                    </p>
                  </div>
                </div>
                <Switch
                  checked={adminOnlyPost}
                  onCheckedChange={setAdminOnlyPost}
                />
              </div>

              {/* Admin Only Add Members */}
              <div className="flex items-center justify-between p-4 rounded-lg border">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-purple-500/10">
                    <UserCog className="h-5 w-5 text-purple-500" />
                  </div>
                  <div>
                    <Label className="text-sm font-medium">Admin-Only Add Members</Label>
                    <p className="text-xs text-muted-foreground">
                      Only admins can add new members to this channel
                    </p>
                  </div>
                </div>
                <Switch
                  checked={adminOnlyAdd}
                  onCheckedChange={setAdminOnlyAdd}
                />
              </div>
            </div>
          </div>
        )}
      </div>
    </CustomModal>
  )
}
