"use client"

import { useState, useCallback, useEffect, useRef, useMemo } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { getInitials } from "@/lib/utils"
import CustomModal from "@/components/shared/custom-modal"
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Settings,
  Users,
  Archive,
  LogOut,
  Shield,
  Crown,
  Trash2,
  UserMinus,
  Loader2,
  Camera,
  Upload,
  RefreshCw,
  UserPlus,
  MessageSquareOff,
  UserCog,
  Check,
  Lock
} from "lucide-react"
import { cn } from "@/lib/utils"
import { IChannel, IChannelMember } from "@/types/communication"
import { useCommunications } from "@/hooks/use-communications"
import { useSession } from "next-auth/react"
import { toast } from "@/hooks/use-toast"
import { useUsers } from "@/hooks/use-users"
import { communicationLogger as logger } from "@/lib/logger"

interface ChannelSettingsModalProps {
  isOpen: boolean
  onClose: () => void
  channel: IChannel
  className?: string
  onSettingsUpdate?: (updatedChannel: Partial<IChannel>) => void
}

interface ChannelSettings {
  name?: string
  avatar_url?: string
  auto_sync_enabled: boolean
  allow_external_members: boolean
  admin_only_post: boolean
  admin_only_add: boolean
}

export function ChannelSettingsModal({
  isOpen,
  onClose,
  channel,
  className,
  onSettingsUpdate
}: ChannelSettingsModalProps) {
  const { data: session } = useSession()
  const currentUserId = (session?.user as any)?.id
  const fileInputRef = useRef<HTMLInputElement>(null)
  
  const {
    leaveChannel,
    archiveChannel,
    actionLoading
  } = useCommunications()

  const { users } = useUsers()

  // Settings state
  const [settings, setSettings] = useState<ChannelSettings>({
    name: channel.name || '',
    avatar_url: channel.avatar_url || '',
    auto_sync_enabled: channel.auto_sync_enabled ?? true,
    allow_external_members: channel.allow_external_members ?? false,
    admin_only_post: channel.admin_only_post ?? false,
    admin_only_add: channel.admin_only_add ?? false
  })

  // Filter allowed users for adding members
  const currentMemberIds = channel.channel_members.map(m => m.mongo_member_id)
  const allowedUsers = useMemo(() => {
    return users.filter(u => !currentMemberIds.includes(u._id)).filter(u => {
      if (settings.allow_external_members) return true
      // If not allowing external, only show users from same department
      if (channel.mongo_department_id) {
        return u.department?.toString() === channel.mongo_department_id
      }
      // For project channels, allow all for now (could be improved to check task assignments)
      return true
    })
  }, [users, currentMemberIds, settings.allow_external_members, channel.mongo_department_id])
  
  const [hasChanges, setHasChanges] = useState(false)
  const [showLeaveConfirm, setShowLeaveConfirm] = useState(false)
  const [showArchiveConfirm, setShowArchiveConfirm] = useState(false)
  const [showRemoveMemberConfirm, setShowRemoveMemberConfirm] = useState<string | null>(null)
  const [isProcessing, setIsProcessing] = useState(false)
  const [isSavingSettings, setIsSavingSettings] = useState(false)
  const [isUploadingAvatar, setIsUploadingAvatar] = useState(false)
  
  // Add member state
  const [showAddMember, setShowAddMember] = useState(false)
  const [selectedUsersToAdd, setSelectedUsersToAdd] = useState<string[]>([])
  const [isAddingMembers, setIsAddingMembers] = useState(false)

  // Get current user's membership
  const currentMembership = channel.channel_members.find(
    m => m.mongo_member_id === currentUserId
  )
  
  const isOwner = currentMembership?.channelRole === 'owner' || channel.mongo_creator_id === currentUserId
  const isAdmin = isOwner || currentMembership?.channelRole === 'admin'
  const isArchived = (channel as any).is_archived || false

  // Update settings when channel changes
  useEffect(() => {
    setSettings({
      name: channel.name || '',
      avatar_url: channel.avatar_url || '',
      auto_sync_enabled: channel.auto_sync_enabled ?? true,
      allow_external_members: channel.allow_external_members ?? false,
      admin_only_post: channel.admin_only_post ?? false,
      admin_only_add: channel.admin_only_add ?? false
    })
    setHasChanges(false)
  }, [channel])

  // Check for changes
  useEffect(() => {
    const changed = 
      settings.name !== (channel.name || '') ||
      settings.avatar_url !== (channel.avatar_url || '') ||
      settings.auto_sync_enabled !== (channel.auto_sync_enabled ?? true) ||
      settings.allow_external_members !== (channel.allow_external_members ?? false) ||
      settings.admin_only_post !== (channel.admin_only_post ?? false) ||
      settings.admin_only_add !== (channel.admin_only_add ?? false)
    
    setHasChanges(changed)
  }, [settings, channel])

  // Get initials from name
  const getInitials = (name: string) => {
    return name
      .split(' ')
      .map(n => n[0])
      .join('')
      .toUpperCase()
      .slice(0, 2)
  }

  // Get role badge
  const getRoleBadge = (channelRole: 'owner' | 'admin' | 'member', isCreator: boolean) => {
    if (channelRole === 'owner' || isCreator) {
      return <Badge variant="default" className="ml-2"><Crown className="h-3 w-3 mr-1" />Owner</Badge>
    }
    if (channelRole === 'admin') {
      return <Badge variant="secondary" className="ml-2"><Shield className="h-3 w-3 mr-1" />Admin</Badge>
    }
    return null
  }

  // Handle avatar upload
  const handleAvatarUpload = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    // Validate file type
    if (!file.type.startsWith('image/')) {
      toast({
        title: "Invalid file type",
        description: "Please upload an image file",
        variant: "destructive"
      })
      return
    }

    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      toast({
        title: "File too large",
        description: "Please upload an image smaller than 5MB",
        variant: "destructive"
      })
      return
    }

    setIsUploadingAvatar(true)
    try {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('folder', 'channel-avatars')
      formData.append('channelId', channel.id)

      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      })

      if (!response.ok) {
        throw new Error('Upload failed')
      }

      const data = await response.json()
      setSettings(prev => ({ ...prev, avatar_url: data.url }))
      
      toast({
        title: "Avatar uploaded",
        description: "Channel avatar has been updated"
      })
    } catch (error) {
      logger.error('Avatar upload error:', error)
      toast({
        title: "Upload failed",
        description: "Failed to upload avatar. Please try again.",
        variant: "destructive"
      })
    } finally {
      setIsUploadingAvatar(false)
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
    }
  }, [channel.id])

  // Handle save settings
  const handleSaveSettings = useCallback(async () => {
    if (!hasChanges) return

    setIsSavingSettings(true)
    try {
      const response = await fetch(`/api/communication/channels/${channel.id}?action=settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Failed to save settings')
      }

      const data = await response.json()
      
      toast({
        title: "Settings saved",
        description: "Channel settings have been updated successfully"
      })

      // Notify parent component
      if (onSettingsUpdate) {
        onSettingsUpdate(data.channel)
      }

      setHasChanges(false)
    } catch (error: any) {
      logger.error('Save settings error:', error)
      toast({
        title: "Save failed",
        description: error.message || "Failed to save settings. Please try again.",
        variant: "destructive"
      })
    } finally {
      setIsSavingSettings(false)
    }
  }, [channel.id, settings, hasChanges, onSettingsUpdate])

  // Handle member role change
  const handleRoleChange = useCallback(async (memberId: string, newRole: 'admin' | 'member') => {
    try {
      const response = await fetch(`/api/communication/channels/${channel.id}?action=member-role`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          memberId: memberId,
          role: newRole
        })
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Failed to update role')
      }

      toast({
        title: "Role updated",
        description: `Member role has been changed to ${newRole}`
      })

      // Trigger channel refresh if callback provided
      if (onSettingsUpdate) {
        onSettingsUpdate({})
      }
    } catch (error: any) {
      logger.error('Role change error:', error)
      toast({
        title: "Update failed",
        description: error.message || "Failed to update member role",
        variant: "destructive"
      })
    }
  }, [channel.id, onSettingsUpdate])

  // Handle remove member
  const handleRemoveMember = useCallback(async (memberId: string) => {
    try {
      const response = await fetch(`/api/communication/channels/${channel.id}?action=remove-member&mongo_member_id=${memberId}`, {
        method: 'DELETE'
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Failed to remove member')
      }

      const data = await response.json()
      if (data.success && data.channel) {
        // Update channel data immediately
        onSettingsUpdate?.(data.channel)
      } else {
        // Fallback to refresh if no channel data returned
        onSettingsUpdate?.({})
      }

      toast({
        title: "Member removed",
        description: "The member has been removed from this channel"
      })

      setShowRemoveMemberConfirm(null)
    } catch (error: any) {
      logger.error('Remove member error:', error)
      toast({
        title: "Remove failed",
        description: error.message || "Failed to remove member",
        variant: "destructive"
      })
    }
  }, [channel.id, onSettingsUpdate])

  // Handle leave channel
  const handleLeave = useCallback(async () => {
    setIsProcessing(true)
    const result = await leaveChannel(channel.id)
    setIsProcessing(false)
    
    if (result.success) {
      setShowLeaveConfirm(false)
      onClose()
    }
  }, [leaveChannel, channel.id, onClose])

  // Handle archive/unarchive channel
  const handleArchive = useCallback(async () => {
    setIsProcessing(true)
    const result = await archiveChannel(channel.id, isArchived ? 'unarchive' : 'archive')
    setIsProcessing(false)
    
    if (result.success) {
      setShowArchiveConfirm(false)
      onClose()
    }
  }, [archiveChannel, channel.id, isArchived, onClose])

  // Handle add members
  const handleAddMembers = useCallback(async () => {
    if (selectedUsersToAdd.length === 0) return

    setIsAddingMembers(true)
    try {
      // Call API to add members
      const response = await fetch(`/api/communication/channels/${channel.id}?action=members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: selectedUsersToAdd })
      })

      if (!response.ok) {
        throw new Error('Failed to add members')
      }

      const data = await response.json()
      if (data.success) {
        toast({
          title: "Success",
          description: `Added ${selectedUsersToAdd.length} member(s) to the channel`
        })
        setSelectedUsersToAdd([])
        setShowAddMember(false)
        // Update channel data immediately with the returned data
        if (data.channel) {
          onSettingsUpdate?.(data.channel)
        } else {
          onSettingsUpdate?.({})
        }
      } else {
        throw new Error(data.error || 'Failed to add members')
      }
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to add members",
        variant: "destructive"
      })
    } finally {
      setIsAddingMembers(false)
    }
  }, [selectedUsersToAdd, channel.id, onSettingsUpdate])

  // Don't show for DM channels
  if (channel.type === 'dm') {
    return null
  }

  return (
    <>
      <CustomModal
        isOpen={isOpen}
        onClose={onClose}
        title="Channel Settings"
        modalSize="lg"
        className={className}
      >
        <Tabs defaultValue="general" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="general" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              General
            </TabsTrigger>
            <TabsTrigger value="permissions" className="flex items-center gap-2">
              <Lock className="h-4 w-4" />
              Permissions
            </TabsTrigger>
            <TabsTrigger value="members" className="flex items-center gap-2">
              <Users className="h-4 w-4" />
              Members ({channel.channel_members.length})
            </TabsTrigger>
          </TabsList>

          {/* General Tab */}
          <TabsContent value="general" className="space-y-6 mt-4">
            {/* Channel Avatar */}
            <div className="flex items-center gap-4">
              <div className="relative">
                <Avatar className="h-20 w-20">
                  <AvatarImage src={settings.avatar_url} />
                  <AvatarFallback className="bg-primary/10 text-primary text-xl">
                    {getInitials(settings.name || channel.type)}
                  </AvatarFallback>
                </Avatar>
                {isAdmin && (
                  <>
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleAvatarUpload}
                      accept="image/*"
                      className="hidden"
                    />
                    <Button
                      variant="secondary"
                      size="icon"
                      className="absolute -bottom-1 -right-1 h-8 w-8 rounded-full"
                      onClick={() => fileInputRef.current?.click()}
                      disabled={isUploadingAvatar}
                    >
                      {isUploadingAvatar ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Camera className="h-4 w-4" />
                      )}
                    </Button>
                  </>
                )}
              </div>
              <div className="flex-1">
                {isAdmin ? (
                  <div className="space-y-2">
                    <Label className="text-sm font-medium">Channel Name</Label>
                    <Input
                      value={settings.name}
                      onChange={(e) => setSettings(prev => ({ ...prev, name: e.target.value }))}
                      placeholder="Enter channel name"
                    />
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Label className="text-sm font-medium">Channel Name</Label>
                    <p className="font-medium text-lg">{channel.name || 'Unnamed Channel'}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Channel Info */}
            <div className="space-y-4">
              <div className="space-y-2">
                <Label className="text-sm font-medium">Channel Type</Label>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">{channel.type}</Badge>
                  {channel.is_private && <Badge variant="secondary">Private</Badge>}
                  {isArchived && <Badge variant="destructive">Archived</Badge>}
                </div>
              </div>

              <div className="space-y-2">
                <Label className="text-sm font-medium">Created</Label>
                <p className="text-sm text-muted-foreground">
                  {new Date(channel.created_at).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                  })}
                </p>
              </div>
            </div>

            <Separator />

            {/* Actions */}
            <div className="space-y-3">
              <Label className="text-sm font-medium">Actions</Label>
              
              {/* Save Changes Button */}
              {isAdmin && hasChanges && (
                <Button
                  className="w-full"
                  onClick={handleSaveSettings}
                  disabled={isSavingSettings}
                >
                  {isSavingSettings && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Save Changes
                </Button>
              )}
              
              {/* Archive/Unarchive - Admin only */}
              {isAdmin && (
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  onClick={() => setShowArchiveConfirm(true)}
                  disabled={actionLoading}
                >
                  <Archive className="h-4 w-4 mr-2" />
                  {isArchived ? 'Unarchive Channel' : 'Archive Channel'}
                </Button>
              )}

              {/* Leave Channel - Not for owners */}
              {!isOwner && (
                <Button
                  variant="outline"
                  className="w-full justify-start text-destructive hover:text-destructive"
                  onClick={() => setShowLeaveConfirm(true)}
                  disabled={actionLoading}
                >
                  <LogOut className="h-4 w-4 mr-2" />
                  Leave Channel
                </Button>
              )}

              {isOwner && (
                <p className="text-xs text-muted-foreground">
                  As the channel owner, you cannot leave. Transfer ownership or archive the channel instead.
                </p>
              )}
            </div>
          </TabsContent>

          {/* Permissions Tab */}
          <TabsContent value="permissions" className="space-y-6 mt-4">
            {isAdmin ? (
              <>
                {/* Auto Sync Setting */}
                <div className="flex items-center justify-between p-4 rounded-lg border">
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
                    checked={settings.auto_sync_enabled}
                    onCheckedChange={(checked) => setSettings(prev => ({ ...prev, auto_sync_enabled: checked }))}
                  />
                </div>

                {/* Allow External Members */}
                <div className="flex items-center justify-between p-4 rounded-lg border">
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
                    checked={settings.allow_external_members}
                    onCheckedChange={(checked) => setSettings(prev => ({ ...prev, allow_external_members: checked }))}
                  />
                </div>

                {/* Admin Only Post */}
                <div className="flex items-center justify-between p-4 rounded-lg border">
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
                    checked={settings.admin_only_post}
                    onCheckedChange={(checked) => setSettings(prev => ({ ...prev, admin_only_post: checked }))}
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
                    checked={settings.admin_only_add}
                    onCheckedChange={(checked) => setSettings(prev => ({ ...prev, admin_only_add: checked }))}
                  />
                </div>

                {/* Save Button */}
                {hasChanges && (
                  <Button
                    className="w-full"
                    onClick={handleSaveSettings}
                    disabled={isSavingSettings}
                  >
                    {isSavingSettings && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                    Save Permission Settings
                  </Button>
                )}
              </>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Lock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Only admins can modify channel permissions</p>
              </div>
            )}
          </TabsContent>

          {/* Members Tab */}
          <TabsContent value="members" className="mt-4">
            {/* Add Member Button */}
            {isAdmin && (
              <div className="mb-4">
                <Button
                  onClick={() => setShowAddMember(!showAddMember)}
                  className="w-full"
                  variant="outline"
                >
                  <UserPlus className="h-4 w-4 mr-2" />
                  Add Members
                </Button>
              </div>
            )}

            {/* Add Member Form */}
            {showAddMember && isAdmin && (
              <div className="mb-4 p-4 border rounded-lg bg-muted/20">
                <h4 className="font-medium mb-3">Select Users to Add</h4>
                <ScrollArea className="h-[200px] pr-4">
                  <div className="space-y-2">
                    {users
                      .filter(user => 
                        !channel.channel_members.some(member => member.mongo_member_id === user._id) &&
                        user._id !== currentUserId
                      )
                      .filter(user => {
                        // If allow_external_members is false, only show users from relevant departments/projects
                        if (!settings.allow_external_members) {
                          if (channel.type === 'department' && channel.mongo_department_id) {
                            return user.department?.toString() === channel.mongo_department_id
                          }
                          if (channel.type === 'project' && channel.mongo_project_id) {
                            return user.department?.toString() === channel.mongo_department_id
                          }
                          if (channel.type === 'client-support' && channel.mongo_project_id) {
                            return user.isClient || user.department?.toString() === channel.mongo_department_id
                          }
                          // For group channels, show all non-client users
                          return !user.isClient
                        }
                        // If allow_external_members is true, show all users
                        return true
                      })
                      .map((user) => (
                        <div
                          key={user._id}
                          className={cn(
                            "flex items-center justify-between p-2 rounded-lg cursor-pointer",
                            "hover:bg-muted/50 transition-colors",
                            selectedUsersToAdd.includes(user._id) && "bg-primary/10"
                          )}
                          onClick={() => {
                            setSelectedUsersToAdd(prev =>
                              prev.includes(user._id)
                                ? prev.filter(id => id !== user._id)
                                : [...prev, user._id]
                            )
                          }}
                        >
                          <div className="flex items-center gap-3">
                            <Avatar className="h-8 w-8">
                              <AvatarImage src={user.avatar} />
                              <AvatarFallback className="bg-primary/10 text-primary text-xs">
                                {getInitials(user.name || user.email || 'U')}
                              </AvatarFallback>
                            </Avatar>
                            <div>
                              <p className="text-sm font-medium">{user.name || 'Unknown User'}</p>
                              <p className="text-xs text-muted-foreground">{user.email}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {selectedUsersToAdd.includes(user._id) && (
                              <div className="w-4 h-4 bg-primary rounded-full flex items-center justify-center">
                                <Check className="h-3 w-3 text-primary-foreground" />
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                  </div>
                </ScrollArea>
                {selectedUsersToAdd.length > 0 && (
                  <div className="flex gap-2 mt-3">
                    <Button
                      onClick={handleAddMembers}
                      disabled={isAddingMembers}
                      size="sm"
                    >
                      {isAddingMembers && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                      Add {selectedUsersToAdd.length} Member{selectedUsersToAdd.length > 1 ? 's' : ''}
                    </Button>
                    <Button
                      onClick={() => setSelectedUsersToAdd([])}
                      variant="outline"
                      size="sm"
                    >
                      Clear
                    </Button>
                  </div>
                )}
              </div>
            )}

            <ScrollArea className="h-[350px] pr-4">
              <div className="space-y-2">
                {channel.channel_members.map((member) => {
                  const isCurrentUser = member.mongo_member_id === currentUserId
                  const isMemberOwner = member.channelRole === 'owner' || member.mongo_member_id === channel.mongo_creator_id
                  const canManageMember = isAdmin && !isMemberOwner && !isCurrentUser
                  
                  return (
                    <div
                      key={member.mongo_member_id}
                      className={cn(
                        "flex items-center justify-between p-3 rounded-lg",
                        "hover:bg-muted/50 transition-colors",
                        isCurrentUser && "bg-primary/5"
                      )}
                    >
                      <div className="flex items-center gap-3">
                        <Avatar className="h-10 w-10">
                          <AvatarImage src={member.avatar} />
                          <AvatarFallback className="bg-primary/10 text-primary text-sm">
                            {getInitials(member.name || 'U')}
                          </AvatarFallback>
                        </Avatar>
                        <div>
                          <div className="flex items-center">
                            <p className="font-medium text-sm">
                              {member.name || 'Unknown User'}
                              {isCurrentUser && <span className="text-muted-foreground ml-1">(You)</span>}
                            </p>
                            {getRoleBadge(member.channelRole, isMemberOwner)}
                          </div>
                          <p className="text-xs text-muted-foreground">
                            {member.email || member.userRole || 'Member'}
                          </p>
                        </div>
                      </div>

                      {/* Admin actions for managing members */}
                      {canManageMember && (
                        <div className="flex items-center gap-2">
                          <Select
                            value={member.channelRole}
                            onValueChange={(value: 'admin' | 'member') => handleRoleChange(member.mongo_member_id, value)}
                          >
                            <SelectTrigger className="w-24 h-8">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="admin">Admin</SelectItem>
                              <SelectItem value="member">Member</SelectItem>
                            </SelectContent>
                          </Select>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-destructive hover:text-destructive hover:bg-destructive/10"
                            onClick={() => setShowRemoveMemberConfirm(member.mongo_member_id)}
                          >
                            <UserMinus className="h-4 w-4" />
                          </Button>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </CustomModal>

      {/* Leave Confirmation Dialog */}
      <AlertDialog open={showLeaveConfirm} onOpenChange={setShowLeaveConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Leave Channel?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to leave "{channel.name}"? 
              You'll no longer receive messages from this channel.
              {isAdmin && (
                <span className="block mt-2 text-amber-600">
                  Note: As an admin, leaving will transfer your role to another member.
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isProcessing}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleLeave}
              disabled={isProcessing}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isProcessing && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Leave Channel
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Archive Confirmation Dialog */}
      <AlertDialog open={showArchiveConfirm} onOpenChange={setShowArchiveConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {isArchived ? 'Unarchive Channel?' : 'Archive Channel?'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {isArchived ? (
                <>
                  This will restore the channel and make it visible to all members again.
                  Members will be able to send messages.
                </>
              ) : (
                <>
                  Archiving will hide this channel from the channel list.
                  Members won't be able to send new messages, but message history will be preserved.
                </>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isProcessing}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleArchive}
              disabled={isProcessing}
            >
              {isProcessing && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {isArchived ? 'Unarchive' : 'Archive'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Remove Member Confirmation Dialog */}
      <AlertDialog open={!!showRemoveMemberConfirm} onOpenChange={() => setShowRemoveMemberConfirm(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove Member?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to remove this member from the channel?
              They will no longer be able to see messages or participate in this channel.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => showRemoveMemberConfirm && handleRemoveMember(showRemoveMemberConfirm)}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Remove Member
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

export default ChannelSettingsModal
