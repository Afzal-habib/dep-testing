'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { ChevronDown, ChevronRight, Shield, Users, Settings, Database, FileText, Lock } from 'lucide-react'
import type { Permission } from '@/types'
import { useSystemPermissions } from '@/hooks/use-system-permissions'
import { CardLoader } from '../ui/loader'

interface PermissionSelectorProps {
  selectedPermissions?: Permission[]
  onPermissionsChange: (permissions: Permission[]) => void
  disabled?: boolean
}

const CATEGORY_ICONS: Record<string, React.ComponentType<any>> = {
  user_management: Users,
  department_management: Shield,
  role_management: Lock,
  system_administration: Settings,
  reporting: FileText,
  data_management: Database,
  security: Lock,
  integration: Settings,
  custom: Settings,
}

const CATEGORY_COLORS: Record<string, string> = {
  user_management: 'bg-blue-100 text-blue-800',
  department_management: 'bg-green-100 text-green-800',
  role_management: 'bg-purple-100 text-purple-800',
  system_administration: 'bg-red-100 text-red-800',
  reporting: 'bg-yellow-100 text-yellow-800',
  data_management: 'bg-indigo-100 text-indigo-800',
  security: 'bg-red-100 text-red-800',
  integration: 'bg-gray-100 text-gray-800',
  custom: 'bg-orange-100 text-orange-800',
}

const ACTION_DESCRIPTIONS: Record<string, string> = {
  create: 'Can create new records',
  read: 'Can view and access records',
  update: 'Can modify existing records',
  delete: 'Can remove records permanently',
  assign: 'Can assign records to users',
  approve: 'Can approve requests/changes',
  reject: 'Can reject requests/changes',
  export: 'Can export data to files',
  import: 'Can import data from files',
  archive: 'Can archive/restore records',
}

const CONDITION_DESCRIPTIONS: Record<string, string> = {
  own: 'Only for records they own',
  department: 'Only within their department',
  assigned: 'Only for assigned records',
  subordinates: 'Only for subordinate users',
  unrestricted: '🌟 ALL RECORDS (Full Access)'
}

export function PermissionSelector({ 
  selectedPermissions = [], 
  onPermissionsChange,
  disabled = false 
}: PermissionSelectorProps) {
  const [expandedCategories, setExpandedCategories] = useState<string[]>(['user_management'])
  const [expandedResources, setExpandedResources] = useState<string[]>([])
  const [loadAttempts, setLoadAttempts] = useState(0)
  const [isRetrying, setIsRetrying] = useState(false)
  
  const {
    groupedPermissions,
    loading,
    error,
    fetchSystemPermissions,
  } = useSystemPermissions()

  // Auto-fetch permissions with retry logic
  useEffect(() => {
    const loadPermissions = async () => {
      try {
        console.log('PermissionSelector: Component mounted, fetching system permissions (attempt:', loadAttempts + 1, ')')
        const result = await fetchSystemPermissions()
        console.log('PermissionSelector: Fetch result:', result)
        console.log('PermissionSelector: Grouped permissions from store:', groupedPermissions)
        setLoadAttempts(prev => prev + 1)
      } catch (error) {
        console.error('PermissionSelector: Fetch error:', error)
        setLoadAttempts(prev => prev + 1)
        
        // Auto-retry up to 3 times with increasing delays
        if (loadAttempts < 3) {
          setTimeout(() => {
            console.log('PermissionSelector: Auto-retrying in 2 seconds...')
            loadPermissions()
          }, 2000 + (loadAttempts * 1000))
        }
      }
    }

    // Only load if we don't have permissions yet and not currently loading
    const hasPermissions = Object.keys(groupedPermissions).length > 0
    console.log('PermissionSelector: Check if need to load permissions:', {
      hasPermissions,
      loading,
      loadAttempts,
      groupedPermissionsKeys: Object.keys(groupedPermissions)
    })
    
    if (!hasPermissions && !loading && loadAttempts === 0) {
      loadPermissions()
    }
  }, [fetchSystemPermissions, groupedPermissions, loading, loadAttempts])

  // Manual retry function
  const handleRetry = async () => {
    setIsRetrying(true)
    try {
      console.log('PermissionSelector: Manual retry initiated')
      const result = await fetchSystemPermissions()
      console.log('PermissionSelector: Manual retry result:', result)
      console.log('PermissionSelector: Grouped permissions after manual retry:', groupedPermissions)
      setLoadAttempts(0) // Reset attempts on successful manual retry
    } catch (error) {
      console.error('PermissionSelector: Manual retry error:', error)
    } finally {
      setIsRetrying(false)
    }
  }

  // Debug logging
  useEffect(() => {
    console.log('PermissionSelector: State changed', {
      loading,
      error,
      groupedPermissionsKeys: Object.keys(groupedPermissions),
      totalPermissions: Object.values(groupedPermissions).reduce((acc, perms) => acc + perms.length, 0),
      selectedPermissionsCount: Array.isArray(selectedPermissions) ? selectedPermissions.length : 0,
      loadAttempts,
      isRetrying
    })
  }, [loading, error, groupedPermissions, selectedPermissions, loadAttempts, isRetrying])

  // Debug selected permissions changes
  useEffect(() => {
    if (Array.isArray(selectedPermissions) && selectedPermissions.length > 0) {
      console.log('PermissionSelector: Selected permissions updated:', {
        count: selectedPermissions.length,
        permissions: selectedPermissions.map(p => ({
          resource: p.resource,
          actions: p.actions,
          hasConditions: !!p.conditions
        }))
      })
    }
  }, [selectedPermissions])

  // Additional debugging for disappearing permissions
  useEffect(() => {
    const categories = Object.keys(groupedPermissions)
    if (categories.length > 0) {
      console.log('PermissionSelector: Permissions loaded successfully:', {
        categoriesCount: categories.length,
        categories,
        firstCategoryPermissions: categories[0] ? groupedPermissions[categories[0]] : null
      })
    } else if (!loading && !error) {
      console.log('PermissionSelector: No permissions found but no error either')
    }
  }, [groupedPermissions, loading, error])

  const toggleCategory = (category: string) => {
    setExpandedCategories(prev => 
      prev.includes(category) 
        ? prev.filter(c => c !== category)
        : [...prev, category]
    )
  }

  const toggleResource = (resource: string) => {
    setExpandedResources(prev => 
      prev.includes(resource) 
        ? prev.filter(r => r !== resource)
        : [...prev, resource]
    )
  }

  const isResourceSelected = (resource: string) => {
    return Array.isArray(selectedPermissions) && selectedPermissions.some(p => p.resource === resource)
  }

  const getSelectedPermission = (resource: string) => {
    return Array.isArray(selectedPermissions) ? selectedPermissions.find(p => p.resource === resource) : undefined
  }

  const updatePermission = (resource: string, updates: Partial<Permission>) => {
    if (!Array.isArray(selectedPermissions)) return
    
    const newPermissions = selectedPermissions.map(p => 
      p.resource === resource ? { ...p, ...updates } : p
    )
    onPermissionsChange(newPermissions)
  }

  const addPermission = (resource: string, availableActions: string[]) => {
    const currentPermissions = Array.isArray(selectedPermissions) ? selectedPermissions : []
    const newPermission: Permission = {
      resource,
      actions: ['read'], // Default to read permission
      conditions: {
        own: true,
        department: false,
        assigned: false,
        subordinates: false,
        unrestricted: false, // Add this
      }
    }
    onPermissionsChange([...currentPermissions, newPermission])
    
    // Auto-expand the resource to show actions
    if (!expandedResources.includes(resource)) {
      setExpandedResources(prev => [...prev, resource])
    }
  }

  const removePermission = (resource: string) => {
    if (!Array.isArray(selectedPermissions)) return
    
    const newPermissions = selectedPermissions.filter(p => p.resource !== resource)
    onPermissionsChange(newPermissions)
  }

  const toggleAction = (resource: string, action: string) => {
    const permission = getSelectedPermission(resource)
    if (!permission) return

    const newActions = permission.actions.includes(action)
      ? permission.actions.filter(a => a !== action)
      : [...permission.actions, action]
    
    // Ensure at least one action is selected
    if (newActions.length === 0) {
      newActions.push('read')
    }
    
    updatePermission(resource, { actions: newActions })
  }

  const toggleCondition = (resource: string, condition: keyof Permission['conditions']) => {
    const permission = getSelectedPermission(resource)
    if (!permission || !permission.conditions) return

    updatePermission(resource, {
      conditions: {
        ...permission.conditions,
        [condition]: !permission.conditions[condition]
      }
    })
  }

  const selectAllActions = (resource: string, availableActions: string[]) => {
    updatePermission(resource, { actions: [...availableActions] })
  }

  const selectNoneActions = (resource: string) => {
    updatePermission(resource, { actions: ['read'] }) // Keep at least read
  }

  if (loading || isRetrying) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Permissions
          </CardTitle>
        </CardHeader>
        <CardContent>
            <CardLoader height="h-32" cards={1} />
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Permissions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <div className="text-destructive mb-4">
              Failed to load permissions: {error}
              {loadAttempts > 0 && (
                <div className="text-sm text-muted-foreground mt-2">
                  Attempts: {loadAttempts}/3
                </div>
              )}
            </div>
            <Button 
              type="button"
              variant="outline" 
              onClick={handleRetry}
              disabled={isRetrying}
            >
              {isRetrying ? "Retrying..." : "Retry Loading"}
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  const categories = Object.keys(groupedPermissions)
  
  // Show empty state if no permissions found
  if (categories.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Permissions Configuration
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            Configure what actions this role can perform and under what conditions
          </p>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <div className="text-muted-foreground mb-4">
              No permissions available. This might indicate a configuration issue.
            </div>
            <Button 
              type="button"
              variant="outline" 
              onClick={handleRetry}
              disabled={isRetrying}
            >
              {isRetrying ? "Retrying..." : "Reload Permissions"}
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="w-full">
      <CardHeader className="pb-6">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-xl font-semibold">Role Permissions</CardTitle>
            <p className="text-muted-foreground mt-1">
              Check the boxes to grant permissions to this role
            </p>
          </div>
          {Array.isArray(selectedPermissions) && selectedPermissions.length > 0 && (
            <Badge variant="default" className="px-3 py-1 text-base">
              {selectedPermissions.length} Selected
            </Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {categories.map(category => {
          const Icon = CATEGORY_ICONS[category] || Shield
          const permissions = groupedPermissions[category] || []
          const isExpanded = expandedCategories.includes(category)
          const selectedCount = permissions.filter(p => isResourceSelected(p.resource)).length
          
          return (
            <div key={category} className="border rounded-lg">
              {/* Category Header */}
              <div 
                className={`flex items-center justify-between p-4 cursor-pointer hover:bg-accent/50 transition-colors ${
                  selectedCount > 0 ? 'bg-primary/5 border-l-4 border-l-primary' : ''
                }`}
                onClick={() => toggleCategory(category)}
              >
                <div className="flex items-center gap-3">
                  <Icon className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <h3 className="font-medium capitalize text-foreground">
                      {category.replace(/_/g, ' ')}
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      {selectedCount} of {permissions.length} selected
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {selectedCount > 0 && (
                    <Badge className="bg-primary/10 text-primary">
                      {selectedCount}
                    </Badge>
                  )}
                  {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                </div>
              </div>

              {/* Permissions List */}
              {isExpanded && (
                <div className="border-t bg-muted/30">
                  {permissions.map((permission, index) => {
                    const isSelected = isResourceSelected(permission.resource)
                    const selectedPerm = getSelectedPermission(permission.resource)
                    
                    return (
                      <div 
                        key={permission.resource} 
                        className={`p-4 ${index !== permissions.length - 1 ? 'border-b border-border' : ''} ${
                          isSelected ? 'bg-card shadow-sm' : ''
                        }`}
                      >
                        {/* Permission Header */}
                        <div className="flex items-start gap-3">
                          <Checkbox
                            checked={isSelected}
                            onCheckedChange={(checked) => {
                              if (checked) {
                                addPermission(permission.resource, permission.availableActions.map(a => a.action))
                              } else {
                                removePermission(permission.resource)
                              }
                            }}
                            disabled={disabled}
                            className="mt-1"
                          />
                          <div className="flex-1">
                            <Label className={`font-medium cursor-pointer block ${
                              isSelected ? 'text-primary' : 'text-foreground'
                            }`}>
                              {permission.displayName}
                            </Label>
                            {permission.description && (
                              <p className="text-sm text-muted-foreground mt-1">
                                {permission.description}
                              </p>
                            )}
                          </div>
                        </div>

                        {/* Actions Selection */}
                        {isSelected && selectedPerm && (
                          <div className="ml-7 mt-4 space-y-3">
                            {/* Actions */}
                            <div>
                              <div className="flex items-center justify-between mb-2">
                                <Label className="text-sm font-medium text-foreground">
                                  What can they do?
                                </Label>
                                <div className="space-x-1">
                                  <Button
                                    type="button"
                                    variant="outline"
                                    size="sm"
                                    onClick={() => selectAllActions(permission.resource, permission.availableActions.map(a => a.action))}
                                    disabled={disabled}
                                    className="h-7 px-2 text-xs"
                                  >
                                    All
                                  </Button>
                                  <Button
                                    type="button"
                                    variant="outline"
                                    size="sm"
                                    onClick={() => selectNoneActions(permission.resource)}
                                    disabled={disabled}
                                    className="h-7 px-2 text-xs"
                                  >
                                    None
                                  </Button>
                                </div>
                              </div>
                              
                              <div className="flex flex-wrap gap-2">
                                {permission.availableActions.map(actionInfo => (
                                  <Button
                                    key={actionInfo.action}
                                    type="button"
                                    variant={selectedPerm?.actions.includes(actionInfo.action) ? "default" : "outline"}
                                    size="sm"
                                    onClick={() => toggleAction(permission.resource, actionInfo.action)}
                                    disabled={disabled}
                                    className={`h-8 px-3 text-sm capitalize ${
                                      selectedPerm?.actions.includes(actionInfo.action)
                                        ? 'bg-primary hover:bg-primary/90 text-primary-foreground'
                                        : 'hover:bg-accent hover:text-accent-foreground border-border'
                                    }`}
                                  >
                                    {actionInfo.action}
                                  </Button>
                                ))}
                              </div>
                            </div>

                            {/* Access Level Conditions */}
                            {selectedPerm?.conditions && Object.keys(selectedPerm.conditions).length > 0 && (
                              <div>
                                <Label className="text-sm font-medium text-foreground mb-2 block">
                                  Access Level:
                                </Label>
                                <div className="flex flex-wrap gap-2">
                                  {Object.entries(selectedPerm.conditions).map(([condition, value]) => (
                                    <Button
                                      key={condition}
                                      type="button"
                                      variant={value ? "default" : "outline"}
                                      size="sm"
                                      onClick={() => toggleCondition(permission.resource, condition as keyof Permission['conditions'])}
                                      disabled={disabled}
                                      className={`h-8 px-3 text-sm ${
                                        value
                                          ? 'bg-primary hover:bg-primary/90 text-primary-foreground'
                                          : 'hover:bg-accent hover:text-accent-foreground border-border'
                                      }`}
                                    >
                                      {CONDITION_DESCRIPTIONS[condition]}
                                    </Button>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}

        {/* Simple Summary */}
        {Array.isArray(selectedPermissions) && selectedPermissions.length > 0 && (
          <div className="mt-6 p-4 bg-primary/5 rounded-lg border border-primary/20">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-medium text-primary">Selected Permissions</h4>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => onPermissionsChange([])}
                disabled={disabled}
                className="text-destructive hover:bg-destructive/10 border-destructive/20"
              >
                Clear All
              </Button>
            </div>
            <div className="space-y-2">
              {selectedPermissions.map(permission => (
                <div key={permission.resource} className="flex items-center justify-between bg-card p-3 rounded border border-border">
                  <div>
                    <span className="font-medium capitalize text-foreground">
                      {permission.resource.replace(/_/g, ' ')}
                    </span>
                    <div className="flex gap-1 mt-1">
                      {Array.isArray(permission.actions) && permission.actions.map(action => (
                        <Badge key={action} variant="secondary" className="text-xs">
                          {action}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => removePermission(permission.resource)}
                    disabled={disabled}
                    className="text-destructive hover:bg-destructive/10 h-8 w-8 p-0"
                  >
                    ×
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}