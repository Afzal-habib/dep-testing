"use client"

import { useState, useCallback } from 'react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { MessageSquare, Loader2 } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { toast } from '@/hooks/use-toast'

interface ProjectChannelButtonProps {
  projectId: string
  projectName: string
  disabled?: boolean
  className?: string
  variant?: 'default' | 'outline' | 'secondary' | 'ghost'
  size?: 'default' | 'sm' | 'lg' | 'icon'
}

export function ProjectChannelButton({
  projectId,
  projectName,
  disabled = false,
  className,
  variant = 'outline',
  size = 'default'
}: ProjectChannelButtonProps) {
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(false)

  const handleOpenChannel = useCallback(async () => {
    setIsLoading(true)
    try {
      // First, check if project channel exists
      const response = await fetch(`/api/communication/channels?mongo_project_id=${projectId}&type=project`)
      
      if (!response.ok) {
        throw new Error('Failed to fetch channel')
      }

      const data = await response.json()
      
      if (data.channels && data.channels.length > 0) {
        // Channel exists, navigate to it
        const channelId = data.channels[0].id
        router.push(`/communications?channelId=${channelId}`)
      } else {
        // No channel exists, create one
        const createResponse = await fetch('/api/communication/channels', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: `${projectName} Channel`,
            type: 'project',
            mongo_project_id: projectId,
            channel_members: [], // Will be auto-synced with project members
            is_private: true
          })
        })

        if (!createResponse.ok) {
          throw new Error('Failed to create channel')
        }

        const createData = await createResponse.json()
        
        toast({
          title: "Channel Created",
          description: `Project channel for "${projectName}" has been created`
        })

        // Navigate to the new channel
        router.push(`/communications?channelId=${createData.channel.id}`)
      }
    } catch (error: any) {
      console.error('Failed to open project channel:', error)
      toast({
        title: "Error",
        description: error.message || "Failed to open project channel",
        variant: "destructive"
      })
    } finally {
      setIsLoading(false)
    }
  }, [projectId, projectName, router])

  return (
    <Button
      variant={variant}
      size={size}
      onClick={handleOpenChannel}
      disabled={disabled || isLoading}
      className={cn("gap-2", className)}
    >
      {isLoading ? (
        <Loader2 className="h-4 w-4 animate-spin" />
      ) : (
        <MessageSquare className="h-4 w-4" />
      )}
      {size !== 'icon' && (
        <span>Project Channel</span>
      )}
    </Button>
  )
}

export default ProjectChannelButton
