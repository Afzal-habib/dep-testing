"use client"

import { useState, useEffect, useCallback } from "react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { 
  Wifi, 
  WifiOff, 
  RefreshCw, 
  CheckCircle2,
  AlertTriangle,
  Loader2
} from "lucide-react"
import { cn } from "@/lib/utils"
import { getRealtimeManager } from "@/lib/realtime-manager"
import { communicationLogger as logger } from "@/lib/logger"

type ConnectionState = 'connected' | 'disconnected' | 'reconnecting' | 'error'

interface ConnectionStatusProps {
  className?: string
  showWhenConnected?: boolean
}

export function ConnectionStatus({ 
  className,
  showWhenConnected = false 
}: ConnectionStatusProps) {
  const [connectionState, setConnectionState] = useState<ConnectionState>('connected')
  const [reconnectAttempt, setReconnectAttempt] = useState(0)
  const [isManualReconnecting, setIsManualReconnecting] = useState(false)

  // Subscribe to connection state changes
  useEffect(() => {
    const handleOnline = () => {
      setConnectionState('reconnecting')
      // Attempt to reconnect after coming back online
      const manager = getRealtimeManager()
      if (manager) {
        manager.reconnect?.().then(() => {
          setConnectionState('connected')
        }).catch(() => {
          setConnectionState('error')
        })
      } else {
        setConnectionState('connected')
      }
    }

    const handleOffline = () => {
      setConnectionState('disconnected')
    }

    // Listen to browser online/offline events
    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)

    // Check initial state
    if (!navigator.onLine) {
      setConnectionState('disconnected')
    }

    // Listen to realtime manager connection events
    const handleConnectionChange = (event: CustomEvent) => {
      const { state, attempt } = event.detail || {}
      if (state) {
        setConnectionState(state)
      }
      if (typeof attempt === 'number') {
        setReconnectAttempt(attempt)
      }
    }

    window.addEventListener('realtime-connection-change' as any, handleConnectionChange)

    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
      window.removeEventListener('realtime-connection-change' as any, handleConnectionChange)
    }
  }, [])

  // Manual reconnect handler
  const handleManualReconnect = useCallback(async () => {
    setIsManualReconnecting(true)
    setConnectionState('reconnecting')
    
    try {
      const manager = getRealtimeManager()
      if (manager && manager.reconnect) {
        await manager.reconnect()
        setConnectionState('connected')
      } else {
        // Fallback: reload the page
        window.location.reload()
      }
    } catch (error) {
      logger.error('Manual reconnect failed:', error)
      setConnectionState('error')
    } finally {
      setIsManualReconnecting(false)
    }
  }, [])

  // Don't show when connected unless explicitly requested
  if (connectionState === 'connected' && !showWhenConnected) {
    return null
  }

  const getStatusConfig = () => {
    switch (connectionState) {
      case 'connected':
        return {
          icon: CheckCircle2,
          message: 'Connected',
          variant: 'default' as const,
          bgClass: 'bg-green-500/10 border-green-500/20 text-green-700 dark:text-green-400'
        }
      case 'disconnected':
        return {
          icon: WifiOff,
          message: 'You\'re offline. Messages will sync when you reconnect.',
          variant: 'destructive' as const,
          bgClass: 'bg-yellow-500/10 border-yellow-500/20 text-yellow-700 dark:text-yellow-400'
        }
      case 'reconnecting':
        return {
          icon: Loader2,
          message: reconnectAttempt > 0 
            ? `Reconnecting... (attempt ${reconnectAttempt})` 
            : 'Reconnecting...',
          variant: 'default' as const,
          bgClass: 'bg-blue-500/10 border-blue-500/20 text-blue-700 dark:text-blue-400'
        }
      case 'error':
        return {
          icon: AlertTriangle,
          message: 'Connection error. Please try reconnecting.',
          variant: 'destructive' as const,
          bgClass: 'bg-red-500/10 border-red-500/20 text-red-700 dark:text-red-400'
        }
      default:
        return {
          icon: Wifi,
          message: 'Checking connection...',
          variant: 'default' as const,
          bgClass: ''
        }
    }
  }

  const config = getStatusConfig()
  const Icon = config.icon

  return (
    <div 
      className={cn(
        "flex items-center justify-between px-4 py-2 rounded-md border",
        config.bgClass,
        className
      )}
    >
      <div className="flex items-center gap-2">
        <Icon 
          className={cn(
            "h-4 w-4",
            connectionState === 'reconnecting' && "animate-spin"
          )} 
        />
        <span className="text-sm font-medium">{config.message}</span>
      </div>
      
      {(connectionState === 'disconnected' || connectionState === 'error') && (
        <Button
          size="sm"
          variant="ghost"
          onClick={handleManualReconnect}
          disabled={isManualReconnecting}
          className="h-7 px-2"
        >
          <RefreshCw className={cn(
            "h-3 w-3 mr-1",
            isManualReconnecting && "animate-spin"
          )} />
          Reconnect
        </Button>
      )}
    </div>
  )
}

// Compact version for inline use
export function ConnectionStatusBadge({ className }: { className?: string }) {
  const [isOnline, setIsOnline] = useState(true)

  useEffect(() => {
    const handleOnline = () => setIsOnline(true)
    const handleOffline = () => setIsOnline(false)

    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)
    setIsOnline(navigator.onLine)

    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
    }
  }, [])

  if (isOnline) return null

  return (
    <div className={cn(
      "flex items-center gap-1 px-2 py-1 rounded-full text-xs",
      "bg-yellow-500/20 text-yellow-700 dark:text-yellow-400",
      className
    )}>
      <WifiOff className="h-3 w-3" />
      <span>Offline</span>
    </div>
  )
}

export default ConnectionStatus
