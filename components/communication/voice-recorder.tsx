"use client"

import { useState, useCallback, useRef, useEffect, memo } from 'react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { 
  Mic, 
  Square, 
  Play, 
  Pause, 
  X, 
  Send, 
  Loader2,
  MicOff,
  Trash2
} from 'lucide-react'
import { toast } from '@/hooks/use-toast'
import useVoiceRecorder from '@/hooks/use-voice-recorder'
import { communicationLogger as logger } from "@/lib/logger"

interface VoiceRecorderProps {
  onSendVoice: (audioBlob: Blob, duration: number) => Promise<void>
  onCancel?: () => void
  disabled?: boolean
  className?: string
  maxDuration?: number // in seconds
}

/**
 * Professional Voice Recorder Component - WhatsApp Web Style
 * Inline recording UI that replaces the message input area
 */
export const VoiceRecorder = memo(function VoiceRecorder({
  onSendVoice,
  onCancel,
  disabled = false,
  className,
  maxDuration = 300
}: VoiceRecorderProps) {
  const {
    isRecording,
    isPaused,
    duration,
    audioBlob,
    audioUrl,
    error,
    isSupported,
    permissionStatus,
    audioLevel,
    startRecording,
    stopRecording,
    pauseRecording,
    resumeRecording,
    cancelRecording,
    resetRecording,
    formatDuration,
    requestPermission
  } = useVoiceRecorder()

  const [isSending, setIsSending] = useState(false)
  const [isPlaying, setIsPlaying] = useState(false)
  const [playbackProgress, setPlaybackProgress] = useState(0)
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const playbackIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const waveformBarsRef = useRef<number[]>([])

  // Generate random waveform bars on mount
  useEffect(() => {
    waveformBarsRef.current = Array.from({ length: 50 }, () => Math.random() * 0.7 + 0.3)
  }, [])

  // Handle permission request with toast feedback
  const handleRequestPermission = useCallback(async (): Promise<boolean> => {
    const granted = await requestPermission()
    
    if (!granted) {
      toast({
        title: "Microphone Access Required",
        description: permissionStatus === 'denied' 
          ? "Click the lock icon (🔒) in your browser's address bar, allow microphone access, then refresh."
          : "Please allow microphone access when prompted.",
        variant: "destructive",
        duration: 8000
      })
    }
    return granted
  }, [requestPermission, permissionStatus])

  // Handle start recording
  const handleStartRecording = useCallback(async () => {
    if (permissionStatus !== 'granted') {
      const granted = await handleRequestPermission()
      if (!granted) return
    }

    const started = await startRecording()
    if (!started && error) {
      toast({
        title: "Recording Failed",
        description: error,
        variant: "destructive"
      })
    }
  }, [permissionStatus, handleRequestPermission, startRecording, error])

  // Handle stop recording - don't await for faster response
  const handleStopRecording = useCallback(() => {
    stopRecording()
  }, [stopRecording])

  // Handle cancel - immediate response
  const handleCancel = useCallback(() => {
    // Stop playback immediately
    if (audioRef.current) {
      audioRef.current.pause()
      audioRef.current.src = ''
    }
    if (playbackIntervalRef.current) {
      clearInterval(playbackIntervalRef.current)
      playbackIntervalRef.current = null
    }
    setIsPlaying(false)
    setPlaybackProgress(0)
    // Cancel recording immediately
    cancelRecording()
    onCancel?.()
  }, [cancelRecording, onCancel])

  // Handle playback toggle
  const handleTogglePlayback = useCallback(() => {
    if (!audioRef.current || !audioUrl) return

    if (isPlaying) {
      audioRef.current.pause()
      setIsPlaying(false)
      if (playbackIntervalRef.current) {
        clearInterval(playbackIntervalRef.current)
      }
    } else {
      audioRef.current.play().then(() => {
        setIsPlaying(true)
        
        playbackIntervalRef.current = setInterval(() => {
          if (audioRef.current) {
            const progress = (audioRef.current.currentTime / audioRef.current.duration) * 100
            setPlaybackProgress(progress)
          }
        }, 50)
      }).catch((err) => {
        logger.error('Playback failed:', err)
        toast({
          title: "Playback Error",
          description: "Unable to play the audio. Try recording again.",
          variant: "destructive"
        })
      })
    }
  }, [audioUrl, isPlaying])

  // Handle audio ended
  useEffect(() => {
    const audio = audioRef.current
    if (!audio) return

    const handleEnded = () => {
      setIsPlaying(false)
      setPlaybackProgress(0)
      if (playbackIntervalRef.current) {
        clearInterval(playbackIntervalRef.current)
      }
    }

    audio.addEventListener('ended', handleEnded)
    return () => {
      audio.removeEventListener('ended', handleEnded)
      if (playbackIntervalRef.current) {
        clearInterval(playbackIntervalRef.current)
      }
    }
  }, [audioUrl])

  // Handle send voice message
  const handleSend = useCallback(async () => {
    if (!audioBlob) return

    setIsSending(true)
    try {
      await onSendVoice(audioBlob, duration)
      resetRecording()
      setPlaybackProgress(0)
    } catch (err) {
      logger.error('Failed to send voice message:', err)
      toast({
        title: "Send Failed",
        description: "Failed to send voice message. Please try again.",
        variant: "destructive"
      })
    } finally {
      setIsSending(false)
    }
  }, [audioBlob, duration, onSendVoice, resetRecording])

  // Handle delete recording - immediate response
  const handleDelete = useCallback(() => {
    // Stop playback immediately
    if (audioRef.current) {
      audioRef.current.pause()
      audioRef.current.src = ''
    }
    if (playbackIntervalRef.current) {
      clearInterval(playbackIntervalRef.current)
      playbackIntervalRef.current = null
    }
    setIsPlaying(false)
    setPlaybackProgress(0)
    // Reset recording state
    resetRecording()
    onCancel?.()
  }, [resetRecording, onCancel])

  // Not supported state
  if (!isSupported) {
    return (
      <div className={cn("flex items-center gap-2 p-3 text-muted-foreground text-sm", className)}>
        <MicOff className="h-4 w-4" />
        <span>Voice recording not supported</span>
      </div>
    )
  }

  // Recording state - WhatsApp style inline bar
  if (isRecording) {
    return (
      <div className={cn(
        "flex items-center gap-3 p-3 bg-background rounded-lg",
        className
      )}>
        {/* Cancel button */}
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9 rounded-full hover:bg-destructive/10 hover:text-destructive shrink-0"
          onClick={handleCancel}
        >
          <Trash2 className="h-4 w-4" />
        </Button>

        {/* Live waveform visualization - audio level responsive */}
        <div className="flex-1 flex items-center justify-center gap-[2px] h-8 overflow-hidden">
          {Array.from({ length: 40 }).map((_, i) => {
            // Create wave pattern based on position and audio level
            const position = i / 40
            const wave = Math.sin(position * Math.PI * 4 + Date.now() / 200) * 0.3
            // Height is primarily driven by audio level, with minimal base
            const height = isPaused 
              ? 0.15 // Flat when paused
              : Math.max(0.08, audioLevel * (0.6 + wave) + 0.08)
            
            return (
              <div
                key={i}
                className={cn(
                  "w-[4px] rounded-full",
                  isPaused ? "bg-muted-foreground/40" : "bg-primary"
                )}
                style={{
                  height: `${Math.max(4, height * 32)}px`,
                  transition: 'height 50ms ease-out'
                }}
              />
            )
          })}
        </div>

        {/* Duration */}
        <div className="text-sm font-mono font-medium text-foreground min-w-[45px] text-right shrink-0">
          {formatDuration(duration)}
        </div>

        {/* Pause/Resume button */}
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9 rounded-full shrink-0"
          onClick={isPaused ? resumeRecording : pauseRecording}
        >
          {isPaused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
        </Button>

        {/* Stop/Send button */}
        <Button
          size="sm"
          className="rounded-full px-4 gap-2 bg-primary hover:bg-primary/90 shrink-0"
          onClick={handleStopRecording}
        >
          <Square className="h-3 w-3 fill-current" />
          Stop
        </Button>
      </div>
    )
  }

  // Preview state - show recorded audio with playback
  if (audioBlob && audioUrl) {
    return (
      <div className={cn(
        "flex items-center gap-3 p-3 bg-background rounded-lg",
        className
      )}>
        {/* Hidden audio element */}
        <audio ref={audioRef} src={audioUrl} preload="metadata" />

        {/* Delete button */}
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9 rounded-full hover:bg-destructive/10 hover:text-destructive shrink-0"
          onClick={handleDelete}
          disabled={isSending}
        >
          <Trash2 className="h-4 w-4" />
        </Button>

        {/* Play/Pause button */}
        <Button
          variant="outline"
          size="icon"
          className="h-9 w-9 rounded-full shrink-0"
          onClick={handleTogglePlayback}
        >
          {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4 ml-0.5" />}
        </Button>

        {/* Waveform with progress */}
        <div className="flex-1 flex items-center gap-[2px] h-8 overflow-hidden relative">
          {waveformBarsRef.current.map((height, i) => {
            const progressPercent = (i / waveformBarsRef.current.length) * 100
            const isActive = progressPercent <= playbackProgress
            
            return (
              <div
                key={i}
                className={cn(
                  "flex-1 min-w-[3px] max-w-[6px] rounded-full transition-colors duration-100",
                  isActive ? "bg-primary" : "bg-muted-foreground/30"
                )}
                style={{
                  height: `${Math.max(15, height * 100)}%`
                }}
              />
            )
          })}
        </div>

        {/* Duration */}
        <div className="text-sm font-mono text-muted-foreground min-w-[45px] text-right shrink-0">
          {formatDuration(duration)}
        </div>

        {/* Send button */}
        <Button
          size="sm"
          onClick={handleSend}
          disabled={isSending || disabled}
          className="rounded-full px-4 gap-2 shrink-0"
        >
          {isSending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Send className="h-4 w-4" />
          )}
          Send
        </Button>
      </div>
    )
  }

  // Default state - mic button
  const isBlocked = permissionStatus === 'denied' || permissionStatus === 'unavailable'
  
  return (
    <div className={cn("relative inline-flex items-center", className)}>
      <Button
        variant="ghost"
        size="icon"
        className={cn(
          "h-9 w-9 rounded-full transition-all",
          permissionStatus === 'granted' && "hover:bg-primary/10 hover:text-primary",
          isBlocked && "text-muted-foreground opacity-70",
          permissionStatus === 'checking' && "opacity-50",
          disabled && "opacity-50 cursor-not-allowed"
        )}
        onClick={permissionStatus === 'granted' ? handleStartRecording : handleRequestPermission}
        disabled={disabled || permissionStatus === 'checking' || permissionStatus === 'unavailable'}
        title={
          permissionStatus === 'unavailable'
            ? "Microphone not available"
            : permissionStatus === 'denied' 
              ? "Microphone blocked - Click to retry" 
              : permissionStatus === 'granted' 
                ? "Record voice message" 
                : permissionStatus === 'checking'
                  ? "Checking microphone..."
                  : "Enable microphone"
        }
      >
        {permissionStatus === 'checking' ? (
          <Loader2 className="h-5 w-5 animate-spin" />
        ) : isBlocked ? (
          <MicOff className="h-5 w-5" />
        ) : (
          <Mic className="h-5 w-5" />
        )}
      </Button>
    </div>
  )
})

// Compact voice recorder - just the button that triggers recording in the main VoiceRecorder
interface CompactVoiceRecorderProps {
  onSendVoice: (audioBlob: Blob, duration: number) => Promise<void>
  disabled?: boolean
  className?: string
}

export const CompactVoiceRecorder = memo(function CompactVoiceRecorder({
  onSendVoice,
  disabled = false,
  className
}: CompactVoiceRecorderProps) {
  const [isExpanded, setIsExpanded] = useState(false)

  const handleCancel = useCallback(() => {
    setIsExpanded(false)
  }, [])

  const handleSendVoice = useCallback(async (audioBlob: Blob, duration: number) => {
    await onSendVoice(audioBlob, duration)
    setIsExpanded(false)
  }, [onSendVoice])

  if (isExpanded) {
    return (
      <VoiceRecorder
        onSendVoice={handleSendVoice}
        onCancel={handleCancel}
        disabled={disabled}
        className={className}
      />
    )
  }

  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn(
        "h-9 w-9 rounded-full hover:bg-primary/10 hover:text-primary transition-colors",
        disabled && "opacity-50 cursor-not-allowed",
        className
      )}
      onClick={() => setIsExpanded(true)}
      disabled={disabled}
      title="Record voice message"
    >
      <Mic className="h-5 w-5" />
    </Button>
  )
})

export default VoiceRecorder
