"use client"

import { useState, useRef, useCallback, useEffect } from 'react'

export interface VoiceRecorderState {
  isRecording: boolean
  isPaused: boolean
  duration: number // in seconds
  audioBlob: Blob | null
  audioUrl: string | null
  error: string | null
  isSupported: boolean
  permissionStatus: 'prompt' | 'granted' | 'denied' | 'checking' | 'unavailable'
  audioLevel: number // 0-1 for visualization
}

export interface UseVoiceRecorderReturn extends VoiceRecorderState {
  startRecording: () => Promise<boolean>
  stopRecording: () => Promise<Blob | null>
  pauseRecording: () => void
  resumeRecording: () => void
  cancelRecording: () => void
  resetRecording: () => void
  formatDuration: (seconds: number) => string
  requestPermission: () => Promise<boolean>
}

const MAX_RECORDING_DURATION = 300 // 5 minutes max

/**
 * Professional Voice Recorder Hook - WhatsApp Web Style
 * 
 * Features:
 * - Proper permission handling with real-time status
 * - Audio level visualization
 * - Pause/Resume support
 * - Auto-stop at max duration
 * - Proper cleanup and error handling
 */
export function useVoiceRecorder(): UseVoiceRecorderReturn {
  const [state, setState] = useState<VoiceRecorderState>({
    isRecording: false,
    isPaused: false,
    duration: 0,
    audioBlob: null,
    audioUrl: null,
    error: null,
    isSupported: false,
    permissionStatus: 'checking',
    audioLevel: 0
  })

  // Refs for recording management
  const mediaRecorderRef = useRef<MediaRecorder | null>(null)
  const audioChunksRef = useRef<Blob[]>([])
  const streamRef = useRef<MediaStream | null>(null)
  const timerRef = useRef<NodeJS.Timeout | null>(null)
  const startTimeRef = useRef<number>(0)
  const pausedDurationRef = useRef<number>(0)
  const analyserRef = useRef<AnalyserNode | null>(null)
  const audioContextRef = useRef<AudioContext | null>(null)
  const animationFrameRef = useRef<number | null>(null)
  const audioBlobRef = useRef<Blob | null>(null)

  // Check browser support on mount
  useEffect(() => {
    const checkSupport = () => {
      if (typeof window === 'undefined') return false
      
      const hasMediaRecorder = 'MediaRecorder' in window
      const hasMediaDevices = 'mediaDevices' in navigator && 'getUserMedia' in navigator.mediaDevices
      const isSecureContext = window.isSecureContext || 
                              window.location.protocol === 'https:' || 
                              window.location.hostname === 'localhost' ||
                              window.location.hostname === '127.0.0.1' ||
                              window.location.hostname.startsWith('192.168.') ||
                              window.location.hostname.startsWith('10.')
      
      return hasMediaRecorder && hasMediaDevices && isSecureContext
    }

    const isSupported = checkSupport()
    setState(prev => ({ ...prev, isSupported }))

    if (isSupported) {
      checkPermissionStatus()
    } else {
      setState(prev => ({ 
        ...prev, 
        permissionStatus: 'denied', 
        error: 'Voice recording not supported in this browser or requires HTTPS' 
      }))
    }
  }, [])

  // Cleanup function
  const cleanup = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
    if (animationFrameRef.current) {
      cancelAnimationFrame(animationFrameRef.current)
      animationFrameRef.current = null
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(track => track.stop())
      streamRef.current = null
    }
    if (audioContextRef.current && audioContextRef.current.state !== 'closed') {
      audioContextRef.current.close().catch(() => {})
      audioContextRef.current = null
    }
  }, [])

  // Clean up on unmount
  useEffect(() => {
    return () => {
      cleanup()
      if (state.audioUrl) {
        URL.revokeObjectURL(state.audioUrl)
      }
    }
  }, [cleanup, state.audioUrl])

  // Check permission status without triggering prompt
  const checkPermissionStatus = useCallback(async () => {
    try {
      if (navigator.permissions) {
        try {
          const result = await navigator.permissions.query({ name: 'microphone' as PermissionName })
          
          const mapState = (state: PermissionState): 'prompt' | 'granted' | 'denied' => {
            if (state === 'granted') return 'granted'
            if (state === 'denied') return 'denied'
            return 'prompt'
          }
          
          setState(prev => ({ ...prev, permissionStatus: mapState(result.state) }))
          
          result.onchange = () => {
            setState(prev => ({ ...prev, permissionStatus: mapState(result.state) }))
          }
          
          return
        } catch {
          // Permissions API not supported for microphone
        }
      }
      
      setState(prev => ({ ...prev, permissionStatus: 'prompt' }))
    } catch (error) {
      console.error('Failed to check permission status:', error)
      setState(prev => ({ ...prev, permissionStatus: 'prompt' }))
    }
  }, [])

  // Format duration as MM:SS
  const formatDuration = useCallback((seconds: number): string => {
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`
  }, [])

  // Get supported MIME type
  const getSupportedMimeType = useCallback((): string => {
    const mimeTypes = [
      'audio/webm;codecs=opus',
      'audio/webm',
      'audio/ogg;codecs=opus',
      'audio/ogg',
      'audio/mp4',
      'audio/mpeg'
    ]
    
    for (const mimeType of mimeTypes) {
      if (MediaRecorder.isTypeSupported(mimeType)) {
        return mimeType
      }
    }
    
    return ''
  }, [])

  // Request microphone permission
  const requestPermission = useCallback(async (): Promise<boolean> => {
    if (!state.isSupported) {
      setState(prev => ({ 
        ...prev, 
        error: 'Voice recording is not supported in this browser',
        permissionStatus: 'unavailable'
      }))
      return false
    }

    setState(prev => ({ ...prev, error: null, permissionStatus: 'checking' }))

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
          channelCount: 1,
          sampleRate: { ideal: 48000 }
        }
      })

      stream.getTracks().forEach(track => track.stop())
      
      setState(prev => ({ 
        ...prev, 
        permissionStatus: 'granted', 
        error: null 
      }))
      
      return true
    } catch (error: unknown) {
      const err = error as Error & { name?: string }
      console.error('Microphone permission error:', err)
      
      let errorMessage = 'Unable to access microphone'
      let permissionStatus: 'denied' | 'prompt' | 'unavailable' = 'denied'

      const errorName = err?.name || ''
      const errorMsg = err?.message?.toLowerCase() || ''

      switch (errorName) {
        case 'NotAllowedError':
        case 'PermissionDeniedError':
          // Check if it's a policy violation vs user denial
          if (errorMsg.includes('policy') || errorMsg.includes('not allowed in this document')) {
            errorMessage = 'Microphone blocked by browser policy. Please refresh the page and try again.'
            permissionStatus = 'unavailable'
          } else {
            errorMessage = 'Microphone access was denied. Click the lock icon in your browser\'s address bar to allow microphone access.'
            permissionStatus = 'denied'
          }
          break
        case 'NotFoundError':
        case 'DevicesNotFoundError':
          errorMessage = 'No microphone found. Please connect a microphone and try again.'
          permissionStatus = 'prompt'
          break
        case 'NotReadableError':
        case 'TrackStartError':
          errorMessage = 'Microphone is being used by another application. Please close other apps and try again.'
          permissionStatus = 'prompt'
          break
        case 'OverconstrainedError':
          try {
            const fallbackStream = await navigator.mediaDevices.getUserMedia({ audio: true })
            fallbackStream.getTracks().forEach(track => track.stop())
            setState(prev => ({ ...prev, permissionStatus: 'granted', error: null }))
            return true
          } catch {
            errorMessage = 'Microphone does not support required audio format.'
          }
          break
        case 'SecurityError':
          errorMessage = 'Voice recording requires a secure connection (HTTPS).'
          permissionStatus = 'unavailable'
          break
        case 'AbortError':
          errorMessage = 'Microphone access was interrupted. Please try again.'
          permissionStatus = 'prompt'
          break
        default:
          errorMessage = `Microphone error: ${err?.message || 'Unknown error'}`
      }

      setState(prev => ({ 
        ...prev, 
        error: errorMessage, 
        permissionStatus 
      }))
      
      return false
    }
  }, [state.isSupported])

  // Update audio level for visualization
  const updateAudioLevel = useCallback(() => {
    if (!analyserRef.current) return

    const dataArray = new Uint8Array(analyserRef.current.frequencyBinCount)
    analyserRef.current.getByteFrequencyData(dataArray)

    const average = dataArray.reduce((sum, value) => sum + value, 0) / dataArray.length
    const normalizedLevel = Math.min(1, average / 128)

    setState(prev => {
      if (prev.isRecording && !prev.isPaused) {
        animationFrameRef.current = requestAnimationFrame(updateAudioLevel)
      }
      return { ...prev, audioLevel: normalizedLevel }
    })
  }, [])

  // Start recording
  const startRecording = useCallback(async (): Promise<boolean> => {
    if (!state.isSupported) {
      setState(prev => ({ ...prev, error: 'Voice recording is not supported' }))
      return false
    }

    // Clear any previous audio URL
    if (state.audioUrl) {
      URL.revokeObjectURL(state.audioUrl)
    }

    setState(prev => ({ 
      ...prev, 
      error: null, 
      audioBlob: null, 
      audioUrl: null,
      duration: 0,
      audioLevel: 0
    }))
    audioBlobRef.current = null

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
          channelCount: 1,
          sampleRate: { ideal: 48000 }
        }
      })

      streamRef.current = stream
      setState(prev => ({ ...prev, permissionStatus: 'granted' }))

      // Set up audio analysis for level visualization
      try {
        audioContextRef.current = new (window.AudioContext || (window as any).webkitAudioContext)()
        analyserRef.current = audioContextRef.current.createAnalyser()
        analyserRef.current.fftSize = 256
        
        const source = audioContextRef.current.createMediaStreamSource(stream)
        source.connect(analyserRef.current)
      } catch (audioContextError) {
        console.warn('Audio context setup failed, visualization disabled:', audioContextError)
      }

      const mimeType = getSupportedMimeType()
      const mediaRecorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined)
      mediaRecorderRef.current = mediaRecorder
      audioChunksRef.current = []

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          audioChunksRef.current.push(event.data)
        }
      }

      mediaRecorder.onerror = (event: any) => {
        console.error('MediaRecorder error:', event.error)
        setState(prev => ({ 
          ...prev, 
          error: 'Recording failed unexpectedly',
          isRecording: false 
        }))
        cleanup()
      }

      mediaRecorder.onstop = () => {
        const mimeType = mediaRecorder.mimeType || 'audio/webm'
        const audioBlob = new Blob(audioChunksRef.current, { type: mimeType })
        const audioUrl = URL.createObjectURL(audioBlob)
        audioBlobRef.current = audioBlob

        // Stop stream tracks
        if (streamRef.current) {
          streamRef.current.getTracks().forEach(track => track.stop())
          streamRef.current = null
        }

        // Close audio context
        if (audioContextRef.current && audioContextRef.current.state !== 'closed') {
          audioContextRef.current.close().catch(() => {})
          audioContextRef.current = null
        }

        setState(prev => ({
          ...prev,
          isRecording: false,
          isPaused: false,
          audioBlob,
          audioUrl,
          audioLevel: 0
        }))
      }

      mediaRecorder.start(100)
      startTimeRef.current = Date.now()
      pausedDurationRef.current = 0

      timerRef.current = setInterval(() => {
        const elapsed = (Date.now() - startTimeRef.current - pausedDurationRef.current) / 1000
        
        if (elapsed >= MAX_RECORDING_DURATION) {
          if (mediaRecorderRef.current?.state === 'recording') {
            mediaRecorderRef.current.stop()
          }
          if (timerRef.current) {
            clearInterval(timerRef.current)
            timerRef.current = null
          }
          setState(prev => ({ ...prev, duration: MAX_RECORDING_DURATION }))
        } else {
          setState(prev => ({ ...prev, duration: elapsed }))
        }
      }, 100)

      if (analyserRef.current) {
        animationFrameRef.current = requestAnimationFrame(updateAudioLevel)
      }

      setState(prev => ({
        ...prev,
        isRecording: true,
        isPaused: false,
        duration: 0,
        error: null
      }))

      return true
    } catch (error: any) {
      console.error('Failed to start recording:', error)
      
      let errorMessage = 'Failed to start recording'
      let permissionStatus: 'denied' | 'prompt' = 'prompt'

      switch (error.name) {
        case 'NotAllowedError':
        case 'PermissionDeniedError':
          errorMessage = 'Microphone access denied. Please allow microphone access to record.'
          permissionStatus = 'denied'
          break
        case 'NotFoundError':
          errorMessage = 'No microphone found. Please connect a microphone.'
          break
        case 'NotReadableError':
          errorMessage = 'Microphone is busy. Please close other apps using it.'
          break
        default:
          errorMessage = error.message || 'Failed to start recording'
      }

      setState(prev => ({ 
        ...prev, 
        error: errorMessage,
        permissionStatus,
        isRecording: false
      }))
      
      cleanup()
      return false
    }
  }, [state.isSupported, state.audioUrl, getSupportedMimeType, updateAudioLevel, cleanup])

  // Stop recording and return audio blob
  const stopRecording = useCallback((): Promise<Blob | null> => {
    return new Promise((resolve) => {
      if (timerRef.current) {
        clearInterval(timerRef.current)
        timerRef.current = null
      }

      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current)
        animationFrameRef.current = null
      }

      const mediaRecorder = mediaRecorderRef.current
      if (!mediaRecorder || mediaRecorder.state === 'inactive') {
        setState(prev => ({ ...prev, isRecording: false, isPaused: false, audioLevel: 0 }))
        resolve(audioBlobRef.current)
        return
      }

      const originalOnstop = mediaRecorder.onstop
      mediaRecorder.onstop = (event) => {
        if (originalOnstop) {
          originalOnstop.call(mediaRecorder, event)
        }
        
        // Small delay to ensure state is updated
        setTimeout(() => {
          resolve(audioBlobRef.current)
        }, 50)
      }

      mediaRecorder.stop()
    })
  }, [])

  // Pause recording - immediate UI response
  const pauseRecording = useCallback(() => {
    // Update state FIRST for immediate UI feedback
    setState(prev => ({ ...prev, isPaused: true, audioLevel: 0 }))
    
    // Then pause the recorder
    const mediaRecorder = mediaRecorderRef.current
    if (mediaRecorder && mediaRecorder.state === 'recording') {
      try { mediaRecorder.pause() } catch {}
      pausedDurationRef.current = Date.now() - startTimeRef.current - (state.duration * 1000)
    }
    
    if (animationFrameRef.current) {
      cancelAnimationFrame(animationFrameRef.current)
      animationFrameRef.current = null
    }
  }, [state.duration])

  // Resume recording - immediate UI response
  const resumeRecording = useCallback(() => {
    // Update state FIRST for immediate UI feedback
    setState(prev => ({ ...prev, isPaused: false }))
    
    const mediaRecorder = mediaRecorderRef.current
    if (mediaRecorder && mediaRecorder.state === 'paused') {
      try { mediaRecorder.resume() } catch {}
      startTimeRef.current = Date.now() - (state.duration * 1000)
      
      if (analyserRef.current) {
        animationFrameRef.current = requestAnimationFrame(updateAudioLevel)
      }
    }
  }, [state.duration, updateAudioLevel])

  // Cancel recording without saving - immediate UI response
  const cancelRecording = useCallback(() => {
    // Update state FIRST for immediate UI response
    setState(prev => {
      if (prev.audioUrl) {
        URL.revokeObjectURL(prev.audioUrl)
      }
      return {
        ...prev,
        isRecording: false,
        isPaused: false,
        duration: 0,
        audioBlob: null,
        audioUrl: null,
        error: null,
        audioLevel: 0
      }
    })

    // Then cleanup resources
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }

    if (animationFrameRef.current) {
      cancelAnimationFrame(animationFrameRef.current)
      animationFrameRef.current = null
    }

    const mediaRecorder = mediaRecorderRef.current
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
      mediaRecorder.onstop = null
      try { mediaRecorder.stop() } catch {}
    }
    mediaRecorderRef.current = null

    if (streamRef.current) {
      streamRef.current.getTracks().forEach(track => {
        try { track.stop() } catch {}
      })
      streamRef.current = null
    }

    if (audioContextRef.current && audioContextRef.current.state !== 'closed') {
      audioContextRef.current.close().catch(() => {})
      audioContextRef.current = null
    }

    audioChunksRef.current = []
    audioBlobRef.current = null
  }, [])

  // Reset to initial state (after sending)
  const resetRecording = useCallback(() => {
    audioBlobRef.current = null
    
    setState(prev => {
      if (prev.audioUrl) {
        URL.revokeObjectURL(prev.audioUrl)
      }
      return {
        ...prev,
        duration: 0,
        audioBlob: null,
        audioUrl: null,
        error: null,
        audioLevel: 0
      }
    })
  }, [])

  return {
    ...state,
    startRecording,
    stopRecording,
    pauseRecording,
    resumeRecording,
    cancelRecording,
    resetRecording,
    formatDuration,
    requestPermission
  }
}

export default useVoiceRecorder
