import { NextRequest } from "next/server"
import { executeGenericDbQuery } from "@/lib/mongodb"
import Settings from "@/models/Settings"

// SSE endpoint for real-time theme updates
export async function GET(request: NextRequest) {
  // Set up SSE headers
  const headers = {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Cache-Control',
  }

  let isConnected = true
  let intervalId: NodeJS.Timeout

  // Create a readable stream for SSE
  const stream = new ReadableStream({
    start(controller) {
      // Send initial connection event
      controller.enqueue(`data: ${JSON.stringify({ type: 'connected', timestamp: new Date().toISOString() })}\n\n`)

      // Function to send theme updates
      const sendThemeUpdate = async () => {
        if (!isConnected) return

        try {
          // Use cached query for SSE theme updates
          const themeData = await executeGenericDbQuery(async () => {
            const currentThemeSetting = await Settings.findOne({ 
              key: 'theme_variant',
              category: 'appearance',
              isPublic: true 
            }).lean()

            return {
              theme: currentThemeSetting?.value || 'default',
              metadata: {
                updatedBy: (currentThemeSetting?.metadata as any)?.updatedBy || 'system',
                updatedAt: (currentThemeSetting?.metadata as any)?.updatedAt || new Date()
              }
            }
          }, 'sse-themes', 10000) // 10 second cache for SSE

          const themeUpdate = {
            type: 'theme_update',
            theme: themeData.theme,
            timestamp: new Date().toISOString(),
            updatedBy: themeData.metadata.updatedBy,
            updatedAt: themeData.metadata.updatedAt
          }

          // Check if controller is still open before sending
          if (isConnected && controller.desiredSize !== null) {
            try {
              controller.enqueue(`data: ${JSON.stringify(themeUpdate)}\n\n`)
            } catch (controllerError) {
              console.warn('Controller already closed, stopping theme updates')
              isConnected = false
            }
          }
        } catch (error) {
          console.error('Error sending theme update:', error)
          
          // Only try to send error if controller is still open
          if (isConnected && controller.desiredSize !== null) {
            try {
              controller.enqueue(`data: ${JSON.stringify({ type: 'error', message: 'Failed to fetch theme update', timestamp: new Date().toISOString() })}\n\n`)
            } catch (controllerError) {
              console.warn('Controller already closed, cannot send error message')
              isConnected = false
            }
          }
        }
      }

      // Send initial theme state
      sendThemeUpdate()

      // Set up polling every 10 seconds
      intervalId = setInterval(sendThemeUpdate, 10000)

      // Handle client disconnect
      request.signal.addEventListener('abort', () => {
        isConnected = false
        if (intervalId) {
          clearInterval(intervalId)
        }
        controller.close()
      })
    },

    cancel() {
      isConnected = false
      if (intervalId) {
        clearInterval(intervalId)
      }
    }
  })

  return new Response(stream, { headers })
}