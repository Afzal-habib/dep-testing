import { NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery } from "@/lib/mongodb"
import Settings from "@/models/Settings"
import { THEME_VARIANTS, VALID_THEME_VARIANTS } from "@/lib/constants/theme-variants"

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/public/themes - Get current theme (accessible to all authenticated users)
export async function GET(request: NextRequest) {
  try {
    // Set response headers for better caching
    const headers = new Headers({
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=60, s-maxage=60', // 1 minute cache
      'X-Content-Type-Options': 'nosniff'
    })

    // Use cached query with shorter cache for faster response
    const themeData = await executeGenericDbQuery(async () => {
      try {
        // Get current theme setting from database with timeout
        const currentThemeSetting = await Settings.findOne({ 
          key: 'theme_variant',
          category: 'appearance',
          isPublic: true // Only get public settings
        }).lean().maxTimeMS(2000) // 2 second timeout

        const currentTheme = currentThemeSetting?.value || 'default'

        // Validate that the current theme exists in THEME_VARIANTS
        const validTheme = THEME_VARIANTS[currentTheme as keyof typeof THEME_VARIANTS] 
          ? currentTheme 
          : 'default'

        return { currentTheme: validTheme }
      } catch (dbError) {
        console.warn('Database query failed, using default theme:', dbError)
        return { currentTheme: 'default' }
      }
    }, 'public-themes', 15000) // Reduced to 15 second cache for faster updates

    const validTheme = themeData.currentTheme

    // Always ensure the theme exists in THEME_VARIANTS
    const finalTheme = THEME_VARIANTS[validTheme as keyof typeof THEME_VARIANTS] ? validTheme : 'default'

    // Return current theme and variants
    return NextResponse.json({
      success: true,
      data: {
        currentTheme: finalTheme,
        themeConfig: THEME_VARIANTS[finalTheme as keyof typeof THEME_VARIANTS],
        variants: THEME_VARIANTS,
        availableThemes: VALID_THEME_VARIANTS,
        timestamp: new Date().toISOString() // For cache busting
      },
      message: 'Current theme retrieved successfully'
    }, { 
      status: 200,
      headers 
    })

  } catch (error: any) {
    console.error('Error in GET /api/public/themes:', error)
    
    // Always return a valid response to prevent app breaking
    const headers = new Headers({
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=30', // Short cache for errors
      'X-Content-Type-Options': 'nosniff'
    })

    return NextResponse.json({
      success: true,
      data: {
        currentTheme: 'default',
        themeConfig: THEME_VARIANTS.default,
        variants: THEME_VARIANTS,
        availableThemes: VALID_THEME_VARIANTS,
        timestamp: new Date().toISOString()
      },
      message: 'Fallback to default theme due to error',
      fallback: true
    }, { 
      status: 200, // Still return 200 to prevent client errors
      headers 
    })
  }
}