"use client"

import Image from "next/image"
import { cn } from "@/lib/utils"

interface ProfessionalLoaderProps {
  size?: "sm" | "md" | "lg"
  className?: string
  showText?: boolean
  text?: string
}

export function ProfessionalLoader({ 
  size = "md", 
  className,
  showText = true,
  text = "Loading..."
}: ProfessionalLoaderProps) {
  const containerSizes = {
    sm: "w-28 h-28",
    md: "w-36 h-36",
    lg: "w-48 h-48"
  }

  const logoSizes = {
    sm: { width: 52, height: 52 },
    md: { width: 72, height: 72 },
    lg: { width: 96, height: 96 }
  }

  return (
    <div className={cn("flex flex-col items-center justify-center gap-5", className)}>
      {/* Ultra-sophisticated multi-layer loader */}
      <div className={cn("relative flex items-center justify-center", containerSizes[size])}>
        
        {/* Outermost glow field */}
        <div 
        />
        
        {/* Primary orbital ring */}
        <div 
          className="absolute inset-0 rounded-full"
          style={{ 
            background: `conic-gradient(from 0deg, 
              hsl(var(--primary)) 0deg, 
              hsl(var(--primary)/0.8) 30deg,
              hsl(var(--primary)/0.4) 60deg,
              transparent 90deg,
              hsl(var(--primary)/0.2) 120deg,
              hsl(var(--primary)/0.6) 150deg,
              hsl(var(--primary)) 180deg,
              hsl(var(--primary)/0.8) 210deg,
              hsl(var(--primary)/0.4) 240deg,
              transparent 270deg,
              hsl(var(--primary)/0.2) 300deg,
              hsl(var(--primary)/0.6) 330deg,
              hsl(var(--primary)) 360deg)`,
            animation: 'orbital-spin 3s linear infinite',
            filter: 'blur(0.5px)',
          }}
        />
        
        {/* Secondary counter-orbital */}
        <div 
          className="absolute inset-2 rounded-full border-2"
          style={{ 
            borderImage: `conic-gradient(from 180deg, 
              transparent 0deg,
              hsl(var(--primary)/0.6) 45deg,
              hsl(var(--primary)) 90deg,
              hsl(var(--primary)/0.6) 135deg,
              transparent 180deg,
              hsl(var(--primary)/0.3) 225deg,
              hsl(var(--primary)/0.8) 270deg,
              hsl(var(--primary)/0.3) 315deg,
              transparent 360deg) 1`,
            animation: 'counter-orbital 4s linear infinite reverse',
            filter: 'drop-shadow(0 0 8px hsl(var(--primary)/0.4))'
          }}
        />
        
        {/* Tertiary inner ring with particles */}
        <div 
          className="absolute inset-3 rounded-full border"
          style={{
            borderColor: 'hsl(var(--primary)/0.3)',
            animation: 'particle-dance 5s ease-in-out infinite',
            boxShadow: `inset 0 0 15px hsl(var(--primary)/0.1)`
          }}
        />
        
        {/* Logo pedestal with elevation */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div 
            className="relative p-3 rounded-full bg-background/80 backdrop-blur-sm"
            style={{
              boxShadow: `
                0 8px 32px hsl(var(--primary)/0.15),
                inset 0 1px 0 hsl(var(--primary)/0.1),
                0 0 0 1px hsl(var(--primary)/0.05)
              `,
              animation: 'logo-float 6s ease-in-out infinite'
            }}
          >
            {/* Logo ambient glow */}
            <div 
              className="absolute inset-0 rounded-full opacity-60 blur-md"
              style={{
                background: `radial-gradient(circle, hsl(var(--primary)/0.2) 0%, transparent 70%)`
              }}
            />
            
            {/* Main logo with premium treatment */}
            <div className="relative z-10">
              <Image
                src="/digi-era-logo.webp"
                alt="DIGI ERA PRO"
                width={logoSizes[size].width}
                height={logoSizes[size].height}
                className="object-contain filter drop-shadow-lg"
                style={{
                  filter: 'drop-shadow(0 4px 8px hsl(var(--primary)/0.2)) drop-shadow(0 0 12px hsl(var(--primary)/0.1))',
                  // width: 'auto',
                  // height: 'auto'
                }}
                priority
              />
            </div>
          </div>
        </div>
      </div>

      {/* Premium loading interface */}
      {showText && (
        <div className="flex flex-col items-center">
          {/* Elegant title with letter spacing */}
          <div className="text-center">
            <div className="text-xs text-muted-foreground font-medium tracking-widest uppercase">
              Please Wait
            </div>
          </div>
          
          {/* Sophisticated progress visualization */}
          <div className="flex flex-col items-center gap-4">
            {/* Animated progress arc */}
            <div className="relative w-24 h-4 overflow-hidden">
              <div 
                className="absolute bottom-0 w-full h-1 rounded-full"
                style={{
                  background: `linear-gradient(90deg, 
                    hsl(var(--primary)) 0%, 
                    hsl(var(--primary)/0.8) 25%,
                    hsl(var(--primary)/0.4) 50%,
                    hsl(var(--primary)/0.8) 75%,
                    hsl(var(--primary)) 100%)`,
                  animation: 'progress-wave 2s ease-in-out infinite'
                }}
              />
            </div>
            
            {/* Enhanced dot matrix */}
            <div className="flex space-x-3">
              <div 
                className="w-3 h-3 rounded-full bg-gradient-to-br from-primary to-primary/70"
                style={{ 
                  animation: 'matrix-pulse 1.8s ease-in-out infinite',
                  animationDelay: '0ms',
                  boxShadow: `0 0 8px hsl(var(--primary)/0.6)`
                }} 
              />
              <div 
                className="w-3 h-3 rounded-full bg-gradient-to-br from-primary/80 to-primary/50"
                style={{ 
                  animation: 'matrix-pulse 1.8s ease-in-out infinite',
                  animationDelay: '300ms',
                  boxShadow: `0 0 8px hsl(var(--primary)/0.4)`
                }} 
              />
              <div 
                className="w-3 h-3 rounded-full bg-gradient-to-br from-primary/60 to-primary/40"
                style={{ 
                  animation: 'matrix-pulse 1.8s ease-in-out infinite',
                  animationDelay: '600ms',
                  boxShadow: `0 0 8px hsl(var(--primary)/0.3)`
                }} 
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Alternative spinner-only version without logo for smaller spaces
export function CompactLoader({ className }: { className?: string }) {
  return (
    <div className={cn("relative w-8 h-8", className)}>
      <div className="absolute inset-0 rounded-full border-2 border-primary/20 border-t-primary animate-spin" />
    </div>
  )
}