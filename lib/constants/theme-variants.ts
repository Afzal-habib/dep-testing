// Centralized theme variants configuration
// This is the single source of truth for all theme variants

export interface ThemeColors {
  primary: string
  'primary-foreground': string
  secondary: string
  'secondary-foreground': string
  accent: string
  'accent-foreground': string
  muted: string
  'muted-foreground': string
  background: string
  foreground: string
  card: string
  'card-foreground': string
  border: string
  input: string
  ring: string
  destructive: string
  'destructive-foreground': string
  'sidebar-background': string
  'sidebar-foreground': string
  'sidebar-primary': string
  'sidebar-primary-foreground': string
  'sidebar-accent': string
  'sidebar-accent-foreground': string
  'sidebar-border': string
  'sidebar-ring': string
}

export interface ThemeVariant {
  name: string
  description: string
  light: ThemeColors
  dark: ThemeColors
}


export const THEME_VARIANTS: Record<string, ThemeVariant> = {
  default: {
    name: 'Default',
    description: 'Pink primary with modern design',
    light: {
      primary: '326 100% 50%',
      'primary-foreground': '0 0% 100%',
      secondary: '240 4.8% 95.9%',
      'secondary-foreground': '240 5.9% 10%',
      accent: '326 100% 50%',
      'accent-foreground': '0 0% 100%',
      muted: '240 4.8% 95.9%',
      'muted-foreground': '240 3.8% 46.1%',
      background: '0 0% 100%',
      foreground: '240 10% 3.9%',
      card: '0 0% 100%',
      'card-foreground': '240 10% 3.9%',
      border: '240 5.9% 90%',
      input: '240 5.9% 90%',
      ring: '326 100% 50%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '0 0% 98%',
      'sidebar-foreground': '240 10% 3.9%',
      'sidebar-primary': '326 100% 50%',
      'sidebar-primary-foreground': '0 0% 100%',
      'sidebar-accent': '240 4.8% 95.9%',
      'sidebar-accent-foreground': '240 5.9% 10%',
      'sidebar-border': '240 5.9% 90%',
      'sidebar-ring': '326 100% 50%'
    },
    dark: {
      primary: '326 100% 50%',
      'primary-foreground': '0 0% 98%',
      secondary: '240 3.7% 15.9%',
      'secondary-foreground': '0 0% 98%',
      accent: '326 100% 50%',
      'accent-foreground': '0 0% 98%',
      muted: '240 3.7% 15.9%',
      'muted-foreground': '240 5% 64.9%',
      background: '240 10% 3.9%',
      foreground: '0 0% 98%',
      card: '240 10% 3.9%',
      'card-foreground': '0 0% 98%',
      border: '240 3.7% 15.9%',
      input: '240 3.7% 15.9%',
      ring: '326 100% 50%',
      destructive: '0 62.8% 30.6%',
      'destructive-foreground': '0 0% 98%',
      'sidebar-background': '240 10% 3.9%',
      'sidebar-foreground': '0 0% 98%',
      'sidebar-primary': '326 100% 50%',
      'sidebar-primary-foreground': '0 0% 98%',
      'sidebar-accent': '240 3.7% 15.9%',
      'sidebar-accent-foreground': '0 0% 98%',
      'sidebar-border': '240 3.7% 15.9%',
      'sidebar-ring': '326 100% 50%'
    }
  },
   coral: {
    name: 'Coral Red',
    description: 'Vibrant coral and red tones with professional dark styling',
    light: {
      primary: '0 72% 58%',
      'primary-foreground': '0 0% 100%',
      secondary: '0 20% 90%',
      'secondary-foreground': '0 20% 15%',
      accent: '0 80% 60%',
      'accent-foreground': '0 0% 100%',
      muted: '0 15% 92%',
      'muted-foreground': '0 10% 45%',
      background: '0 0% 98%',
      foreground: '0 20% 8%',
      card: '0 0% 100%',
      'card-foreground': '0 20% 8%',
      border: '0 15% 88%',
      input: '0 15% 88%',
      ring: '0 72% 58%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '0 10% 96%',
      'sidebar-foreground': '0 20% 8%',
      'sidebar-primary': '0 72% 58%',
      'sidebar-primary-foreground': '0 0% 100%',
      'sidebar-accent': '0 15% 92%',
      'sidebar-accent-foreground': '0 20% 15%',
      'sidebar-border': '0 15% 88%',
      'sidebar-ring': '0 72% 58%'
    },
    dark: {
      primary: '0 72% 58%',
      'primary-foreground': '0 0% 100%',
      secondary: '220 25% 20%',
      'secondary-foreground': '0 20% 85%',
      accent: '0 80% 60%',
      'accent-foreground': '0 0% 100%',
      muted: '220 25% 18%',
      'muted-foreground': '0 15% 65%',
      background: '220 40% 8%',
      foreground: '0 10% 95%',
      card: '220 35% 12%',
      'card-foreground': '0 10% 95%',
      border: '220 25% 18%',
      input: '220 25% 18%',
      ring: '0 72% 58%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '220 40% 8%',
      'sidebar-foreground': '0 10% 95%',
      'sidebar-primary': '0 72% 58%',
      'sidebar-primary-foreground': '0 0% 100%',
      'sidebar-accent': '220 25% 18%',
      'sidebar-accent-foreground': '0 20% 85%',
      'sidebar-border': '220 25% 15%',
      'sidebar-ring': '0 72% 58%'
    }
  },
  ocean: {
    name: 'Ocean Blue',
    description: 'Cool blue tones with ocean-inspired palette',
    light: {
      primary: '207 89% 54%',
      'primary-foreground': '0 0% 100%',
      secondary: '213 27% 84%',
      'secondary-foreground': '213 27% 20%',
      accent: '199 89% 48%',
      'accent-foreground': '0 0% 100%',
      muted: '213 27% 84%',
      'muted-foreground': '213 17% 46%',
      background: '0 0% 100%',
      foreground: '213 27% 8%',
      card: '0 0% 100%',
      'card-foreground': '213 27% 8%',
      border: '213 27% 84%',
      input: '213 27% 84%',
      ring: '207 89% 54%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '213 100% 97%',
      'sidebar-foreground': '213 27% 8%',
      'sidebar-primary': '207 89% 54%',
      'sidebar-primary-foreground': '0 0% 100%',
      'sidebar-accent': '213 27% 90%',
      'sidebar-accent-foreground': '213 27% 20%',
      'sidebar-border': '213 27% 84%',
      'sidebar-ring': '207 89% 54%'
    },
    dark: {
      primary: '207 89% 54%',
      'primary-foreground': '213 27% 8%',
      secondary: '213 27% 16%',
      'secondary-foreground': '213 27% 84%',
      accent: '199 89% 48%',
      'accent-foreground': '213 27% 8%',
      muted: '213 27% 16%',
      'muted-foreground': '213 17% 60%',
      background: '213 50% 5%',
      foreground: '213 27% 94%',
      card: '213 50% 5%',
      'card-foreground': '213 27% 94%',
      border: '213 27% 16%',
      input: '213 27% 16%',
      ring: '207 89% 54%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '213 50% 5%',
      'sidebar-foreground': '213 27% 94%',
      'sidebar-primary': '207 89% 54%',
      'sidebar-primary-foreground': '213 27% 8%',
      'sidebar-accent': '213 27% 16%',
      'sidebar-accent-foreground': '213 27% 84%',
      'sidebar-border': '213 27% 16%',
      'sidebar-ring': '207 89% 54%'
    }
  },
  forest: {
    name: 'Forest Green',
    description: 'Natural green tones with earthy accents',
    light: {
      primary: '142 76% 36%',
      'primary-foreground': '0 0% 100%',
      secondary: '138 23% 85%',
      'secondary-foreground': '138 23% 20%',
      accent: '134 76% 31%',
      'accent-foreground': '0 0% 100%',
      muted: '138 23% 85%',
      'muted-foreground': '138 13% 46%',
      background: '0 0% 100%',
      foreground: '138 23% 8%',
      card: '0 0% 100%',
      'card-foreground': '138 23% 8%',
      border: '138 23% 85%',
      input: '138 23% 85%',
      ring: '142 76% 36%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '138 40% 97%',
      'sidebar-foreground': '138 23% 8%',
      'sidebar-primary': '142 76% 36%',
      'sidebar-primary-foreground': '0 0% 100%',
      'sidebar-accent': '138 23% 90%',
      'sidebar-accent-foreground': '138 23% 20%',
      'sidebar-border': '138 23% 85%',
      'sidebar-ring': '142 76% 36%'
    },
    dark: {
      primary: '142 76% 36%',
      'primary-foreground': '138 23% 8%',
      secondary: '138 23% 16%',
      'secondary-foreground': '138 23% 85%',
      accent: '134 76% 31%',
      'accent-foreground': '138 23% 8%',
      muted: '138 23% 16%',
      'muted-foreground': '138 13% 60%',
      background: '138 40% 4%',
      foreground: '138 23% 94%',
      card: '138 40% 4%',
      'card-foreground': '138 23% 94%',
      border: '138 23% 16%',
      input: '138 23% 16%',
      ring: '142 76% 36%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '138 40% 4%',
      'sidebar-foreground': '138 23% 94%',
      'sidebar-primary': '142 76% 36%',
      'sidebar-primary-foreground': '138 23% 8%',
      'sidebar-accent': '138 23% 16%',
      'sidebar-accent-foreground': '138 23% 85%',
      'sidebar-border': '138 23% 16%',
      'sidebar-ring': '142 76% 36%'
    }
  },
  sunset: {
    name: 'Sunset Orange',
    description: 'Warm orange and red tones inspired by sunset',
    light: {
      primary: '25 95% 53%',
      'primary-foreground': '0 0% 100%',
      secondary: '25 25% 85%',
      'secondary-foreground': '25 25% 20%',
      accent: '20 95% 48%',
      'accent-foreground': '0 0% 100%',
      muted: '25 25% 85%',
      'muted-foreground': '25 15% 46%',
      background: '0 0% 100%',
      foreground: '25 25% 8%',
      card: '0 0% 100%',
      'card-foreground': '25 25% 8%',
      border: '25 25% 85%',
      input: '25 25% 85%',
      ring: '25 95% 53%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '25 50% 97%',
      'sidebar-foreground': '25 25% 8%',
      'sidebar-primary': '25 95% 53%',
      'sidebar-primary-foreground': '0 0% 100%',
      'sidebar-accent': '25 25% 90%',
      'sidebar-accent-foreground': '25 25% 20%',
      'sidebar-border': '25 25% 85%',
      'sidebar-ring': '25 95% 53%'
    },
    dark: {
      primary: '25 95% 53%',
      'primary-foreground': '25 25% 8%',
      secondary: '25 25% 16%',
      'secondary-foreground': '25 25% 85%',
      accent: '20 95% 48%',
      'accent-foreground': '25 25% 8%',
      muted: '25 25% 16%',
      'muted-foreground': '25 15% 60%',
      background: '25 40% 4%',
      foreground: '25 25% 94%',
      card: '25 40% 4%',
      'card-foreground': '25 25% 94%',
      border: '25 25% 16%',
      input: '25 25% 16%',
      ring: '25 95% 53%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '25 40% 4%',
      'sidebar-foreground': '25 25% 94%',
      'sidebar-primary': '25 95% 53%',
      'sidebar-primary-foreground': '25 25% 8%',
      'sidebar-accent': '25 25% 16%',
      'sidebar-accent-foreground': '25 25% 85%',
      'sidebar-border': '25 25% 16%',
      'sidebar-ring': '25 95% 53%'
    }
  },
  amber: {
    name: 'Amber Dashboard',
    description: 'Warm amber and orange tones inspired by professional dashboards',
    light: {
      primary: '43 96% 56%',
      'primary-foreground': '0 0% 100%',
      secondary: '43 30% 85%',
      'secondary-foreground': '43 30% 20%',
      accent: '38 92% 50%',
      'accent-foreground': '0 0% 100%',
      muted: '43 30% 85%',
      'muted-foreground': '43 20% 46%',
      background: '0 0% 100%',
      foreground: '43 30% 8%',
      card: '0 0% 100%',
      'card-foreground': '43 30% 8%',
      border: '43 30% 85%',
      input: '43 30% 85%',
      ring: '43 96% 56%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '43 50% 97%',
      'sidebar-foreground': '43 30% 8%',
      'sidebar-primary': '43 96% 56%',
      'sidebar-primary-foreground': '0 0% 100%',
      'sidebar-accent': '43 30% 90%',
      'sidebar-accent-foreground': '43 30% 20%',
      'sidebar-border': '43 30% 85%',
      'sidebar-ring': '43 96% 56%'
    },
    dark: {
      primary: '43 96% 56%',
      'primary-foreground': '220 26% 14%',
      secondary: '220 26% 18%',
      'secondary-foreground': '43 30% 85%',
      accent: '38 92% 50%',
      'accent-foreground': '220 26% 14%',
      muted: '220 26% 18%',
      'muted-foreground': '43 20% 60%',
      background: '220 26% 14%',
      foreground: '43 30% 94%',
      card: '220 26% 18%',
      'card-foreground': '43 30% 94%',
      border: '220 26% 25%',
      input: '220 26% 25%',
      ring: '43 96% 56%',
      destructive: '0 84% 60%',
      'destructive-foreground': '0 0% 100%',
      'sidebar-background': '220 26% 14%',
      'sidebar-foreground': '43 30% 94%',
      'sidebar-primary': '43 96% 56%',
      'sidebar-primary-foreground': '220 26% 14%',
      'sidebar-accent': '220 26% 18%',
      'sidebar-accent-foreground': '43 30% 85%',
      'sidebar-border': '220 26% 25%',
      'sidebar-ring': '43 96% 56%'
    }
  }
}

// Helper functions
export const getThemeVariantKeys = () => Object.keys(THEME_VARIANTS)
export const isValidThemeVariant = (variant: string): boolean => variant in THEME_VARIANTS
export const getThemeVariant = (variant: string): ThemeVariant | null => THEME_VARIANTS[variant] || null
export const getDefaultTheme = (): ThemeVariant => THEME_VARIANTS.default

// Export for validation schema
export const VALID_THEME_VARIANTS = getThemeVariantKeys()