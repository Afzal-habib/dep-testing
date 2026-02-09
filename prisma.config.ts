import { defineConfig } from 'prisma/config'
import { config } from 'dotenv'

// Load environment variables
const result = config({ path: '.env.local' })

// Note: Using type assertion to support newer Prisma config options
// that may not be in the current type definitions
export default defineConfig({
  schema: './prisma/schema.prisma',
  datasource: {
    url: process.env.DATABASE_URL!,
  },
} as Parameters<typeof defineConfig>[0])


