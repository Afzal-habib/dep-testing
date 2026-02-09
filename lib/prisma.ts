import { PrismaClient } from '.prisma/client'
import { Pool } from 'pg'
import { PrismaPg } from '@prisma/adapter-pg'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
  pool: Pool | undefined
}

// Use pooled connection for better performance
// const connectionString = process.env.DATABASE_URL_POOLED || process.env.DATABASE_URL!
const connectionString = process.env.DATABASE_URL 
const pool = globalForPrisma.pool ?? new Pool({ connectionString })
const adapter = new PrismaPg(pool)

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    adapter,
    log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
  })

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma
  globalForPrisma.pool = pool
}

export default prisma