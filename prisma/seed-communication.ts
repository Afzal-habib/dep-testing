import { PrismaClient } from '@prisma/client'
import { Pool } from 'pg'
import { PrismaPg } from '@prisma/adapter-pg'
import { config } from 'dotenv'
import mongoose from 'mongoose'
import User from '../models/User'

// Load environment variables
config({ path: '.env.local' })

// Use direct connection for seeding
const connectionString = process.env.DATABASE_URL!
const pool = new Pool({ connectionString })
const adapter = new PrismaPg(pool)

const prisma = new PrismaClient({
  adapter,
  log: ['query', 'info', 'warn', 'error'],
})

async function main() {
  console.log('🌱 Starting communication database seeding with real users...')

  try {
    // Connect to MongoDB
    console.log('📡 Connecting to MongoDB...')
    await mongoose.connect(process.env.MONGODB_URI!)
    console.log('✅ Connected to MongoDB')

    // Fetch real users from MongoDB
    console.log('👥 Fetching users from MongoDB...')
    const users = await User.find({ isDeleted: { $ne: true } })
      .limit(10)
      .lean()
    
    if (users.length === 0) {
      console.error('❌ No users found in MongoDB. Please create users first.')
      process.exit(1)
    }

    console.log(`✅ Found ${users.length} users`)
    const userIds = users.map(u => u._id.toString())

    // Clean existing data
    console.log('🧹 Cleaning existing communication data...')
    await prisma.attachments.deleteMany({})
    await prisma.reactions.deleteMany({})
    await prisma.read_receipts.deleteMany({})
    await prisma.messages.deleteMany({})
    await prisma.channel_members.deleteMany({})
    await prisma.channels.deleteMany({})
    console.log('✅ Cleaned existing data')

    // Create a general company-wide channel with real users
    console.log('📢 Creating general channel...')
    const generalChannel = await prisma.channels.create({
      data: {
        id: crypto.randomUUID(),
        type: 'group',
        name: 'General',
        mongo_creator_id: userIds[0],
        is_private: false,
        member_count: Math.min(5, users.length),
        updated_at: new Date(),
      },
    })

    // Add first 5 users to general channel
    const generalChannelMembers = users.slice(0, 5).map((user, idx) => ({
      id: crypto.randomUUID(),
      channel_id: generalChannel.id,
      mongo_member_id: user._id.toString(),
      role: idx === 0 ? 'admin' : 'member',
      is_online: false,
    }))

    await prisma.channel_members.createMany({
      data: generalChannelMembers,
    })
    console.log(`✅ Created general channel with ${generalChannelMembers.length} members`)

    // Create a sample message in general channel
    if (users.length > 0) {
      const welcomeMessage = await prisma.messages.create({
        data: {
          id: crypto.randomUUID(),
          channel_id: generalChannel.id,
          mongo_sender_id: userIds[0],
          content: 'Welcome to the General channel! 👋',
          content_type: 'text',
        },
      })
      console.log('✅ Created welcome message')

      // Update channel's last_message_at
      await prisma.channels.update({
        where: { id: generalChannel.id },
        data: { last_message_at: welcomeMessage.created_at },
      })
    }

    // Create DM channels between users
    if (users.length >= 2) {
      console.log('💬 Creating DM channels...')
      let dmCount = 0
      
      for (let i = 0; i < Math.min(3, users.length - 1); i++) {
        const dmChannel = await prisma.channels.create({
          data: {
            id: crypto.randomUUID(),
            type: 'dm',
            mongo_creator_id: userIds[i],
            is_private: true,
            member_count: 2,
            updated_at: new Date(),
          },
        })

        await prisma.channel_members.createMany({
          data: [
            {
              id: crypto.randomUUID(),
              channel_id: dmChannel.id,
              mongo_member_id: userIds[i],
              role: 'member',
              is_online: false,
            },
            {
              id: crypto.randomUUID(),
              channel_id: dmChannel.id,
              mongo_member_id: userIds[i + 1],
              role: 'member',
              is_online: false,
            },
          ],
        })
        dmCount++
      }
      console.log(`✅ Created ${dmCount} DM channels`)
    }

    console.log('\n✨ Communication seeding completed successfully!')
    console.log(`📊 Summary:`)
    console.log(`   - Users: ${users.length}`)
    console.log(`   - Channels: ${await prisma.channels.count()}`)
    console.log(`   - Channel Members: ${await prisma.channel_members.count()}`)
    console.log(`   - Messages: ${await prisma.messages.count()}`)

  } catch (error) {
    console.error('❌ Error during seeding:', error)
    throw error
  } finally {
    await prisma.$disconnect()
    await mongoose.disconnect()
  }
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
