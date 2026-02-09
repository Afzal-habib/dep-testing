import { PrismaClient } from '@prisma/client'
import { Pool } from 'pg'
import { PrismaPg } from '@prisma/adapter-pg'
import { config } from 'dotenv'

// Load environment variables
config({ path: '.env.local' })

// Use direct connection for seeding (not pooled)
const connectionString = process.env.DIRECT_DATABASE_URL!
const pool = new Pool({ connectionString })
const adapter = new PrismaPg(pool)

const prisma = new PrismaClient({
  adapter,
  log: ['query', 'info', 'warn', 'error'],
})

async function main() {
  console.log('🌱 Starting database seeding...')

  try {
    // Clean existing data (optional - comment out if you want to preserve existing data)
    console.log('🧹 Cleaning existing data...')
    await prisma.attachments.deleteMany({})
    await prisma.reactions.deleteMany({})
    await prisma.read_receipts.deleteMany({})
    await prisma.messages.deleteMany({})
    await prisma.channel_members.deleteMany({})
    await prisma.channels.deleteMany({})
    console.log('✅ Cleaned existing data')

    // Example MongoDB user IDs (replace with actual user IDs from your MongoDB)
    const mockUserIds = {
      admin: '507f1f77bcf86cd799439011',
      user1: '507f1f77bcf86cd799439012',
      user2: '507f1f77bcf86cd799439013',
      user3: '507f1f77bcf86cd799439014',
    }

    // Create a general company-wide channel
    console.log('📢 Creating general channel...')
    const generalChannel = await prisma.channels.create({
      data: {
        id: crypto.randomUUID(),
        type: 'group',
        name: 'General',
        mongo_creator_id: mockUserIds.admin,
        is_private: false,
        member_count: 3,
        created_at: new Date(),
        updated_at: new Date(),
      },
    })

    // Add members to general channel
    await prisma.channel_members.createMany({
      data: [
        {
          id: crypto.randomUUID(),
          channel_id: generalChannel.id,
          mongo_member_id: mockUserIds.admin,
          role: 'admin',
          is_online: false,
        },
        {
          id: crypto.randomUUID(),
          channel_id: generalChannel.id,
          mongo_member_id: mockUserIds.user1,
          role: 'member',
          is_online: false,
        },
        {
          id: crypto.randomUUID(),
          channel_id: generalChannel.id,
          mongo_member_id: mockUserIds.user2,
          role: 'member',
          is_online: false,
        },
      ],
    })
    console.log('✅ Created general channel with members')

    // Create a department channel
    console.log('🏢 Creating department channel...')
    const deptChannel = await prisma.channels.create({
      data: {
        id: crypto.randomUUID(),
        type: 'department',
        name: 'Engineering Team',
        mongo_creator_id: mockUserIds.admin,
        mongo_department_id: '507f1f77bcf86cd799439020',
        is_private: true,
        member_count: 2,
        created_at: new Date(),
        updated_at: new Date(),
      },
    })

    await prisma.channel_members.createMany({
      data: [
        {
          id: crypto.randomUUID(),
          channel_id: deptChannel.id,
          mongo_member_id: mockUserIds.admin,
          role: 'admin',
          is_online: false,
        },
        {
          id: crypto.randomUUID(),
          channel_id: deptChannel.id,
          mongo_member_id: mockUserIds.user1,
          role: 'member',
          is_online: false,
        },
      ],
    })
    console.log('✅ Created department channel with members')

    // Create a DM channel
    console.log('💬 Creating DM channel...')
    const dmChannel = await prisma.channels.create({
      data: {
        id: crypto.randomUUID(),
        type: 'dm',
        mongo_creator_id: mockUserIds.user1,
        is_private: true,
        member_count: 2,
        created_at: new Date(),
        updated_at: new Date(),
      },
    })

    await prisma.channel_members.createMany({
      data: [
        {
          id: crypto.randomUUID(),
          channel_id: dmChannel.id,
          mongo_member_id: mockUserIds.user1,
          role: 'member',
          is_online: false,
        },
        {
          id: crypto.randomUUID(),
          channel_id: dmChannel.id,
          mongo_member_id: mockUserIds.user2,
          role: 'member',
          is_online: false,
         },
      ],
    })
    console.log('✅ Created DM channel with members')

    // Create a project channel
    console.log('📁 Creating project channel...')
    const projectChannel = await prisma.channels.create({
      data: {
        id: crypto.randomUUID(),
        type: 'project',
        name: 'Website Redesign',
        mongo_creator_id: mockUserIds.admin,
        mongo_project_id: '507f1f77bcf86cd799439030',
        is_private: false,
        member_count: 4,
        created_at: new Date(),
        updated_at: new Date(),
      },
    })

    await prisma.channel_members.createMany({
      data: [
        {
          id: crypto.randomUUID(),
          channel_id: projectChannel.id,
          mongo_member_id: mockUserIds.admin,
          role: 'admin',
          is_online: false,
        },
        {
          id: crypto.randomUUID(),
          channel_id: projectChannel.id,
          mongo_member_id: mockUserIds.user1,
          role: 'member',
          is_online: false,
        },
        {
          id: crypto.randomUUID(),
          channel_id: projectChannel.id,
          mongo_member_id: mockUserIds.user2,
          role: 'member',
          is_online: false,
        },
        {
          id: crypto.randomUUID(),
          channel_id: projectChannel.id,
          mongo_member_id: mockUserIds.user3,
          role: 'member',
          is_online: false,
        },
      ],
    })
    console.log('✅ Created project channel with members')

    // Create sample messages in general channel
    console.log('📝 Creating sample messages...')
    const message1 = await prisma.messages.create({
      data: {
        id: crypto.randomUUID(),
        channel_id: generalChannel.id,
        mongo_sender_id: mockUserIds.admin,
        content: 'Welcome to the team communication platform!',
        content_type: 'text',
      },
    })

    const message2 = await prisma.messages.create({
      data: {
        id: crypto.randomUUID(),
        channel_id: generalChannel.id,
        mongo_sender_id: mockUserIds.user1,
        content: 'Thanks! Excited to be here.',
        content_type: 'text',
      },
    })

    // Update channel's last_message_at
    await prisma.channels.update({
      where: { id: generalChannel.id },
      data: { last_message_at: new Date() },
    })
    console.log('✅ Created sample messages')

    // Create read receipts
    console.log('👀 Creating read receipts...')
    await prisma.read_receipts.createMany({
      data: [
        {
          id: crypto.randomUUID(),
          message_id: message1.id,
          mongo_user_id: mockUserIds.user1,
        },
        {
          id: crypto.randomUUID(),
          message_id: message1.id,
          mongo_user_id: mockUserIds.user2,
        },
      ],
    })
    console.log('✅ Created read receipts')

    // Create reactions
    console.log('👍 Creating reactions...')
    await prisma.reactions.createMany({
      data: [
        {
          id: crypto.randomUUID(),
          message_id: message1.id,
          channel_id: generalChannel.id,
          mongo_user_id: mockUserIds.user1,
          emoji: '👍',
          created_at: new Date(),
        },
        {
          id: crypto.randomUUID(),
          message_id: message1.id,
          channel_id: generalChannel.id,
          mongo_user_id: mockUserIds.user2,
          emoji: '🎉',
          created_at: new Date(),
        },
      ],
    })
    console.log('✅ Created reactions')

    console.log('\n🎉 Seeding completed successfully!')
    console.log('\n📊 Summary:')
    console.log(`   - Channels: 4 (1 general, 1 department, 1 DM, 1 project)`)
    console.log(`   - Channel Members: ${3 + 2 + 2 + 4}`)
    console.log(`   - Messages: 2`)
    console.log(`   - Read Receipts: 2`)
    console.log(`   - Reactions: 2`)
    console.log('\n💡 Note: Make sure to update mockUserIds with actual MongoDB user IDs')
  } catch (error) {
    console.error('❌ Error during seeding:', error)
    throw error
  }
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
