import mongoose from 'mongoose'
import { connectToDatabase } from '../migrations/migrationUtils'
import Lead from '../../models/Lead'
import User from '../../models/User'
import Role from '../../models/Role'
import Department from '../../models/Department'
import * as bcrypt from 'bcryptjs'

export interface ILeadSeed {
  name: string
  email: string
  phone?: string
  company?: string
  projectName: string
  projectDescription?: string
  projectBudget?: number
  projectTimeline?: string
  projectRequirements?: string[]
  status: 'active' | 'inactive' | 'qualified' | 'unqualified'
  source?: 'website' | 'referral' | 'cold_call' | 'email' | 'social_media' | 'event' | 'other'
  priority: 'low' | 'medium' | 'high' | 'urgent'
  notes?: string
  tags?: string[]
}

export const leadSeeds: ILeadSeed[] = [
  // High priority active leads
  {
    name: 'John Smith',
    email: 'john.smith@techcorp.com',
    phone: '+15550101',
    company: 'TechCorp Solutions',
    projectName: 'E-commerce Website Redesign',
    projectDescription: 'Complete redesign of existing e-commerce platform with modern UI/UX',
    projectBudget: 25000,
    projectTimeline: '3 months',
    projectRequirements: ['React', 'Node.js', 'MongoDB', 'Payment Integration'],
    status: 'active',
    source: 'website',
    priority: 'high',
    notes: 'Interested in mobile-first design and SEO optimization',
    tags: ['e-commerce', 'redesign', 'urgent']
  },
  {
    name: 'Sarah Johnson',
    email: 'sarah@startup.io',
    phone: '+15550102',
    company: 'Startup.io',
    projectName: 'Mobile App Development',
    projectDescription: 'Native iOS and Android app for fitness tracking',
    projectBudget: 35000,
    projectTimeline: '4 months',
    projectRequirements: ['React Native', 'Firebase', 'Health API'],
    status: 'active',
    source: 'referral',
    priority: 'high',
    notes: 'Budget flexible, timeline is critical',
    tags: ['mobile', 'fitness', 'startup']
  },
  {
    name: 'Mike Chen',
    email: 'mike.chen@retailplus.com',
    phone: '+15550103',
    company: 'Retail Plus',
    projectName: 'Inventory Management System',
    projectDescription: 'Custom inventory and POS system for retail chain',
    projectBudget: 45000,
    projectTimeline: '5 months',
    projectRequirements: ['MERN Stack', 'Real-time Updates', 'Barcode Integration'],
    status: 'qualified',
    source: 'cold_call',
    priority: 'urgent',
    notes: 'Already signed contract, moving to project phase',
    tags: ['inventory', 'pos', 'retail']
  },
  // Medium priority leads
  {
    name: 'Emily Davis',
    email: 'emily@localbusiness.com',
    phone: '+15550104',
    company: 'Local Business Co',
    projectName: 'Business Website',
    projectDescription: 'Simple business website with contact forms and services',
    projectBudget: 8000,
    projectTimeline: '6 weeks',
    projectRequirements: ['WordPress', 'Contact Forms', 'SEO'],
    status: 'active',
    source: 'social_media',
    priority: 'medium',
    notes: 'Small business owner, needs quick turnaround',
    tags: ['wordpress', 'small-business']
  },
  {
    name: 'David Wilson',
    email: 'david.wilson@consulting.com',
    phone: '+15550105',
    company: 'Wilson Consulting',
    projectName: 'CRM System Customization',
    projectDescription: 'Customize existing CRM for specific business needs',
    projectBudget: 18000,
    projectTimeline: '2 months',
    projectRequirements: ['CRM Integration', 'Custom Fields', 'Reporting'],
    status: 'active',
    source: 'email',
    priority: 'medium',
    notes: 'Current CRM user looking for enhancements',
    tags: ['crm', 'customization']
  },
  // Low priority leads
  {
    name: 'Lisa Brown',
    email: 'lisa.brown@email.com',
    phone: '+15550106',
    company: 'Personal Project',
    projectName: 'Personal Portfolio Website',
    projectDescription: 'Portfolio website for freelance designer',
    projectBudget: 3000,
    projectTimeline: '4 weeks',
    projectRequirements: ['Portfolio Template', 'Contact Form'],
    status: 'inactive',
    source: 'website',
    priority: 'low',
    notes: 'Budget constraints, may revisit later',
    tags: ['portfolio', 'freelance']
  },
  // Unqualified leads
  {
    name: 'Test Lead',
    email: 'test@example.com',
    phone: '+15550107',
    company: 'Test Company',
    projectName: 'Test Project',
    projectDescription: 'This is a test lead for demonstration',
    projectBudget: 1000,
    projectTimeline: '1 week',
    projectRequirements: ['Testing'],
    status: 'unqualified',
    source: 'other',
    priority: 'low',
    notes: 'Test data - budget too low for requirements',
    tags: ['test', 'demo']
  },
  // Additional qualified leads to create more clients
  {
    name: 'Jennifer Martinez',
    email: 'jennifer.martinez@healthcareplus.com',
    phone: '+15550108',
    company: 'Healthcare Plus',
    projectName: 'Patient Management System',
    projectDescription: 'Comprehensive patient management system with appointment scheduling and medical records',
    projectBudget: 55000,
    projectTimeline: '6 months',
    projectRequirements: ['HIPAA Compliance', 'React', 'Node.js', 'MongoDB', 'Appointment Scheduling'],
    status: 'qualified',
    source: 'referral',
    priority: 'high',
    notes: 'Healthcare client, requires HIPAA compliance and secure data handling',
    tags: ['healthcare', 'patient-management', 'hipaa']
  },
  {
    name: 'Robert Kim',
    email: 'robert.kim@fintechinnovate.com',
    phone: '+15550109',
    company: 'FinTech Innovate',
    projectName: 'Financial Dashboard Application',
    projectDescription: 'Real-time financial dashboard with analytics and reporting for investment firms',
    projectBudget: 42000,
    projectTimeline: '4 months',
    projectRequirements: ['React', 'D3.js', 'Real-time Data', 'Financial APIs', 'Security'],
    status: 'qualified',
    source: 'cold_call',
    priority: 'high',
    notes: 'FinTech startup looking for secure, scalable solution',
    tags: ['fintech', 'dashboard', 'analytics']
  },
  {
    name: 'Amanda Rodriguez',
    email: 'amanda.rodriguez@educationhub.com',
    phone: '+15550110',
    company: 'Education Hub',
    projectName: 'Online Learning Platform',
    projectDescription: 'E-learning platform with video streaming, quizzes, and progress tracking',
    projectBudget: 38000,
    projectTimeline: '5 months',
    projectRequirements: ['Video Streaming', 'React', 'Node.js', 'MongoDB', 'User Progress Tracking'],
    status: 'qualified',
    source: 'website',
    priority: 'medium',
    notes: 'Educational institution expanding online presence',
    tags: ['education', 'e-learning', 'video-streaming']
  },
  {
    name: 'Michael Thompson',
    email: 'michael.thompson@logisticspro.com',
    phone: '+15550111',
    company: 'Logistics Pro',
    projectName: 'Fleet Management Software',
    projectDescription: 'GPS tracking and fleet management system for transportation company',
    projectBudget: 48000,
    projectTimeline: '5 months',
    projectRequirements: ['GPS Integration', 'Real-time Tracking', 'React Native', 'Node.js'],
    status: 'qualified',
    source: 'social_media',
    priority: 'high',
    notes: 'Logistics company with 50+ vehicles needing comprehensive tracking',
    tags: ['logistics', 'fleet-management', 'gps']
  },
  {
    name: 'Sarah Williams',
    email: 'sarah.williams@restaurantchain.com',
    phone: '+15550112',
    company: 'Restaurant Chain Inc',
    projectName: 'Restaurant Management System',
    projectDescription: 'Complete restaurant management with POS, inventory, and online ordering',
    projectBudget: 32000,
    projectTimeline: '4 months',
    projectRequirements: ['POS System', 'Inventory Management', 'Online Ordering', 'React'],
    status: 'qualified',
    source: 'referral',
    priority: 'medium',
    notes: 'Restaurant chain with 15 locations needing centralized management',
    tags: ['restaurant', 'pos', 'inventory']
  },
  {
    name: 'David Lee',
    email: 'david.lee@constructionco.com',
    phone: '+15550113',
    company: 'Construction Co',
    projectName: 'Construction Project Management',
    projectDescription: 'Project management tool for construction companies with timeline and resource tracking',
    projectBudget: 41000,
    projectTimeline: '4 months',
    projectRequirements: ['Project Timeline', 'Resource Management', 'React', 'MongoDB'],
    status: 'qualified',
    source: 'email',
    priority: 'high',
    notes: 'Construction company managing multiple projects simultaneously',
    tags: ['construction', 'project-management', 'timeline']
  },
  {
    name: 'Lisa Chen',
    email: 'lisa.chen@marketingagency.com',
    phone: '+15550114',
    company: 'Marketing Agency Pro',
    projectName: 'Marketing Campaign Dashboard',
    projectDescription: 'Dashboard for tracking marketing campaigns across multiple channels',
    projectBudget: 28000,
    projectTimeline: '3 months',
    projectRequirements: ['Multi-channel Analytics', 'React', 'Data Visualization', 'API Integration'],
    status: 'qualified',
    source: 'cold_call',
    priority: 'medium',
    notes: 'Marketing agency managing campaigns for 20+ clients',
    tags: ['marketing', 'dashboard', 'analytics']
  },
  {
    name: 'James Wilson',
    email: 'james.wilson@manufacturinginc.com',
    phone: '+15550115',
    company: 'Manufacturing Inc',
    projectName: 'Manufacturing ERP System',
    projectDescription: 'ERP system for manufacturing with inventory, production planning, and quality control',
    projectBudget: 65000,
    projectTimeline: '7 months',
    projectRequirements: ['ERP', 'Inventory', 'Production Planning', 'Quality Control', 'React'],
    status: 'qualified',
    source: 'referral',
    priority: 'urgent',
    notes: 'Large manufacturing company requiring comprehensive ERP solution',
    tags: ['manufacturing', 'erp', 'inventory']
  },
  {
    name: 'Emma Davis',
    email: 'emma.davis@nonprofit.org',
    phone: '+15550116',
    company: 'Nonprofit Organization',
    projectName: 'Donation Management Platform',
    projectDescription: 'Platform for managing donations, volunteers, and fundraising campaigns',
    projectBudget: 22000,
    projectTimeline: '3 months',
    projectRequirements: ['Donation Processing', 'Volunteer Management', 'React', 'MongoDB'],
    status: 'qualified',
    source: 'website',
    priority: 'low',
    notes: 'Nonprofit organization needing affordable solution for donation tracking',
    tags: ['nonprofit', 'donations', 'volunteers']
  }
]

export default async function seedLeads(): Promise<void> {
  try {
    // Ensure database connection (reuse existing or create new)
    if (mongoose.connection.readyState !== 1) {
      console.log('🔌 Connecting to database...')
      await connectToDatabase()
    } else {
      console.log('✅ Using existing database connection')
    }

    console.log('🌱 Starting lead seeding...')

    // Clear existing leads - be very aggressive
    try {
      await Lead.collection.drop()
      console.log(`🗑️  Dropped leads collection`)
    } catch (error) {
      // Collection might not exist, that's fine
      console.log(`🗑️  Leads collection already dropped or doesn't exist`)
    }
    
    // Ensure collection exists and indexes are created
    await Lead.createCollection()
    console.log(`✅ Leads collection recreated`)

    // Verify users exist in database
    const totalUsers = await User.countDocuments()
    console.log(`🔍 Total users in database: ${totalUsers}`)
    
    if (totalUsers === 0) {
      throw new Error('No users found in database. Please seed users first.')
    }

    // Get users to assign as creators (prefer sales/managers, fallback to any active user)
    let salesUsers = await User.find({
      $or: [
        { legacyRole: 'manager' },
        { legacyRole: 'sales' }
      ]
    }).populate('department').limit(5)

    console.log(`📊 Found ${salesUsers.length} sales/manager users`)

    if (salesUsers.length === 0) {
      console.warn('⚠️  No sales/manager users found, using any active users as creators')
      salesUsers = await User.find({ status: 'active' }).populate('department').limit(5)
      console.log(`📊 Found ${salesUsers.length} active users`)
    }

    if (salesUsers.length === 0) {
      // Final attempt - get ANY users
      console.warn('⚠️  No active users found, getting any users...')
      salesUsers = await User.find({}).populate('department').limit(5)
      console.log(`📊 Found ${salesUsers.length} total users`)
    }

    if (salesUsers.length === 0) {
      throw new Error(`No users found to assign as lead creators. Total users in DB: ${totalUsers}. Please seed users first.`)
    }

    console.log(`✅ Using ${salesUsers.length} users as lead creators`)

    let createdCount = 0
    const qualifiedLeads: any[] = []
    const createdClients: any[] = []

    // Get or create client role for creating clients
    let clientRole = await Role.findOne({ name: { $regex: /^client$/i } })
    if (!clientRole) {
      console.log('📝 Creating client role...')
      clientRole = new Role({
        name: 'client',
        displayName: 'Client',
        description: 'Client user role for accessing client portal',
        hierarchyLevel: 1,
        permissions: [], // Clients have limited permissions
        isSystemRole: true,
        status: 'active'
      })
      await clientRole.save()
      console.log('✅ Client role created')
    }

    for (let i = 0; i < leadSeeds.length; i++) {
      const leadData = leadSeeds[i]
      const salesUser = salesUsers[i % salesUsers.length]

      // Check if lead already exists
      let lead = await Lead.findOne({ email: leadData.email })
      if (lead) {
        // Update existing lead
        lead.name = leadData.name
        lead.phone = leadData.phone
        lead.company = leadData.company
        lead.projectName = leadData.projectName
        lead.projectDescription = leadData.projectDescription
        lead.projectBudget = leadData.projectBudget
        lead.projectTimeline = leadData.projectTimeline
        lead.projectRequirements = leadData.projectRequirements
        lead.status = leadData.status
        lead.source = leadData.source
        lead.priority = leadData.priority
        lead.notes = leadData.notes
        lead.tags = leadData.tags
        lead.createdBy = salesUser._id as mongoose.Types.ObjectId
        lead.lastContactDate = new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000)
        lead.nextFollowUpDate = leadData.status === 'active' ?
          new Date(Date.now() + Math.random() * 7 * 24 * 60 * 60 * 1000) : undefined
        lead.qualifiedAt = leadData.status === 'qualified' ? new Date() : undefined
        lead.qualifiedBy = leadData.status === 'qualified' ? salesUser._id as mongoose.Types.ObjectId : undefined
        lead.unqualifiedAt = leadData.status === 'unqualified' ? new Date() : undefined
        lead.unqualifiedReason = leadData.status === 'unqualified' ? 'Budget too low for project scope' : undefined
        await lead.save()
      } else {
        // Create new lead
        lead = new Lead({
          ...leadData,
          createdBy: salesUser._id as mongoose.Types.ObjectId,
          lastContactDate: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000),
          nextFollowUpDate: leadData.status === 'active' ?
            new Date(Date.now() + Math.random() * 7 * 24 * 60 * 60 * 1000) : undefined,
          qualifiedAt: leadData.status === 'qualified' ? new Date() : undefined,
          qualifiedBy: leadData.status === 'qualified' ? salesUser._id as mongoose.Types.ObjectId : undefined,
          unqualifiedAt: leadData.status === 'unqualified' ? new Date() : undefined,
          unqualifiedReason: leadData.status === 'unqualified' ? 'Budget too low for project scope' : undefined
        })
        await lead.save()
      }``

      // Create client user for qualified leads
      if (leadData.status === 'qualified' && clientRole) {
        try {
          // Check if client already exists
          const existingClient = await User.findOne({ email: leadData.email })
          if (!existingClient) {
            const hashedPassword = await bcrypt.hash('Client@123', 10)

            const client = new User({
              name: leadData.name,
              email: leadData.email,
              password: hashedPassword,
              phone: leadData.phone,
              role: clientRole._id,
              department: null, // Clients don't belong to departments
              avatar: '',
              status: 'active',
              leadId: lead._id, // Link to the lead
              isClient: true,
              company: leadData.company, // Required for clients
              website: leadData.company ? `https://www.${leadData.company.toLowerCase().replace(/\s+/g, '')}.com` : `https://${leadData.email.split('@')[1]}`, // Generate website from company or email domain
              clientStatus: 'qualified' // Required for clients
            })

            await client.save()
            lead.clientId = client._id as any
            await lead.save()

            createdClients.push(client)
            console.log(`👤 Created client: ${client.name} (${client.email})`)
          } else {
            console.log(`⚠️  Client already exists for: ${leadData.email}`)
            lead.clientId = existingClient._id as any
            await lead.save()
          }
        } catch (error) {
          console.error(`❌ Failed to create client for lead ${leadData.email}:`, error)
        }
      }

      if (leadData.status === 'qualified') {
        qualifiedLeads.push(lead)
      }

      createdCount++
    }

    console.log(`✅ Created ${createdCount} leads`)
    console.log(`👤 Created ${createdClients.length} client users from qualified leads`)

    // Summary
    const statusCounts = await Lead.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ])

    console.log('\n📊 Lead Seeding Summary:')
    statusCounts.forEach((status: any) => {
      console.log(`   ${status._id}: ${status.count} leads`)
    })

    console.log('\n🎯 Priority Distribution:')
    const priorityCounts = await Lead.aggregate([
      { $group: { _id: '$priority', count: { $sum: 1 } } }
    ])
    priorityCounts.forEach((priority: any) => {
      console.log(`   ${priority._id}: ${priority.count} leads`)
    })

    console.log('\n📈 Source Distribution:')
    const sourceCounts = await Lead.aggregate([
      { $group: { _id: '$source', count: { $sum: 1 } } }
    ])
    sourceCounts.forEach((source: any) => {
      console.log(`   ${source._id}: ${source.count} leads`)
    })

    console.log('\n💰 Budget Range: $3,000 - $45,000')
    console.log('⏱️  Timeline Range: 1 week - 5 months')

    if (createdClients.length > 0) {
      console.log('\n👥 Client Credentials:')
      createdClients.forEach((client: any) => {
        console.log(`   ${client.name}: ${client.email} / Client@123`)
      })
    }

  } catch (error) {
    console.error('❌ Lead seeding failed:', error)
    throw error
  }
}