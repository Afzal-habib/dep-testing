import mongoose from 'mongoose'
import { connectToDatabase } from '../migrations/migrationUtils'
import Project from '../../models/Project'
import Lead from '../../models/Lead'
import User from '../../models/User'
import Department from '../../models/Department'

export interface IProjectSeed {
  name: string
  description?: string
  status: 'pending' | 'active' | 'completed' | 'approved' | 'inactive'
  budget?: number
  startDate?: Date
  endDate?: Date
  priority: 'low' | 'medium' | 'high' | 'urgent'
  projectType?: string
  requirements?: string
  timeline?: string
}

export const projectSeeds: IProjectSeed[] = [
  {
    name: 'E-commerce Website Redesign',
    description: 'Complete redesign of existing e-commerce platform with modern UI/UX, mobile-first design, and improved SEO',
    status: 'active',
    budget: 25000,
    startDate: new Date('2024-01-15'),
    endDate: new Date('2024-04-15'),
    priority: 'high',
    projectType: 'Web Development',
    requirements: 'React, Node.js, MongoDB, Payment Integration, SEO Optimization',
    timeline: '3 months'
  },
  {
    name: 'Mobile App Development',
    description: 'Native iOS and Android fitness tracking app with health API integration',
    status: 'active',
    budget: 35000,
    startDate: new Date('2024-02-01'),
    endDate: new Date('2024-06-01'),
    priority: 'high',
    projectType: 'Mobile Development',
    requirements: 'React Native, Firebase, Health API, Real-time Sync',
    timeline: '4 months'
  },
  {
    name: 'Inventory Management System',
    description: 'Custom inventory and POS system for retail chain with barcode integration',
    status: 'approved',
    budget: 45000,
    startDate: new Date('2024-01-01'),
    endDate: new Date('2024-06-01'),
    priority: 'urgent',
    projectType: 'Enterprise Software',
    requirements: 'MERN Stack, Real-time Updates, Barcode Integration, Multi-location Support',
    timeline: '5 months'
  },
  {
    name: 'Business Website Development',
    description: 'Professional business website with contact forms, services showcase, and SEO optimization',
    status: 'completed',
    budget: 8000,
    startDate: new Date('2023-12-01'),
    endDate: new Date('2024-01-15'),
    priority: 'medium',
    projectType: 'Web Development',
    requirements: 'WordPress, Contact Forms, SEO, Responsive Design',
    timeline: '6 weeks'
  },
  {
    name: 'CRM System Customization',
    description: 'Customize existing CRM system with custom fields, enhanced reporting, and workflow automation',
    status: 'pending',
    budget: 18000,
    startDate: new Date('2024-03-01'),
    endDate: new Date('2024-05-01'),
    priority: 'medium',
    projectType: 'CRM Development',
    requirements: 'CRM Integration, Custom Fields, Advanced Reporting, Workflow Automation',
    timeline: '2 months'
  },
  {
    name: 'Portfolio Website',
    description: 'Personal portfolio website for freelance designer with project showcase',
    status: 'inactive',
    budget: 3000,
    startDate: new Date('2024-01-01'),
    endDate: new Date('2024-02-01'),
    priority: 'low',
    projectType: 'Web Development',
    requirements: 'Portfolio Template, Contact Form, Project Gallery',
    timeline: '4 weeks'
  },
  {
    name: 'Patient Management System',
    description: 'HIPAA-compliant patient management system with appointment scheduling and medical records',
    status: 'active',
    budget: 55000,
    startDate: new Date('2024-02-15'),
    endDate: new Date('2024-08-15'),
    priority: 'high',
    projectType: 'Healthcare Software',
    requirements: 'HIPAA Compliance, React, Node.js, MongoDB, Appointment Scheduling, Medical Records',
    timeline: '6 months'
  },
  {
    name: 'Financial Dashboard Application',
    description: 'Real-time financial dashboard with analytics and reporting for investment firms',
    status: 'active',
    budget: 42000,
    startDate: new Date('2024-03-01'),
    endDate: new Date('2024-07-01'),
    priority: 'high',
    projectType: 'FinTech',
    requirements: 'React, D3.js, Real-time Data, Financial APIs, Security, Data Visualization',
    timeline: '4 months'
  },
  {
    name: 'Online Learning Platform',
    description: 'E-learning platform with video streaming, quizzes, and progress tracking for educational institutions',
    status: 'approved',
    budget: 38000,
    startDate: new Date('2024-04-01'),
    endDate: new Date('2024-09-01'),
    priority: 'medium',
    projectType: 'Education Technology',
    requirements: 'Video Streaming, React, Node.js, MongoDB, User Progress Tracking, Quiz System',
    timeline: '5 months'
  },
  {
    name: 'Fleet Management Software',
    description: 'GPS tracking and fleet management system for transportation and logistics companies',
    status: 'pending',
    budget: 48000,
    startDate: new Date('2024-05-01'),
    endDate: new Date('2024-10-01'),
    priority: 'high',
    projectType: 'Logistics Software',
    requirements: 'GPS Integration, Real-time Tracking, React Native, Node.js, Route Optimization',
    timeline: '5 months'
  },
  {
    name: 'Restaurant Management System',
    description: 'Complete restaurant management with POS, inventory tracking, and online ordering system',
    status: 'active',
    budget: 32000,
    startDate: new Date('2024-01-20'),
    endDate: new Date('2024-05-20'),
    priority: 'medium',
    projectType: 'Restaurant Software',
    requirements: 'POS System, Inventory Management, Online Ordering, React, Payment Integration',
    timeline: '4 months'
  },
  {
    name: 'Construction Project Management',
    description: 'Project management tool for construction companies with timeline tracking and resource allocation',
    status: 'approved',
    budget: 41000,
    startDate: new Date('2024-02-10'),
    endDate: new Date('2024-06-10'),
    priority: 'high',
    projectType: 'Construction Software',
    requirements: 'Project Timeline, Resource Management, React, MongoDB, Document Management',
    timeline: '4 months'
  },
  {
    name: 'Marketing Campaign Dashboard',
    description: 'Dashboard for tracking marketing campaigns across multiple channels with analytics',
    status: 'completed',
    budget: 28000,
    startDate: new Date('2023-11-01'),
    endDate: new Date('2024-02-01'),
    priority: 'medium',
    projectType: 'Marketing Technology',
    requirements: 'Multi-channel Analytics, React, Data Visualization, API Integration, Reporting',
    timeline: '3 months'
  },
  {
    name: 'Manufacturing ERP System',
    description: 'Comprehensive ERP system for manufacturing with inventory, production planning, and quality control',
    status: 'active',
    budget: 65000,
    startDate: new Date('2024-03-15'),
    endDate: new Date('2024-10-15'),
    priority: 'urgent',
    projectType: 'Enterprise Software',
    requirements: 'ERP, Inventory Management, Production Planning, Quality Control, React, Advanced Reporting',
    timeline: '7 months'
  },
  {
    name: 'Donation Management Platform',
    description: 'Platform for managing donations, volunteers, and fundraising campaigns for nonprofit organizations',
    status: 'pending',
    budget: 22000,
    startDate: new Date('2024-06-01'),
    endDate: new Date('2024-09-01'),
    priority: 'low',
    projectType: 'Nonprofit Software',
    requirements: 'Donation Processing, Volunteer Management, Fundraising, React, MongoDB, Email Campaigns',
    timeline: '3 months'
  },
  {
    name: 'Real Estate Property Management',
    description: 'Property management system for real estate agencies with tenant tracking and maintenance scheduling',
    status: 'approved',
    budget: 36000,
    startDate: new Date('2024-04-15'),
    endDate: new Date('2024-08-15'),
    priority: 'medium',
    projectType: 'Real Estate Software',
    requirements: 'Property Tracking, Tenant Management, Maintenance Scheduling, React, Document Storage',
    timeline: '4 months'
  },
  {
    name: 'Event Management Platform',
    description: 'Comprehensive event management system with ticketing, attendee management, and virtual events',
    status: 'active',
    budget: 43000,
    startDate: new Date('2024-05-01'),
    endDate: new Date('2024-09-01'),
    priority: 'high',
    projectType: 'Event Management',
    requirements: 'Ticketing System, Attendee Management, Virtual Events, React, Payment Processing',
    timeline: '4 months'
  },
  {
    name: 'HR Management System',
    description: 'Human resources management system with employee tracking, payroll, and performance reviews',
    status: 'pending',
    budget: 52000,
    startDate: new Date('2024-07-01'),
    endDate: new Date('2024-12-01'),
    priority: 'high',
    projectType: 'HR Software',
    requirements: 'Employee Management, Payroll, Performance Reviews, React, Compliance Tracking',
    timeline: '5 months'
  },
  {
    name: 'Travel Booking Platform',
    description: 'Online travel booking platform with hotel, flight, and activity reservations',
    status: 'approved',
    budget: 58000,
    startDate: new Date('2024-03-20'),
    endDate: new Date('2024-09-20'),
    priority: 'urgent',
    projectType: 'Travel Technology',
    requirements: 'Booking Engine, Payment Processing, API Integration, React, Search Functionality',
    timeline: '6 months'
  },
  {
    name: 'Legal Case Management',
    description: 'Case management system for law firms with document management and client communication',
    status: 'active',
    budget: 39000,
    startDate: new Date('2024-01-10'),
    endDate: new Date('2024-05-10'),
    priority: 'medium',
    projectType: 'Legal Software',
    requirements: 'Case Tracking, Document Management, Client Communication, React, Secure File Storage',
    timeline: '4 months'
  }
]

export default async function seedProjects(): Promise<void> {
  try {
    // Ensure database connection (reuse existing or create new)
    if (mongoose.connection.readyState !== 1) {
      console.log('🔌 Connecting to database...')
      await connectToDatabase()
    } else {
      console.log('✅ Using existing database connection')
    }

    console.log('🌱 Starting project seeding...')

    // Clear existing projects
    const deletedCount = await Project.countDocuments()
    await Project.deleteMany({})
    console.log(`🗑️  Cleared ${deletedCount} existing projects`)

    // Get qualified leads with their associated clients
    const qualifiedLeadsWithClients = await Lead.find({ status: 'qualified' })
      .populate('clientId')
      .populate('createdBy')

    // Filter to only leads that have clients created
    const validLeads = qualifiedLeadsWithClients.filter(lead => lead.clientId)

    if (validLeads.length === 0) {
      console.warn('⚠️  No qualified leads with clients found. Run lead seeding first.')
      return
    }

    console.log(`📋 Found ${validLeads.length} qualified leads with clients`)

    // Get departments for project assignment
    const departments = await Department.find({}).limit(5)

    // Get project managers and team leads for approval/creation
    const projectManagers = await User.find({
      $or: [
        { 'role.name': 'project_manager' },
        { 'legacyRole': 'manager' }
      ]
    })

    const teamLeads = await User.find({
      'role.name': { $regex: /team_lead/i }
    })

    let createdCount = 0

    for (let i = 0; i < Math.min(projectSeeds.length, validLeads.length); i++) {
      const projectData = projectSeeds[i]
      const lead = validLeads[i]
      const client = lead.clientId as any // Client is populated User
      const projectManager = projectManagers[i % projectManagers.length]
      const teamLead = teamLeads[i % teamLeads.length]

      const project = new Project({
        ...projectData,
        clientId: client._id,
        createdBy: projectManager?._id || lead.createdBy,
        approvedBy: projectData.status === 'approved' || projectData.status === 'active' ? teamLead?._id : undefined,
        approvedAt: projectData.status === 'approved' || projectData.status === 'active' ? new Date() : undefined
      })

      await project.save()
      createdCount++
    }

    console.log(`✅ Created ${createdCount} projects`)

    // Summary
    const statusCounts = await Project.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ])

    console.log('\n📊 Project Seeding Summary:')
    statusCounts.forEach((status: any) => {
      console.log(`   ${status._id}: ${status.count} projects`)
    })

    console.log('\n🎯 Priority Distribution:')
    const priorityCounts = await Project.aggregate([
      { $group: { _id: '$priority', count: { $sum: 1 } } }
    ])
    priorityCounts.forEach((priority: any) => {
      console.log(`   ${priority._id}: ${priority.count} projects`)
    })

    console.log('\n🏗️  Project Types:')
    const typeCounts = await Project.aggregate([
      { $group: { _id: '$projectType', count: { $sum: 1 } } }
    ])
    typeCounts.forEach((type: any) => {
      console.log(`   ${type._id}: ${type.count} projects`)
    })

    const budgetStats = await Project.aggregate([
      {
        $group: {
          _id: null,
          totalBudget: { $sum: '$budget' },
          avgBudget: { $avg: '$budget' },
          minBudget: { $min: '$budget' },
          maxBudget: { $max: '$budget' }
        }
      }
    ])

    if (budgetStats.length > 0) {
      const stats = budgetStats[0]
      console.log('\n💰 Budget Statistics:')
      console.log(`   Total: $${stats.totalBudget?.toLocaleString()}`)
      console.log(`   Average: $${Math.round(stats.avgBudget || 0).toLocaleString()}`)
      console.log(`   Range: $${stats.minBudget?.toLocaleString()} - $${stats.maxBudget?.toLocaleString()}`)
    }

  } catch (error) {
    console.error('❌ Project seeding failed:', error)
    throw error
  }
}