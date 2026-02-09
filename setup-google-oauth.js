#!/usr/bin/env node

/**
 * Google OAuth Setup Helper
 * 
 * This script helps you set up Google OAuth for the CRM application.
 * Run with: node setup-google-oauth.js
 */

const fs = require('fs')
const path = require('path')

console.log('🔧 Google OAuth Setup Helper\n')

// Check if .env.local exists
const envPath = path.join(process.cwd(), '.env.local')
const envExamplePath = path.join(process.cwd(), '.env.example')

if (!fs.existsSync(envPath)) {
    console.log('📋 Creating .env.local file from .env.example...')

    if (fs.existsSync(envExamplePath)) {
        fs.copyFileSync(envExamplePath, envPath)
        console.log('✅ .env.local created successfully')
    } else {
        console.log('❌ .env.example not found. Please create .env.local manually.')
        process.exit(1)
    }
}

// Read current .env.local
let envContent = fs.readFileSync(envPath, 'utf8')

// Check if Google OAuth variables exist
const hasGoogleClientId = envContent.includes('GOOGLE_CLIENT_ID=')
const hasGoogleClientSecret = envContent.includes('GOOGLE_CLIENT_SECRET=')

if (!hasGoogleClientId || !hasGoogleClientSecret) {
    console.log('\n🔑 Google OAuth credentials not found in .env.local')
    console.log('\nTo set up Google OAuth:')
    console.log('1. Go to: https://console.cloud.google.com/')
    console.log('2. Create a new project or select existing one')
    console.log('3. Enable Google+ API')
    console.log('4. Create OAuth 2.0 credentials')
    console.log('5. Add authorized redirect URI: http://localhost:3000/api/auth/callback/google')
    console.log('6. Add authorized JavaScript origin: http://localhost:3000')
    console.log('\nThen add your credentials to .env.local:')
    console.log('GOOGLE_CLIENT_ID=your_client_id_here')
    console.log('GOOGLE_CLIENT_SECRET=your_client_secret_here')

    if (!hasGoogleClientId && !envContent.includes('GOOGLE_CLIENT_ID')) {
        envContent += '\n# Google OAuth Configuration\nGOOGLE_CLIENT_ID=your_google_client_id_here\n'
    }
    if (!hasGoogleClientSecret && !envContent.includes('GOOGLE_CLIENT_SECRET')) {
        envContent += 'GOOGLE_CLIENT_SECRET=your_google_client_secret_here\n'
    }

    fs.writeFileSync(envPath, envContent)
    console.log('\n✅ Added Google OAuth placeholders to .env.local')
} else {
    console.log('✅ Google OAuth credentials found in .env.local')
}

console.log('\n📖 For detailed setup instructions, see: GOOGLE_OAUTH_SETUP.md')
console.log('\n🚀 After adding your credentials, restart the dev server with: npm run dev')