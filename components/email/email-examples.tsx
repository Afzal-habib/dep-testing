// Example usage of the enhanced email functionality with CC, BCC, and multiple recipients

import { useEmail } from '@/hooks/use-email'
import { useEffect } from 'react'

export function EmailExamples() {
  const { 
    sendEmail, 
    sendNotificationEmail, 
    validateEmailAddresses, 
    countTotalRecipients,
    formatEmailAddresses 
  } = useEmail()

  useEffect(() => {
    // Example 1: Send email to multiple TO recipients
    const sendToMultipleRecipients = async () => {
      try {
        await sendEmail({
          to: ['user1@example.com', 'user2@example.com', 'user3@example.com'],
          subject: 'Team Update - Project Status',
          htmlContent: `
            <h2>Project Status Update</h2>
            <p>Dear Team,</p>
            <p>Here's the latest update on our project progress...</p>
          `,
          textContent: 'Project Status Update\n\nDear Team,\n\nHere\'s the latest update...',
          category: 'notification',
          priority: 'normal'
        })
        console.log('Email sent to multiple recipients')
      } catch (error) {
        console.error('Failed to send email:', error)
      }
    }

    // Example 2: Send email with CC and BCC
    const sendEmailWithCcBcc = async () => {
      try {
        await sendEmail({
          to: 'primary@example.com',
          cc: ['manager@example.com', 'team-lead@example.com'],
          bcc: ['admin@example.com', 'archive@example.com'],
          subject: 'Important Announcement',
          htmlContent: `
            <div style="font-family: Arial, sans-serif;">
              <h2>Important Company Announcement</h2>
              <p>This message is being sent to all relevant stakeholders.</p>
              <ul>
                <li>Primary recipient will see this directly</li>
                <li>CC recipients are visible to all</li>
                <li>BCC recipients are hidden from others</li>
              </ul>
            </div>
          `,
          textContent: 'Important Company Announcement\n\nThis message is being sent to all relevant stakeholders...',
          category: 'notification',
          priority: 'high',
          replyTo: 'noreply@company.com'
        })
        console.log('Email sent with CC and BCC')
      } catch (error) {
        console.error('Failed to send email with CC/BCC:', error)
      }
    }

    // Example 3: Send notification email using the utility function
    const sendTeamNotification = async () => {
      try {
        await sendNotificationEmail({
          to: ['dev-team@example.com'],
          cc: ['project-manager@example.com'],
          bcc: ['cto@example.com'],
          subject: 'Code Review Required',
          message: `
            <p>A new pull request has been submitted and requires code review.</p>
            <p><strong>PR #123:</strong> Implement user authentication</p>
            <p><strong>Author:</strong> John Doe</p>
            <p><a href="https://github.com/company/repo/pull/123">View Pull Request</a></p>
          `,
          priority: 'normal'
        })
        console.log('Team notification sent')
      } catch (error) {
        console.error('Failed to send team notification:', error)
      }
    }

    // Example 4: Validate email addresses before sending
    const validateAndSend = async () => {
      const recipients = ['valid@example.com', 'invalid-email', 'another@example.com']
      
      if (!validateEmailAddresses(recipients)) {
        console.error('Some email addresses are invalid')
        return
      }

      const totalRecipients = countTotalRecipients({
        to: recipients,
        cc: ['cc@example.com'],
        bcc: ['bcc1@example.com', 'bcc2@example.com']
      })

      console.log(`Total recipients: ${totalRecipients}`)

      if (totalRecipients <= 100) { // Check against limit
        await sendEmail({
          to: recipients,
          cc: 'cc@example.com',
          bcc: ['bcc1@example.com', 'bcc2@example.com'],
          subject: 'Validated Email Send',
          htmlContent: '<p>This email was sent after validation.</p>',
          category: 'system'
        })
      }
    }

    // Example 5: Format email addresses utility
    const demonstrateFormatting = () => {
      const singleEmail = 'user@example.com'
      const multipleEmails = ['user1@example.com', 'user2@example.com']

      const formatted1 = formatEmailAddresses(singleEmail)
      const formatted2 = formatEmailAddresses(multipleEmails)

      console.log('Formatted single:', formatted1) // ['user@example.com']
      console.log('Formatted multiple:', formatted2) // ['user1@example.com', 'user2@example.com']
    }

    // Uncomment to test examples
    // sendToMultipleRecipients()
    // sendEmailWithCcBcc()
    // sendTeamNotification()
    // validateAndSend()
    // demonstrateFormatting()

  }, [sendEmail, sendNotificationEmail, validateEmailAddresses, countTotalRecipients, formatEmailAddresses])

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-4">AWS SES Email Integration Examples</h1>
      
      <div className="space-y-6">
        <div className="bg-gray-50 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-2">Features Added:</h2>
          <ul className="list-disc list-inside space-y-1 text-sm">
            <li><strong>CC (Carbon Copy):</strong> Recipients visible to all other recipients</li>
            <li><strong>BCC (Blind Carbon Copy):</strong> Hidden recipients not visible to others</li>
            <li><strong>Multiple TO Recipients:</strong> Send to multiple primary recipients</li>
            <li><strong>Email Validation:</strong> Automatic validation of email addresses</li>
            <li><strong>Recipient Limits:</strong> Enforced limits (50 per field, 100 total)</li>
            <li><strong>Cost Calculation:</strong> Accurate cost calculation based on total recipients</li>
            <li><strong>Enhanced Logging:</strong> Complete logging of all recipient types</li>
          </ul>
        </div>

        <div className="bg-blue-50 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-2">Usage Examples:</h2>
          <div className="space-y-2 text-sm font-mono">
            <p><strong>Single recipient:</strong> to: 'user@example.com'</p>
            <p><strong>Multiple recipients:</strong> to: ['user1@example.com', 'user2@example.com']</p>
            <p><strong>With CC:</strong> cc: ['manager@example.com']</p>
            <p><strong>With BCC:</strong> bcc: ['admin@example.com', 'archive@example.com']</p>
          </div>
        </div>

        <div className="bg-yellow-50 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-2">Environment Variables Required:</h2>
          <pre className="text-sm font-mono bg-gray-800 text-green-400 p-3 rounded">
{`# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key_here  
AWS_SECRET_ACCESS_KEY=your_secret_access_key_here

# SES Configuration
AWS_SES_FROM_EMAIL=noreply@yourcompany.com
AWS_SES_REPLY_TO=support@yourcompany.com
SES_CONFIGURATION_SET=depllc-crm-emails`}
          </pre>
        </div>

        <div className="bg-green-50 p-4 rounded-lg">
          <h2 className="text-lg font-semibold mb-2">Integration Complete!</h2>
          <p className="text-sm">
            The AWS SES integration now supports CC, BCC, and multiple recipients with proper validation,
            logging, and cost calculation. Use the EmailComposer component for a full UI experience.
          </p>
        </div>
      </div>
    </div>
  )
}

// Usage in a Next.js page or component:
// import { EmailComposer } from '@/components/email/email-composer'
// import { EmailExamples } from '@/components/email/email-examples'
//
// export default function EmailPage() {
//   return (
//     <div className="container mx-auto py-8">
//       <EmailComposer 
//         onEmailSent={() => console.log('Email sent successfully!')}
//         defaultCategory="notification"
//       />
//       <EmailExamples />
//     </div>
//   )
// }