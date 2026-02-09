# AWS S3 Integration Setup

This document outlines the setup process for AWS S3 integration in the Digi Era Pro CRM system.

## Overview

The S3 integration provides secure file storage for three different types of files:
1. **Profile Pictures** (max 1MB) - User profile images
2. **Documents** (max 25MB) - Shared documents within the application  
3. **Email Attachments** (max 25MB) - Files attached to emails sent via AWS SES

All files are organized in separate folders within your S3 bucket and integrate seamlessly with the existing AWS SES email system.

## Required Environment Variables

Add the following environment variables to your `.env.local` file:

```bash
# AWS Configuration (shared with SES)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key_id
AWS_SECRET_ACCESS_KEY=your_secret_access_key

# S3 Specific Configuration
AWS_S3_BUCKET_NAME=your-crm-bucket-name

# SES Configuration (existing)
AWS_SES_FROM_EMAIL=noreply@yourdomain.com
AWS_SES_REPLY_TO=support@yourdomain.com
SES_CONFIGURATION_SET=your-configuration-set-name

# Optional: Webhook security
WEBHOOK_SECRET=your-webhook-secret-for-ses-notifications
```

## AWS S3 Bucket Setup

### 1. Create S3 Bucket

```bash
aws s3 mb s3://your-crm-bucket-name --region us-east-1
```

### 2. Configure Bucket Policy

Create a bucket policy that allows your application to read, write, and delete objects:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CRMApplicationAccess",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:user/your-crm-user"
            },
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:GetObjectVersion"
            ],
            "Resource": "arn:aws:s3:::your-crm-bucket-name/*"
        },
        {
            "Sid": "CRMBucketAccess",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:user/your-crm-user"
            },
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": "arn:aws:s3:::your-crm-bucket-name"
        }
    ]
}
```

### 3. Configure CORS (if accessing from browser)

```json
[
    {
        "AllowedHeaders": ["*"],
        "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
        "AllowedOrigins": ["https://yourdomain.com", "http://localhost:3000"],
        "ExposeHeaders": ["ETag"],
        "MaxAgeSeconds": 3000
    }
]
```

### 4. Enable Versioning (recommended)

```bash
aws s3api put-bucket-versioning --bucket your-crm-bucket-name --versioning-configuration Status=Enabled
```

## IAM User Permissions

Your IAM user needs the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:GetObjectVersion",
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::your-crm-bucket-name",
                "arn:aws:s3:::your-crm-bucket-name/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ses:SendEmail",
                "ses:SendRawEmail",
                "ses:GetSendQuota",
                "ses:GetSendStatistics"
            ],
            "Resource": "*"
        }
    ]
}
```

## Folder Structure

The S3 bucket will automatically organize files into the following structure:

```
your-crm-bucket-name/
├── profile-pictures/
│   └── {userId}/
│       └── {timestamp}-{hash}-{filename}
├── documents/
│   └── {userId}/
│       └── {timestamp}-{hash}-{filename}
└── email-attachments/
    └── {userId}/
        └── {timestamp}-{hash}-{filename}
```

## File Type Configurations

### Profile Pictures
- **Max Size**: 1MB
- **Allowed Types**: JPEG, PNG, WebP, GIF
- **URL Expiry**: 7 days
- **Use Cases**: User avatars, profile images

### Documents
- **Max Size**: 25MB
- **Allowed Types**: PDF, Word, Excel, PowerPoint, TXT, CSV, Images
- **URL Expiry**: 24 hours
- **Use Cases**: Project documents, contracts, reports

### Email Attachments
- **Max Size**: 25MB per file
- **Allowed Types**: PDF, Office documents, Images, ZIP files
- **URL Expiry**: 30 days
- **Use Cases**: Files sent via email through SES integration

## Usage Examples

### Profile Picture Upload
```typescript
import { ProfilePictureUpload } from '@/components/upload/profile-picture-upload'

<ProfilePictureUpload
  currentImageUrl={user.profileImage}
  onImageUploaded={(imageData) => {
    // Update user profile with new image
    updateUserProfile({ profileImage: imageData.url, profileImageKey: imageData.key })
  }}
  onImageRemoved={() => {
    // Remove profile image
    updateUserProfile({ profileImage: null, profileImageKey: null })
  }}
/>
```

### Document Upload
```typescript
import { FileUpload } from '@/components/upload/file-upload'

<FileUpload
  fileType="DOCUMENTS"
  multiple={true}
  maxFiles={5}
  onFilesUploaded={(files) => {
    // Handle uploaded documents
    console.log('Uploaded documents:', files)
  }}
  clientId={currentClient.id}
/>
```

### Email with S3 Attachments
```typescript
import { EmailComposer } from '@/components/email/email-composer'

<EmailComposer
  onEmailSent={() => {
    console.log('Email sent successfully with S3 attachments!')
  }}
  defaultCategory="notification"
/>
```

## API Endpoints

### File Operations
- `POST /api/files` - Upload file directly
- `GET /api/files?key={key}&fileType={type}` - Get presigned URL for file access
- `DELETE /api/files/{key}` - Delete file
- `POST /api/files/presigned-url` - Get presigned URL for direct browser upload

### Email with Attachments
- `POST /api/email` - Send email (automatically detects S3 attachments)
- `GET /api/email` - Get email analytics (includes attachment statistics)
- `GET /api/email/quota` - Get SES sending quota

## Security Features

1. **Server-side Encryption**: All files encrypted at rest using AES256
2. **Presigned URLs**: Time-limited access URLs for secure file access
3. **File Validation**: Size and type validation before upload
4. **User Isolation**: Files organized by user ID to prevent cross-user access
5. **Access Control**: API routes protected by authentication middleware

## Monitoring and Costs

### Cost Estimation
- **Storage**: ~$0.023 per GB per month
- **Requests**: ~$0.0004 per 1,000 PUT requests
- **Data Transfer**: First 1GB free per month
- **Email Attachments**: Additional $0.0001 per attachment

### CloudWatch Metrics
Monitor these metrics in AWS CloudWatch:
- `BucketSizeBytes` - Total bucket size
- `NumberOfObjects` - Total number of files
- Request metrics for API calls

## Troubleshooting

### Common Issues

1. **"Access Denied" errors**
   - Check IAM permissions
   - Verify bucket policy is correctly applied
   - Ensure AWS credentials are properly configured

2. **File upload fails**
   - Check file size limits
   - Verify file type is allowed
   - Ensure bucket exists and is accessible

3. **Email attachments not working**
   - Verify S3 file exists and is accessible
   - Check file isn't corrupted
   - Ensure SES has permission to access the file

4. **Presigned URLs expired**
   - URLs have configurable expiry times
   - Generate new URLs for expired links
   - Consider shorter expiry times for security

### Testing the Integration

Run these tests to verify everything is working:

```bash
# Test file upload
curl -X POST http://localhost:3000/api/files \
  -H "Authorization: Bearer your-token" \
  -F "file=@test-image.jpg" \
  -F "fileType=PROFILE_PICTURES"

# Test email with S3 attachment
curl -X POST http://localhost:3000/api/email \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "to": "test@example.com",
    "subject": "Test with S3 Attachment",
    "htmlContent": "<p>Test email with attachment</p>",
    "category": "system",
    "s3Attachments": [{
      "key": "email-attachments/user123/1234567890-abc123-document.pdf",
      "filename": "document.pdf",
      "contentType": "application/pdf"
    }]
  }'
```

## Migration from Existing System

If you have existing files, you can migrate them:

1. **Backup existing files**
2. **Upload to S3** using the established folder structure
3. **Update database references** to use S3 keys instead of local paths
4. **Test thoroughly** before removing local files

## Performance Optimization

1. **Use CloudFront CDN** for frequently accessed files
2. **Enable S3 Transfer Acceleration** for global users
3. **Implement caching** for presigned URLs
4. **Use multipart uploads** for large files (>100MB)

This completes the AWS S3 integration setup for your CRM system. The integration provides secure, scalable file storage with seamless email attachment support.