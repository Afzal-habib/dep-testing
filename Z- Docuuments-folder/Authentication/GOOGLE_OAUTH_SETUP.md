# Google OAuth Setup Guide

## Setting up Google OAuth for the CRM Application

### 1. Google Cloud Console Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API:
   - Navigate to "APIs & Services" > "Library"
   - Search for "Google+ API" and enable it
4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Choose "Web application"
   - Add authorized JavaScript origins:
     - `http://localhost:3000` (for development)
     - `https://yourdomain.com` (for production)
   - Set the following authorized redirect URIs:
     - `http://localhost:3000/api/auth/callback/google` (for development)
     - `https://yourdomain.com/api/auth/callback/google` (for production)

### 2. Environment Variables

Add these to your `.env.local` file:

```bash
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
```

### 3. How Google Login Works with 2FA

The Google login system is integrated with our existing 2FA system:

1. **User clicks "Continue with Google"**
2. **Google authentication occurs**
3. **System checks if user exists and is active**
4. **If user has `twoFactorEnabled: true`:**
   - Redirects to 2FA verification page
   - User must enter OTP sent to their email
5. **If user has `twoFactorEnabled: false`:**
   - Redirects directly to dashboard

### 4. Security Features

- ✅ **Existing Users Only**: Only allows Google login for users who already exist in the database
- ✅ **Active Accounts Only**: Deactivated accounts cannot use Google login
- ✅ **2FA Integration**: Respects user's 2FA preference
- ✅ **Audit Logging**: Failed Google login attempts are logged
- ✅ **Rate Limiting**: Google login is subject to the same rate limits as regular login

### 5. User Experience

**For users with 2FA disabled:**
```
Click "Continue with Google" → Google OAuth → Dashboard
```

**For users with 2FA enabled:**
```
Click "Continue with Google" → Google OAuth → 2FA Page → Enter OTP → Dashboard
```

### 6. Error Handling

The system handles various error scenarios:
- Google authentication failure
- User doesn't exist in database
- Account is deactivated
- Network errors during authentication
- 2FA verification failures

### 7. Testing

To test Google login:
1. Ensure you have valid Google OAuth credentials
2. Create a user account with the same email as your Google account
3. Set `twoFactorEnabled: true/false` based on desired testing scenario
4. Click "Continue with Google" on the login page

### 8. Troubleshooting

**Common Issues:**

1. **"redirect_uri_mismatch" error:**
   - Check that your Google Cloud Console has the correct redirect URI: `http://localhost:3000/api/auth/callback/google`
   - Ensure authorized JavaScript origins includes: `http://localhost:3000`
   - Wait a few minutes after updating settings in Google Cloud Console

2. **"invalid_client" error:**
   - Verify your `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are correct
   - Check that your `.env.local` file is in the root directory
   - Restart your development server after adding environment variables

3. **User not found error:**
   - Ensure a user exists in your database with the same email as your Google account
   - Check that the user's status is "active"

### 9. Quick Setup Steps

1. **Create Google OAuth App:**
   ```
   Google Cloud Console → APIs & Services → Credentials → Create OAuth 2.0 Client ID
   ```

2. **Configure Redirect URIs:**
   ```
   Authorized JavaScript origins: http://localhost:3000
   Authorized redirect URIs: http://localhost:3000/api/auth/callback/google
   ```

3. **Add Environment Variables:**
   ```bash
   # Add to .env.local
   GOOGLE_CLIENT_ID=your_actual_client_id
   GOOGLE_CLIENT_SECRET=your_actual_client_secret
   ```

4. **Restart Development Server:**
   ```bash
   npm run dev
   ```

### 10. Production Deployment

When deploying to production:
1. Update redirect URIs in Google Cloud Console
2. Set production environment variables
3. Ensure HTTPS is enabled
4. Update `NEXTAUTH_URL` to your production domain