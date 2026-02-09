
@@ -0,0 +1,799 @@
# AWS S3 File Storage Implementation - Digi Era Pro CRM

This document provides a comprehensive overview of the AWS S3 file storage implementation integrated into the Digi Era Pro CRM system, including architecture, components, usage patterns, and integration with AWS SES for email attachments.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [File Structure](#file-structure)
3. [Core Components](#core-components)
4. [Database Integration](#database-integration)
5. [API Implementation](#api-implementation)
6. [Frontend Components](#frontend-components)
7. [Email Integration](#email-integration)
8. [Security Features](#security-features)
9. [Usage Examples](#usage-examples)
10. [Configuration & Setup](#configuration--setup)
11. [Best Practices](#best-practices)
12. [Performance Optimizations](#performance-optimizations)

---

## Architecture Overview

The S3 implementation follows a multi-layered architecture with three distinct file storage categories:

```
AWS S3 Bucket Structure
├── profile-pictures/          # User avatars (max 1MB)
│   └── {userId}/
│       └── {timestamp}-{hash}-{filename}
├── documents/                 # Shared app documents (max 25MB)
│   └── {userId}/
│       └── {timestamp}-{hash}-{filename}
└── email-attachments/         # Email attachments (max 25MB)
    └── {userId}/
        └── {timestamp}-{hash}-{filename}

Application Architecture
├── Frontend (React Components)
│   ├── FileUpload (Generic)
│   ├── ProfilePictureUpload (Specialized)
│   ├── EmailAttachmentSelector
│   └── Enhanced EmailComposer
├── Custom Hooks
│   └── useFileUpload (File operations)
├── API Layer (Next.js Routes)
│   ├── /api/files (Upload/Download)