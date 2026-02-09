
CRM
Customer Relationship Management
Project Scope for Custom CRM System
Objective:
 Develop a CRM platform to streamline client and project management across Sales, Support, and IT departments with role-based access and task visibility.
Project Modules and Estimated Timeline(Phase-wise)
Phase 1: Project Setup & Architecture and Role base permissions(Weeks 1-2) -Completed
Next.js + Tailwind project setup
Strict TypeScript config, Redux Toolkit store
NextAuth with MongoDB adapter + bcryptjs
GitHub Actions pipeline with lint/tests/staging deploy
Base layout, header, sidebar, notification bell
Role-based middleware & environment variable scaffolding
Role-based permission system with dynamic assignment
Timeline: 2 weeks
Phase 2: Authentication & Authorization Module (Weeks 3-4)  -COMPLETED
Purpose: Multi-tier security with role-based access control
Multi-Tier Authentication: Admin (2FA ), Employee (2FA), Client (Global)
Dynamic Role Management: 10+ roles with hierarchical permissions
Security Enforcement: Network validation, session management, audit logging
Superadmin Protection: user with role super_admin(unrestricted)
User registration/login with security tier validation
Two-factor authentication for admins and Internal Employees on every login.
Session management with timeout
Timeline: 2 weeks
Phase 3: Department Management Module (Weeks 5)  - COMPLETED
Purpose: Organizational structure and coordination
Key Features:
Department creation/hierarchy
Employee assignment
Role management with dynamic permissions
Inter-department workflow
Performance tracking
Workflow Process:
Dynamic role creation per department
Role assignment to users
Access based on permissions
Organizational Structure:
Sales (Stages 1-4), Support (5-6), IT (7-9)
Client Services, Administration
Timeline: 1 weeks

Phase 4: Administrative Management Module (Weeks 6) - COMPLETED(Final Touch Pending)
Purpose: System administration and role management
Admin Functions:
User account creation/management
Role assignment and permission config
System settings and config
Security monitoring and audit logs
Department structure management
System Control:
Role hierarchy management 
Permission matrix config
Security policy enforcement
System backup and maintenance
Timeline: 1 week
Phase 5: Lead Generation & Client Management Module (Weeks 7-8) - COMPLETED
Purpose: Initial lead capture and qualification
Workflow Stages:
Lead(Stage 1): Basic info and Basic Project  submission
Sales Closer (Stage 2): Lead qualification -(Lead to Client Conversion)
Sales Agent (Stage 3): Quote/proposal creation
Support Agent - Client on Boarding 
Direct Project creation on Client module 
Key Features:
Client profile creation (details, requirements)
Lead scoring/qualification tracking
Quote/proposal management
Client communication history
Pipeline tracking/conversion metrics
Data Management:
Client contact/company details
Project requirements/scope
Sales activity/follow-up scheduling
Lead source/ROI analysis
Timeline: 2 weeks
Phase 6: Onboarding & Project Validation Module (Weeks 9) - Completed
Purpose: Project validation and requirement gathering
Workflow Stages:
Sales Manager: Project Basic info collection on the lead creation
Support Manager (Stage 5): Info validation and Project Updation
Support Agent (Stage 6): All Project information gathering
Enhancement/documentation
Project Phases and Milestone Management 
Key Features:
Ticket management with status tracking
Project categorization (Web, GMB, SEO, Graphics, Social)
Client requirement validation/enhancement
Document collection/verification
Quality Control:
Info validation checkpoints
Requirement completeness
Client communication tracking
Project scope finalization
Project Categorization
Timeline: 1 week
Phase 7: Approval & Task Creation Module (Weeks 10-11) - IN-PROGRESS
Purpose: Project approval and task breakdown
Workflow Stage:
Support Agent: Project Categorization (department-wise) 
Department Manager (Stage 7): Approval/task creation
Internal assigned users' real-time communications.
Key Features:
Project approval with decision tracking
Task breakdown into units(Sub-Tasks)
Resource allocation/timeline planning
Budget approval/cost estimation
Stakeholder notifications
Management Functions:
Feasibility assessment
Resource availability
Timeline/milestone planning
Risk assessment/mitigation
Timeline: 2 weeks
Phase 8: Execution & Task Management Module (Weeks 12-13) - COMPLETED
Purpose: Task execution and progress monitoring
Workflow Stages:
Team Lead (Stage 8): Subtask creation/assignment
Team Member (Stage 9): Execution/progress updates
Key Features:
Task assignment with priority levels
Progress tracking (real-time)
Time logging/productivity monitoring
Quality assurance/reviews
Internal collaboration
Execution Tracking:
Task status (To-Do, In Progress, Review, Completed)
Time tracking/billable hours
Progress/milestone reporting
Workload balancing
Timeline: 3 weeks
Phase 9: Real-Time Communication Module (Weeks 14-15) -(Basic Implement and In-Progress)
Purpose: Real-time communication with Socket.IO & WebRTC
Key Features:
Real-time text messaging with Socket.IO
Secure file sharing/uploads in chat
User to User,User to Client,,Project based Group,Department Based,Group/private chat rooms (project/task/client-based)
Role-based channel access   -Message history logging/search
Integration with Client Portal/Task Management
Audio Video Calls, Real time screen sharing using WebRTC
Communication Tools:
Socket.IO real-time updates
File attachment previews/downloads using AWS S3 bucket
Notifications for messages/mentions
Encrypted transmission   -Audit logs
Timeline: 2 weeks
Phase 10: Notification & Alert System Module (Weeks 16-17) 
Purpose: Real-time updates
Notification Types:
Task assignment
Project milestones
Client updates
Security breaches
System maintenance
Delivery Channels:
In-app, email, SMS (optional), dashboard
Timeline: 2 weeks
Phase 11: Client Portal & Communication Module (Web Version) (Weeks 18-23)
Purpose: Client interaction and visibility
Client Portal Features:
Project progress viewing/tracking
Document access/download
Team communication
Invoice/billing info
Social media API integration:
Google console
Facebook API
Instagram API
LinkedIn API
Yelp API


Communication Tools:
Real-time updates
Secure document sharing
Feedback collection
Support ticket management
Email notifications
Timeline: 2 weeks
Phase 12: Document & File Management Module (Weeks 24-25)
Purpose: Secure document handling
Key Features:
Secure file upload/storage
Version control/change tracking
Role-based access
Document approval workflows
Client sharing portal
Security Features:
Encrypted storage
Access logging/audit trails
Document expiration/archival
Secure sharing
Timeline: 2 weeks
Phase 13: Reporting & Analytics Module (Weeks 25-26)
Purpose: Performance monitoring
Dashboard Views:
Sales: Lead pipeline, conversion, revenue
Support: Ticket status, response times, satisfaction
IT: Task completion, timelines, resource use
Management: Overall metrics, efficiency
Reports Generation:
Department performance
Project timelines/milestones   -Client feedback
Financial/billing                      -Security audits
Timeline: 2 weeks
Phase 14: Testing, Optimization & Deployment (Weeks 26-27)
Comprehensive testing (unit, integration, security)
Performance optimization
Final deployment and documentation
Timeline: 2 weeks
Project Modules and Estimated Timeline (Graphical View)


Complete Professional Flow of CRM

CRM System - Modern Tech Stack Documentation
1. Core Technology Architecture
Purpose: Foundational tech stack
Frontend Layer
React 18.3.1, Next.js 15.5.3, TypeScript 5.7.2
Tailwind CSS 3.4, Radix UI, Lucide React
React Hook Form, Recharts, Redux Toolkit
Features: SSR, SSG, TypeScript safety, component-based design, responsive layout, form validation
Backend Layer
Next.js API Routes, Node.js, Mongoose ODM
Express Middleware, JOSE JWT, Helmet.js
API Structure: /app/api/ (auth, users, roles, departments, clients, projects, tasks, tickets, reports)
Database Layer
MongoDB Atlas, Mongoose 8.18.1
Connection Pooling, Indexing, Aggregation Pipeline
Schema: users, roles, permissions, departments, clients, projects, tasks, tickets, audit_logs, system_config
2. Authentication & Security
Purpose: Multi-tier security
NextAuth.js 4.24, MongoDB Adapter, JWT with JOSE
BCrypt.js, Rate Limiting, RBAC, Network Validation
Tiers: Admin (2FA ), Employee (2FA), Client (Global + Portal)
3. Development Tools
Purpose: Development workflow
TypeScript, ESLint, Autoprefixer, PostCSS
ts-node, dotenv
4. UI Components
Purpose: Reusable UI
Radix UI, Class Variance Auth
Tailwind Merge, Next Themes, Lucide React
Structure: /components/ (ui, forms, layout, auth, charts, tables, modals)
5. State & Data Flow
Purpose: State management & Cache System
Redux Toolkit, Redux Persist, React Hook Form
React Query, Context API
Tans Stack Query
6. Database Management
Purpose: Schema and data
Scripts: npm run migrate, db:seed, db:fresh, roles:setup
Scripts: /scripts/ (migrations, seeders, setup-*.ts, reset-db.ts)
7. Performance & Optimization
Purpose: Enhance efficiency
Frontend
Code Splitting, Image Optimization, CSS Minification, Bundle Analysis
Backend
API Rate Limiting, Database Indexing, Connection Pooling, Caching
Security
CSRF, XSS Prevention, NoSQL Injection Safe, Input Validation






Multi-Layered Security Architecture:
┌─────────────────────────────────────────────────────────────┐
│                      Client Layer                           │
│  • Input validation  • XSS protection  • CSRF protection   │
│  • Client-side route protection  • UI access control      │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Middleware Layer                          │
│  • Rate limiting  • Request validation  • Security headers │
│  • Security tier enforcement  • Route access control       │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                Multi-Tier Authentication Layer              │
│  ┌─────────────────┬─────────────────┬─────────────────┐    │
│  │     ADMIN       │    EMPLOYEE     │     CLIENT      │    │
│  │ • 2FA (TOTP)    │ • Credentials   │ • Credentials   │    │
│  │ • Global Access │ • 2FA (TOTP     │ • Global Access │    │
│  │ • Session mgmt  │ • Session mgmt  │ • Portal only   │    │
│  └─────────────────┴─────────────────┴─────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│              Dynamic Authorization Layer                    │
│  • RBAC with hierarchy levels  • Dynamic permission eval   │
│  • Context-aware permissions   • Resource-level access     │
│  • Action-based control        • Department constraints    │
│  • Real-time permission cache  • Permission inheritance    │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                Security Enforcement Layer                   │
│  • Permission validation per request                       │
│  • Security tier + role combination checks                 │
│  • Access attempt logging & monitoring                     │
│  • Failed access lockout & rate limiting                   │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                   Business Layer                            │
│  • Input sanitization  • Business logic  • Data validation │
│  • Permission-aware operations  • Audit trail generation   │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                    Data Layer                               │
│  • Encrypted storage  • Comprehensive audit trails         │
│  • Permission-based queries  • Secure backup systems       │
│  • Data access logging  • Multi-tier data isolation        │
└─────────────────────────────────────────────────────────────┘













Multi-Layered Security Architecture Flow Diagram:

All Security Threats and its Solution
1️⃣ Weak Authentication / Password Storage
Threats: Plain text passwords, weak auth flows, single-factor admin logins, session fixation
Solutions: Strong auth with NextAuth.js, bcrypt hashing, JWT security, enforced 2FA for admins, account lockouts, secure session cookies (Redis-backed)

2️⃣ Unvalidated Input / API Abuse
Threats: SQL/NoSQL injection, code injection, API flooding, malformed requests
Solutions: Input validation (Zod, express-validator), sanitization, strict CORS, rate limiting, payload size limits

3️⃣ Device & Network Access Control
Threats: Unauthorized device access, external network infiltration, compromised personal devices
Solutions: IP whitelisting, VPN-only admin access, mTLS certificates, geolocation/IP reputation checks, device fingerprinting

4️⃣ Cross-Site Scripting (XSS) & Insecure Headers
Threats: Stored/reflected XSS, missing headers, clickjacking, content injection
Solutions: Strict CSP, security headers (X-Frame-Options, nosniff, Referrer-Policy), DOMPurify sanitization, nonce-based scripts

5️⃣ Broken Access Control / Authorization
Threats: Horizontal & vertical privilege escalation, bypass of RBAC, resource-level violations


Solutions: RBAC with inheritance, route-level middleware, department-level isolation, conditional permissions, approval workflows

6️⃣ Secrets Management & Environment Security
Threats: Hardcoded keys, env leaks, config drift, secrets in Git
Solutions: Encrypted env vars, environment segregation, secret rotation/scanning, secure key management (DB/API/JWT)



7️⃣ Data Security & Storage Protection
Threats: Breaches, insecure file storage, weak backups, insecure transmission
Solutions: Encryption at rest/in transit, TLS 1.3, encrypted file storage, PII masking, retention policies, prepared queries, access logging

8️⃣ Session Management & Token Security
Threats: Hijacking, replay attacks, weak session handling
Solutions: HTTPOnly + Secure cookies, SameSite=Strict, Redis session store, short-lived JWTs with refresh rotation, anomaly detection

9️⃣ Audit Trail & Compliance Logging
Threats: Missing or tampered logs, weak compliance visibility
Solutions: Write-only audit logging of CRUD + auth events, structured searchable logs, real-time admin monitoring, compliance-ready reports

🔟 Infrastructure & Deployment Security
Threats: CI/CD leaks, container vulnerabilities, config drift, supply chain risks


Solutions: Secure pipelines (Snyk, CodeQL), dependency pinning, IaC, environment isolation, container scanning, runtime monitoring

1️⃣1️⃣ Monitoring & Incident Response
Threats: Blind spots, delayed detection, poor recovery
Solutions: Centralized monitoring & alerts, backup + DR plans, incident playbooks, proactive response drills


Mobile Version Of CRM
Our primary/main focus is on Web-Based CRM, as it contains all functionality
However, there is another version of CRM, which is mobile-based. In a Mobile-Based CRM, we handle specific modules, such as a client portal, and provide limited functionality to the users. As mobile devices are not capable of handling all functionalities, it is not possible and recommended to provide all functionalities to the user.
CRM is usually Web-based, and in a mobile version, we provide limited functionality and access to the user/client.
Accessibility - If we want to provide a mobile-based app to specific users, we deploy it privately and provide the APK file or link to the user/client who has access to the credentials.
https://docs.google.com/document/d/15Bh9Fpm_E8lG4klO1MwcM_1mz11c2wH0rkkJT8ykH7M/edit?usp=sharing

1️⃣ Direct APK Distribution
Host your APK on your own website, Google Drive, Dropbox, or any server.


Users download and manually install the APK.


Users must enable “Install from Unknown Sources” (or “Allow this source”) on their devices.
Pros: Free, fast, full control.
 Cons: Less trust (users see warnings), harder to auto-update, no Play Protect scanning.
CRM System Requirements Analysis
 Current Flow Summary
1. Sales Team → Client acquisition and basic info gathering
2. Support Team → Client info enhancement, project creation, and assignment
3. Department Manager → Project approval, task assignment, and team coordination
4. Team Lead → Sub-task creation and daily progress management
5. Team Member → Task execution and status updates
6. Client Portal → Project visibility and communication
7. Admin → Overall system management and permissions
Professional CRM Flow Enhancement
Lead Generation → Qualification → Project Scoping → Approval → Execution → Delivery → Maintenance
Detailed Flow:
1. Lead Management (Sales Team)
2. Client Onboarding (Support Team)
3. Project Planning (Project Manager + Department Head)
4. Resource Allocation (Department Manager)
5. Task Execution (Team Lead + Team Members)
6. Quality Assurance (QA Team)
7. Client Communication (Account Manager)
8. Project Delivery (Delivery Team)
9. Post-Project Support (Support Team)

Missing Critical Features
 Essential Additions:
1. Financial Management
1. Budget tracking and cost estimation
2. Invoice generation and payment tracking
3. Profitability analysis per project
2. Time Management
1. Time tracking for tasks and projects
2. Automated timesheet generation
3. Billable hours calculation
3. Document Management
1. Version control for project documents
2. Digital signature capabilities
3. Secure file sharing
 Important Demo Questions & Answers
 1. Daily Basis Updates
Q: How to handle tasks for already closed projects?
A: Implement project status hierarchy with "Closed-Pending Updates" status allowing limited modifications with an approval workflow.
 2. Long-term Project Management
Q: How to handle tasks/sub-tasks for projects with long-term assignments on a daily basis?
A: Implement milestone-based tracking with weekly/monthly review cycles and automated progress reports.
 3. Sub-task Creation Authority
Q: Who creates the sub-tasks?
A: Team leads and project managers can create sub-tasks. Team members can request sub-task creation through approval workflow.
4. Permission Management
Q: How to handle permissions for all roles?
A: Implement role-based access control (RBAC) with granular permissions and inheritance hierarchy.
5. Task Updates
Q: How to handle and update tasks/sub-tasks?
A: Real-time updates with a notification system, version control for changes, and approval workflow for critical modifications.
6. Sub-project Creation
Q: How to create sub-projects of assigned tasks/projects?
A: Hierarchical project structure with parent-child relationships and cascading permissions.
7. Team Communication
Q: How to communicate between teams/team members and support team/client?
A: Multi-channel communication system with internal messaging, client portal, and integrated email/SMS notifications.
8. Complaint/Review Management
Q: How to handle complaints/reviews between the client and support team?
A: Dedicated complaint management system with SLA tracking, escalation matrix, and resolution workflows.


Questions for Understanding the Current Flow
Business Understanding:
1. What is your primary business model and revenue streams?
The company’s primary business model is providing services like:
Development (WordPress)
Graphics (Logo Design, Business Cards, Video Editing)
SEO (On Page + Off-Page)
Marketing (Yelp)
2. What are your current pain points in project management?
Communication
Monitoring
3. How many clients do you typically handle simultaneously?
10 - 15 (simultaneously)
4. What is your average project duration and complexity?
Depends on the Project, usually (7 - 10) days
5. How do you currently measure project success?
By the client’s feedback
By the client’s retention period
Operational Requirements:
6. How many departments and team members will use this?
Web - WordPress Development
Graphics
SEO (On-Page + Off-Page)
 Sales
Support
GMB (Google Business Management)
Social Media
HR
Accounting
Quality Assurance(QA) -> will be added soon
7. What is your current project approval process?
Support Team assigns the project to Team Lead / Team Manager
Team Lead / Team Manager assigns the project to Members
No, definite process right now
8. How do you handle client communications currently? And how many email sales agent/support managers/agents are used for communication with multiple clients?
Client is hunted through Yelp
Sales Agent & Sales Closer make a deal with the Sales Team
Then, the client redirects to the Support Team
Support Team takes necessary details and requirements about the project.
9. What are your reporting and analytics needs? 
Different Graphs could be shown on CRM or Client Portal
On CRM, monitoring on employees
On Client Portal, monitoring on progress
10. Do you have any compliance or regulatory requirements?

Technical Considerations:
11. Do you need integration with existing tools?
If companies intra-communication would be on CRM, then it would be a great privilege.
12. What is your preferred deployment model (cloud/on-premise)?
Not really, it would be decided by Development Team.
13. What are your security and data privacy requirements?
Security is our crucial part and main concern. People other than clients and organization cannot use our Product.
14. Do you need mobile access for field teams?
No, only company’s systems should be use for CRM.
Future Planning:
16. What are your growth projections for the next 2-3 years?
17. Do you plan to expand to new markets or services?
Gradually, but not instantly.
19. How do you handle seasonal workload variations?
Seasonal workloads would be balanced, as there are more client demands one service, then other service is not in trending. So that’s why it would be balanced.
20. What is your disaster recovery and business continuity plan?





MongoDB  - Database Integration
For 30-50 users (M10):
Specs (Included): 2 vCPU, 2 GB RAM, 10 GB storage
Pricing: (25-35)$ for 12 hrs. Or (55-60)$ for 24/7
Operation Supported: (500-1000) ops/sec

For 50-100 users (M20):
Specs (Included): 2 vCPU, 4 GB RAM, 10 GB storage
Pricing: (55-65)$ for 12 hrs. Or (100-120)$ for 24/7
Operation Supported: (1000-2000) ops/sec

 Monitor via Atlas dashboards (CPU >70%, latency >100ms, or storage nearing 5 GB). Enable auto-scaling to adjust storage dynamically(storage can be increased)
Sharding:    
If we apply sharding, means it charges for extra clusters or replica sets  i.e
	3 x M10(Pricing) = 1 Primary Cluster + 2 Secondary Clusters
Backup:
  	No Additional Cost

File Handling

1️⃣ Direct-to-S3 Uploads (Best Practice)
Instead of uploading to your Node server first, let the browser upload directly to S3 using a pre-signed URL:
Flow:
Client asks your backend for a signed upload URL.
Browser PUTs the file directly to S3.
Your server gets a WebSocket event or webhook when done.
➡️ Your Node server only handles metadata and auth — not the heavy file transfer.
 This scales beautifully (even thousands of concurrent uploads).
💰 Cost Estimate (per month)
S3 Standard - General-purpose storage for any type of data, typically used for frequently accessed data
Typical Hardware                                                                         Est. Cost :                                                                                     


First 50 TB / Month
$0.023 per GB
Next 450 TB / Month
$0.022 per GB
Over 500 TB / Month
$0.021 per GB


First 5GB(free tier)
50GB * 0.023 = 1.15$
100GB * 0.023 = 2.30$
2️⃣ Use Streaming (Not Memory Buffers)
If you do handle files through Node (for virus scans, etc.), use streaming uploads (busboy, multer, memoryStorage with care) — never load whole files into RAM.
Cost Estimate (per month)
Tier
Typical Hardware
Suitable For
Est. Cost
Basic single VPS
2 vCPU / 4 GB RAM
100 light users, few uploads
~$20–$25
Mid-tier
4 vCPU / 8 GB RAM
100 users, active file sharing
~$40–$60
Scaled (HA)
2× 4 vCPU / 8 GB nodes + Redis
200+ users
~$80–$120


🧾 Summary
✅ Yes, multiple users uploading files → heavier server load.
 ✅ Best solution → stream or direct-upload to cloud storage (S3/R2/Spaces).
 ✅ Use reverse proxy + rate limiting + streaming to keep your Node server responsive.
 ✅ Budget about $40–$60/month for a stable 4 vCPU/8 GB RAM instance if file sharing is common.






