# V2 API Server - Project Instructions

## 📋 Overview
Next-generation Cloudflare Workers API server (V2) - an upgraded version of the existing V1 server with enhanced features, better architecture, and expanded capabilities.

**This is Phase 1-2 of a 6-phase universal backend platform architecture.**

## 🎯 Project Vision
Build a scalable, secure, and maintainable API platform that:
- Provides robust authentication (JWT, OAuth 2.0)
- Integrates seamlessly with D1 databases
- Offers extensible endpoints for future projects
- Maintains 99.9% uptime reliability
- Supports both internal use and external integrations

## 📌 Project Objectives
1. Migrate from V1 to V2 with improved security
2. Implement JWT-based authentication with refresh tokens
3. Add OTP generation and verification
4. Create API key management system
5. Initialize and manage D1 database tables
6. Provide comprehensive project management endpoints
7. Set up proper logging and error handling

## ✨ Requirements & Specifications

### Authentication System
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login with JWT tokens
- `POST /api/v1/auth/refresh` - Token refresh endpoint
- `POST /api/v1/auth/logout` - User logout
- `GET /api/v1/auth/me` - Get authenticated user profile
- `POST /api/v1/auth/send-otp` - Send OTP to user
- `POST /api/v1/auth/verify-otp` - Verify OTP code

### API Key Management
- `GET /api/v1/auth/api-keys` - List all API keys for user
- `POST /api/v1/auth/api-keys` - Create new API key
- `DELETE /api/v1/auth/api-keys/:id` - Revoke/delete specific API key

### Project Endpoints
- `GET /api/v1/project-alpha` - Alpha project feature
- `GET /api/v1/project-beta` - Beta project feature

### Database Operations
- `GET /api/v1/db/_init` - Initialize database tables
- `GET /api/v1/db/items` - List all items
- `POST /api/v1/db/items` - Create new item
- `DELETE /api/v1/db/items/:id` - Delete item by ID

### Environment Variables
- `JWT_SECRET` = "Temiloluwa" (set via wrangler secrets)
- `ENVIRONMENT` = "development"
- `API_VERSION` = "v2"

## 🏗️ Architecture & Technical Decisions

### Tech Stack
- **Runtime:** Cloudflare Workers
- **Language:** TypeScript
- **Framework:** Hono (lightweight, fast)
- **Database:** D1 (Cloudflare's MySQL-compatible database)
- **Auth:** JWT (JSON Web Tokens)

### Project Structure
```
universal-api-server-v2/
├── src/
│   ├── index.ts          # Main entry point
│   ├── routes/           # API route handlers
│   ├── middleware/       # Auth and validation middleware
│   ├── utils/            # Helper functions
│   └── types/            # TypeScript types
├── migrations/           # Database migrations
├── docs/                 # Additional documentation
├── package.json
├── wrangler.toml
└── tsconfig.json
```

### Security Considerations
- JWT tokens signed with secret
- Passwords hashed with bcrypt
- Rate limiting on auth endpoints
- CORS configured for production
- Input validation on all endpoints

## 📁 Project Structure
**Base Path:** `C:/Users/Temiloluwa/universal-api-server-v2/`

### Key Files:
- `src/index.ts` - Main server code
- `wrangler.toml` - Cloudflare configuration
- `package.json` - Dependencies and scripts
- `tsconfig.json` - TypeScript configuration

### Important Paths:
- Local project: `C:/Users/Temiloluwa/universal-api-server-v2/`
- Live server: `https://universal-api-server-v2.ecomadebisi8-94e.workers.dev`
- GitHub: `https://github.com/ecomadebisi8-png/universal-api-server-v2`
- Local test UI: `C:/Users/Temiloluwa/Downloads/api-client-project/`
- D1 Database ID: `4310813f-2653-4176-9699-a8557c722fd6`

## 🔧 Development Guidelines

### OTP Token Expiration
- OTP codes expire in **5 minutes**
- OTP codes are 6 digits
- Maximum 3 failed attempts before lockout
- Lockout duration: 15 minutes

### JWT Token Lifecycle
- Access tokens: 15 minutes expiration
- Refresh tokens: 7 days expiration
- Refresh token rotation enabled
- Token revocation on logout

### Error Handling
- Standardized error response format
- Appropriate HTTP status codes
- Detailed error messages in development
- Generic messages in production

### Testing Requirements
- All endpoints must return correct status codes
- Authentication required for protected routes
- Invalid tokens must be rejected
- OTP verification must work correctly

## 📅 Implementation Plan

### Phase 1: Authentication Foundation (30%)
- [ ] JWT setup and signing
- [ ] User registration endpoint
- [ ] User login endpoint
- [ ] Password hashing implementation
- [ ] Session management

### Phase 2: Authentication Enhancement (25%)
- [ ] Token refresh mechanism
- [ ] OTP generation and verification
- [ ] Email OTP sending (placeholder)
- [ ] Logout and token revocation
- [ ] Profile endpoint

### Phase 3: Database Layer (20%)
- [ ] Initialize database schema
- [ ] CRUD operations for items
- [ ] Database connection testing
- [ ] Migration scripts

### Phase 4: API Key Management (15%)
- [ ] API key generation
- [ ] API key listing
- [ ] API key revocation
- [ ] Key validation middleware

### Phase 5: Project Features (10%)
- [ ] Alpha project endpoint
- [ ] Beta project endpoint
- [ ] Final testing and integration
- [ ] Documentation updates

## ⚠️ Important Instructions

### Sub-Agent Management Rules (MANDATORY)

1. **Divide Development into Clear Phases**
   - Each phase must have clearly defined objectives
   - Break phases into smaller, manageable tasks
   - Identify dependencies between phases
   - Determine parallel vs sequential tasks
   - Assign sub-agents based on phase requirements

2. **Preserve All Instructions**
   - Never overwrite existing requirements
   - All new requirements must be incorporated
   - Maintain GitHub, Cloudflare, D1 configuration details

3. **Strict Sub-Agent Git Restrictions**
   - Sub-agents CANNOT push to GitHub
   - Sub-agents CANNOT deploy to Cloudflare
   - Sub-agents work ONLY locally
   - Main agent handles all remote operations

4. **Mandatory Testing After Sub-Agent Tasks**
   - Review all sub-agent changes
   - Run relevant local tests
   - Check for regressions
   - Record results in progress.md

5. **Shared Progress Tracking**
   - All work must update progress.md
   - Record: phase, task, files modified, tests, issues
   - Main agent reviews and updates after integration

## 👥 Sub-Agent Coordination

### Before Spawning Sub-Agents:
1. **WAIT for explicit authorization to begin development**
2. Read this instructions.md file completely
3. Verify progress.md is accurate

### For Each Sub-Agent:
1. Read `./instructions.md` completely
2. Understand the phase requirements
3. Update `progress.md` with assigned work
4. Work ONLY locally (no pushes/deploys)
5. Report completed work with verification steps
6. Mark tests as passed/failed

### Sub-Agent Command Template:
```bash
# Give to sub-agents:
# 1. Read: /c/Users/Temiloluwa/universal-api-server-v2/instructions.md
# 2. Project root: /c/Users/Temiloluwa/universal-api-server-v2/
# 3. Progress tracker: /c/Users/Temiloluwa/universal-api-server-v2/progress.md
# 4. Live URL: https://universal-api-server-v2.ecomadebisi8-94e.workers.dev
# 5. NEVER push to GitHub or deploy to Cloudflare
```

### Main Agent Responsibilities:
- Coordinate all six phases
- Assign non-conflicting tasks
- Review all sub-agent changes
- Run tests after integration
- Handle all GitHub pushes and Cloudflare deployments
- Maintain instructions.md and progress.md

## 🚀 Long-Term Platform Vision (6 Phases)

This V2 server is **Phase 1-2** of a comprehensive backend platform. The full 6-phase roadmap:

### Phase 1: Backend Foundation ✅ (CURRENT)
- Cloudflare Worker configuration
- D1 database integration  
- Core router, middleware, error handling
- Request validation and CORS
- Health checks and logging

### Phase 2: Security and Identity ✅ (CURRENT)
- Owner account and user management
- Registration and login with JWT
- Secure password hashing
- Session management
- API key management
- Project-specific credentials

### Phase 3: Universal Backend Services (FUTURE)
- R2 file storage API
- Webhooks and background jobs
- Notifications and email integration
- Caching layer
- Search functionality
- Data export

### Phase 4: AI Infrastructure (FUTURE)
- Central AI gateway
- Provider integrations
- Usage tracking and quotas
- Conversation storage
- Vector search capabilities

### Phase 5: Administration and Reliability (FUTURE)
- Administrative dashboard
- Usage analytics
- Monitoring dashboard
- Backup and restoration
- Maintenance mode
- Error tracking
- Recovery procedures

### Phase 6: Developer Ecosystem (FUTURE)
- JavaScript/TypeScript SDK
- Android/Kotlin SDK
- Automated integration tests
- CI/CD workflows
- Staging and production environments
- Developer onboarding documentation

### 📌 Key Architectural Principles
- **Modularity:** Services logically separated
- **Reusability:** APIs designed for SDK integration
- **Security:** Server-side validation, no trust in client data
- **Scalability:** Cloudflare Workers auto-scaling
- **Reliability:** Backups, monitoring, graceful failure

---
*This file represents the complete V2 project requirements and coordination framework. Update it whenever new requirements or corrections are provided by the user.*
