# Universal API Server V2

Next-generation Cloudflare Workers API server built with TypeScript + Hono.

## Features
- JWT-based authentication
- OAuth 2.0 refresh token rotation
- API Key management
- D1 database integration
- Request logging & rate limiting

## Setup

### Prerequisites
- Node.js 18+
- Wrangler CLI
- Cloudflare account

### Installation
```bash
npm install
```

### Development
```bash
wrangler dev
```

### Deploy
```bash
wrangler deploy
```

### Required Environment Variables
- `JWT_SECRET` - Secret for signing JWT tokens (set via `wrangler secret put JWT_SECRET`)

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register user
- `POST /api/v1/auth/login` - Login
- `POST /api/v1/auth/refresh` - Refresh tokens
- `POST /api/v1/auth/logout` - Logout
- `GET /api/v1/auth/me` - Get profile
- `POST /api/v1/auth/send-otp` - Send OTP
- `POST /api/v1/auth/verify-otp` - Verify OTP

### API Keys
- `GET /api/v1/auth/api-keys` - List keys
- `POST /api/v1/auth/api-keys` - Create key
- `DELETE /api/v1/auth/api-keys/:id` - Revoke key

### Projects
- `GET /api/v1/project-alpha` - Alpha project
- `GET /api/v1/project-beta` - Beta project

### Database
- `GET /api/v1/db/_init` - Initialize tables
- `GET /api/v1/db/items` - List items
- `POST /api/v1/db/items` - Create item
- `DELETE /api/v1/db/items/:id` - Delete item

## Local Testing
See `Downloads/api-client-project/` for test UI files.