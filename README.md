Advanced AUTH System


This is a professional-grade AUTH system. It doesn't just "log users in"—it tracks their devices, handles multi-factor security, and manages complex access rules using RBAC and ABAC.

---

## ✨ Features Breakdown

- **🧠 Hybrid Security:** Combines **RBAC** (Role-Based) and **ABAC** (Attribute-Based). It checks if a resource is _locked_ before allowing an edit, even for the owner.
- **🎭 Social Sync:** Custom **Google OAuth2** flow that merges social profiles with existing local accounts.
- **📡 Session R:** Real-time tracking of IP addresses, Browsers, and OS via `deviceDetector`.
- **🔐 MFA :** TOTP (Time-based One-Time Password) integration.

---

## 🛠️ Installation & Setup

To get the "Terminal Vibe" running locally:

```bash
# 1. Clone the fortress
git clone [https://github.com/Mandefro-dev/identity-access-service.git](https://github.com/Mandefro-dev/identity-access-service.git)

# 2. Enter the chamber
cd identity-access-service

# 3. Install dependencies
npm install

# 4. Start 
npm run dev
🔑 Environment Configuration
Create a .env file in the root directory:Code snippet
PORT=5000
MONGO_URI=your_mongodb_uri
# JWT Configuration
JWT_ACCESS_SECRET=your_access_secret
JWT_REFRESH_SECRET=your_refresh_secret
MAILTRAP_TOKEN=mailtrap token
MAILTRAP_ACCOUNT_ID=account id
# Google OAuth
GOOGLE_CLIENT_ID=your_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_secret_key
GOOGLE_REDIRECT_URI=http://localhost:5000/api/auth/google/callback```

🎯 Postman

🚪 Core AuthenticationMethodEndpoint   Description

Core Auth
POST /api/auth/signup - Body: { "email": "test@test.com", "password": "pass", "name": "Bro" }

POST /api/auth/login - Body: { "email": "test@test.com", "password": "pass" }

POST /api/auth/logout - Kills your current session.

GET /api/auth/check-auth - Verifies your token and returns your user data.

Tokens & Social

POST /api/auth/refresh - Hits the server to get a new Access Token using your Refresh cookie.

POST /api/auth/google - Body: { "code": "oauth_code_from_google" } (Exchanges code for session).

MFA / 2FA   requires Login
POST /api/auth/mfa/setup - Generates a Secret and a QR code base64 string.

POST /api/auth/mfa/enable - Body: { "token": "123456" } (Verifies the code from your Authenticator app).

POST /api/auth/mfa/verify-login - Body: { "email": "test@test.com", "token": "123456" } (Use this if login says MFA is required).

 Session Management (Requires login)
GET /api/auth/sessions - Returns an array of every device currently logged into your account.

DELETE /api/auth/sessions/:sessionId - Pass the ID from the previous route to kick that specific device offline.

 The Recovery (Emails)
POST /api/auth/verify-email - Body: { "token": "verification_token_from_email" }

POST /api/auth/forgot-password - Body: { "email": "test@test.com" }



🏗️ Technical Architecture
Runtime: Node.js (ESM)
Database: MongoDB
Auth: JWT + HttpOnly Cookies
Validation: Zod / Joi
Security: Argon2/BCrypt + Crypto
