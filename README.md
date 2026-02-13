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

POST/api/auth/signup                  Register a new user
POST/api/auth/logi                    Secure login (Issues Cookies)
GET/api/auth/check-auth               Verify token & return user context


🔐 Security & MFAMethodEndpoint       Description
POST/api/auth/mfa/setup               Generate QR Code
POST/api/auth/mfa/enable              Verify & Activate 2FA
GET/api/auth/sessions                 List all active device sessions
DELETE/api/auth/sessions/:id          Remote session revocation

🏗️ Technical Architecture
Runtime: Node.js (ESM)
Database: MongoDB
Auth: JWT + HttpOnly Cookies
Validation: Zod / Joi
Security: Argon2/BCrypt + Crypto
