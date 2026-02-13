# 🛡️ Iron Vault: Advanced IAM System

> **Status:** Operational 🚀 | **Developer:** Mandefro-dev

This is a professional-grade **Identity and Access Management (IAM)** system. It doesn't just "log users in"—it tracks their devices, handles multi-factor security, and manages complex access rules using RBAC and ABAC.

---

## ✨ Features Breakdown

- **🧠 Hybrid Security:** Combines **RBAC** (Role-Based) and **ABAC** (Attribute-Based). It checks if a resource is _locked_ before allowing an edit, even for the owner.
- **🎭 Social Sync:** Custom **Google OAuth2** flow that merges social profiles with existing local accounts.
- **📡 Session Radar:** Real-time tracking of IP addresses, Browsers, and OS via `deviceDetector`.
- **🔐 MFA Shield:** TOTP (Time-based One-Time Password) integration.

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

# 4. Start the engine
npm run dev
🔑 Environment ConfigurationCreate a .env file in the root directory:Code snippetPORT=5000
MONGO_URI=your_mongodb_uri

# JWT Configuration
JWT_ACCESS_SECRET=your_access_secret
JWT_REFRESH_SECRET=your_refresh_secret

# Google OAuth
GOOGLE_CLIENT_ID=your_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_secret_key
GOOGLE_REDIRECT_URI=http://localhost:5000/api/auth/google/callback
🎯 Postman Playbook (API Hit List)🚪 Core AuthenticationMethodEndpointDescriptionPOST/api/auth/signupRegister a new userPOST/api/auth/loginSecure login (Issues Cookies)GET/api/auth/check-authVerify token & return user context🔐 Security & MFAMethodEndpointDescriptionPOST/api/auth/mfa/setupGenerate QR CodePOST/api/auth/mfa/enableVerify & Activate 2FAGET/api/auth/sessionsList all active device sessionsDELETE/api/auth/sessions/:idRemote session revocation🏗️ Technical ArchitectureRuntime: Node.js (ESM)Database: MongoDBAuth: JWT + HttpOnly CookiesValidation: Zod / JoiSecurity: Argon2/BCrypt + Crypto
```
