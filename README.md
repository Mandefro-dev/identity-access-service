🛡️ Advanced Identity & Access Management (IAM)The Fortress BackendThis isn't just a login script. It’s a high-performance Identity Service built to handle complex security requirements. From MFA to Session Hijacking protection, I've built the "Iron Vault" to be bulletproof.🚀 The "Senior" FeaturesFeatureDescription🧠 RBAC + ABACHybrid security. Checks Role (Admin/User) + Attributes (Owner/Locked/Verified).🎭 The SocialiteSmart Google OAuth2. Automatically links Google profiles to existing email accounts.📡 Radar SessionsReal-time device tracking (IP, OS, Browser) with remote "Kill-Switch" capability.🔐 MFA ShieldTime-based One-Time Password (TOTP) integration for 2FA security.⏳ Token Rotation15m Access Tokens + 7d Rotating Refresh Tokens with automatic reuse detection.🛠️ Step-by-Step Setup1. Clone & InstallBashgit clone https://github.com/Mandefro-dev/identity-access-service.git
cd identity-access-service
npm install 2. The Secret Keys (.env)Create a .env file in your root directory:Ini, TOMLPORT=5000
MONGO_URI=your_mongodb_connection_string

# JWT Secrets

JWT_ACCESS_SECRET=super_secret_access_key
JWT_REFRESH_SECRET=super_secret_refresh_key

# Google OAuth (Cloud Console)

GOOGLE_CLIENT_ID=your_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_secret_key
GOOGLE_REDIRECT_URI=http://localhost:5000/api/auth/google/callback

# Client

CLIENT_URL=http://localhost:5173 3. IgniteBashnpm run dev
Server Status: Running on http://localhost:5000 🚀🎯 Postman Playbook (API Hit List)🚪 Core Auth GatePOST /api/auth/signupBody: { "email": "user@test.com", "password": "secure", "name": "Dev" }POST /api/auth/loginBody: { "email": "user@test.com", "password": "secure" }GET /api/auth/check-authVerifies JWT and returns User Context.🛡️ MFA & RecoveryPOST /api/auth/mfa/setupGenerates QR code for Authenticator apps.POST /api/auth/mfa/enableBody: { "token": "123456" }POST /api/auth/forgot-passwordTriggers secure recovery email.📡 Session ControlGET /api/auth/sessions _ Lists every device logged into your account.DELETE /api/auth/sessions/:id _ Forces a remote logout for that specific device.🏗️ ArchitectureLanguage: Node.js (ESM)Framework: Express.jsDatabase: MongoDB + MongooseSecurity: JWT, Crypto, Speakeasy, BCrypt<p align="center"><b>Built with ❤️ and zero spaghetti code.</b><sub>Check out the Frontend repository for the React implementation.</sub></p>
