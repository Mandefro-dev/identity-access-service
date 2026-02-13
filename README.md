Advanced AUTH System
Yo, welcome to Auth System. this isn't just a basic login system.

This backend handles Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), Device Tracking, MFA (2FA), and Google OAuth2 with smart account linking.

✨Features
Smart Security Guard (RBAC + ABAC): Doesn't just check if you are an admin. It checks if you own the resource, if it's locked, and if your email is verified.

The "Socialite" (OAuth2): Custom Google Login flow. If a user logs in with Google but already has a password account, it silently merges them. No duplicates.

The Sessions: Tracks every device logged into your account (IP, Browser, OS) and lets you kill sessions remotely.

Short lived Tokens: Short-lived Access Tokens (15m) and secure, rotating Refresh Tokens (7d).

MFA: Time-based One-Time Password (TOTP) integration for that 2FA security.

Step-by-Step Setup
Want to run this locally? It's plug-and-play.

1. Clone the repo & install dependencies:

`Bash`
git clone https://github.com/Mandefro-dev/identity-access-service.git

npm install

2. Set up the Environment:
   Create a .env file in the root. You'll need these keys to the castle:

Code snippet
PORT=5000
MONGO_URI=your_mongodb_connection_string

# Token Secrets

JWT_ACCESS_SECRET=super_secret_access_key
JWT_REFRESH_SECRET=super_secret_refresh_key

# Google OAuth2 (Get this from Google Cloud Console)

GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
GOOGLE_REDIRECT_URI=http://localhost:5000/api/auth/google/callback

# Client URL (For CORS and Email Links)

CLIENT_URL=http://localhost:5173

Bash
npm run dev
Server is now running on http://localhost:5000 🚀

🎯 Test the Routes
Want to test the endpoints without building a frontend? Here is the hit list.

Note: Most protected routes require the Access Token in your cookies or Headers.

1.  Tore Auth
    POST /api/auth/signup - Body: { "email": "test@test.com", "password": "pass", "name": "Bro" }

POST /api/auth/login - Body: { "email": "test@test.com", "password": "pass" }

POST /api/auth/logout - Kills your current session.

GET /api/auth/check-auth - Verifies your token and returns your user data.

2.  Tokens & Social
    POST /api/auth/refresh - Hits the server to get a new Access Token using your Refresh cookie.

POST /api/auth/google - Body: { "code": "oauth_code_from_google" } (Exchanges code for session).

3.  MFA / 2FA Requires Login
    POST /api/auth/mfa/setup - Generates a Secret and a QR code base64 string.

POST /api/auth/mfa/enable - Body: { "token": "123456" } (Verifies the code from your Authenticator app).

POST /api/auth/mfa/verify-login - Body: { "email": "test@test.com", "token": "123456" } (Use this if login says MFA is required).

4.  Session Management-- Requires Login
    GET /api/auth/sessions - Returns an array of every device currently logged into your account.

DELETE /api/auth/sessions/:sessionId - Pass the ID from the previous route to kick that specific device offline.

5.  The Recovery (Emails)
    POST /api/auth/verify-email - Body: { "token": "verification_token_from_email" }

POST /api/auth/forgot-password - Body: { "email": "test@test.com" }

POST /api/auth/reset-password/:token - Body: { "password": "new_secure_password" }

Built with Node.js, Express, MongoDB.
