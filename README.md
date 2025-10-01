# Cognito Self-Hosted UI

PHP application that reproduces the AWS Cognito Hosted UI flows (authorization code + PKCE) while letting you control the UX. It integrates with an existing Cognito User Pool via the AWS SDK and mirrors the `/oauth2/authorize` and `/oauth2/token` endpoints so existing integrations can switch domains without code changes.

## Features
- Authorization Code flow with support for PKCE, state, and redirect URI validation.
- Login with Cognito `USER_PASSWORD_AUTH`, including MFA challenges (email OTP, SMS, authenticator app) and MFA enrollment (SELECT_MFA_TYPE + MFA_SETUP).
- `/oauth2/token` endpoint backed by local authorization-code storage and refresh-token bridging to Cognito.
- Self-service registration with email verification and optional MFA setup.
- Password reset (forgot + confirm flows) matching Cognito behaviour.
- Tailwind CSS powered views for login, MFA, registration, and password forms.

## Requirements
- PHP 8.1+
- Composer
- Node.js 18+
- AWS credentials with permission to access your Cognito User Pool (via environment variables, instance profile, or shared credentials file).

## Getting Started

1. **Install PHP dependencies**
   ```bash
   composer install
   ```

2. **Install frontend build tooling**
   ```bash
   npm install
   ```

3. **Create your environment file**
   ```bash
   cp .env.example .env
   ```
   Populate the following values:
   - `COGNITO_REGION`
   - `COGNITO_USER_POOL_ID`
   - `COGNITO_CLIENT_ID`
   - `COGNITO_CLIENT_SECRET` (if the app client uses a secret)
   - `ALLOWED_REDIRECTS` (comma-separated list of exact redirect URIs that should be honoured)
   - `SESSION_SECRET` (random string used for signing session cookies)

   Ensure AWS credentials are available via the standard SDK lookup chain (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, IMDS, etc.).

4. **Build Tailwind assets**
   ```bash
   npm run build
   ```

5. **Run the development server**
   ```bash
   php -S 0.0.0.0:8000 -t public/
   ```
   Visit `http://localhost:8000/oauth2/authorize?client_id=...&response_type=code&scope=openid&redirect_uri=...` to initiate the flow.

## Configuration Notes
- Authorization codes are stored under `storage/codes` with a default TTL of 5 minutes (`CODE_TTL`). Refresh token metadata is kept under `storage/refresh` so the `/oauth2/token` refresh grant can call Cognito on behalf of the user.
- Adjust `ALLOWED_REDIRECTS` to match the redirect URIs configured on your Cognito App Client. Only exact matches are accepted.
- The app expects PKCE parameters when provided and validates them before issuing tokens.

## MFA & Enrollment
- MFA challenges for email, SMS, and authenticator apps are supported.
- When Cognito returns `SELECT_MFA_TYPE`, users are prompted to choose between available methods.
- `MFA_SETUP` is handled by generating a TOTP secret and SVG QR code (using `bacon/bacon-qr-code`), then verifying the code before completing authentication.

## Development Tips
- Tailwind CSS runs in watch mode with `npm run dev`.
- PHPUnit is installed for future backend tests (`vendor/bin/phpunit`).
- Environment-specific overrides can be added via `.env.local` (ignored from version control).

## Roadmap / TODO
- Add structured logging (Monolog) for audit trails.
- Implement rate limiting for login attempts.
- Expand registration to collect additional attributes based on pool configuration.
- Add automated tests for auth flows (using Cognito local mocks or integration environment).
