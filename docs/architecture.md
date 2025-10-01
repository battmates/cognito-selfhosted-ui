# Cognito Self-Hosted UI – Architecture Outline

## Goals
- Provide a drop-in replacement for the AWS Cognito Hosted UI so existing integrations (e.g. WordPress clients) can switch domains without code changes.
- Leverage Cognito User Pools and AWS-managed email/SMS delivery while self-hosting all HTML, CSS (Tailwind), and UX flows.
- Preserve OAuth 2.0 Authorization Code + PKCE semantics: `/oauth2/authorize` must return a code that can be exchanged on `/oauth2/token`.
- Support end-user flows currently exposed in the hosted UI: login, MFA (email OTP + authenticator app), password reset, self-registration with email verification, and MFA enrollment.

## High-Level Components
- **Public entry point (`public/index.php`)**: fronts all HTTP requests and dispatches to controllers based on path/verb.
- **Router**: minimal PSR-15-like dispatcher that maps `/oauth2/authorize`, `/oauth2/token`, `/logout`, `/register`, `/forgot-password`, `/mfa`, etc.
- **Controllers**:
  - `AuthorizeController`: renders login form, handles username/password submission, drives Cognito `InitiateAuth` and `RespondToAuthChallenge`, produces authorization codes, and redirects back to client with code/state.
  - `TokenController`: exchanges authorization codes stored locally for Cognito tokens, mirrors AWS token endpoint contract.
  - `RegistrationController`: handles `SignUp`, email verification, and optional MFA enrollment.
  - `PasswordController`: orchestrates `ForgotPassword` and confirmation.
  - `MfaController`: manages MFA challenges and enrollment preferences (email vs authenticator app using `AssociateSoftwareToken`).
- **Services**:
  - `CognitoClient`: thin wrapper around AWS SDK providing methods for auth, challenges, user management.
  - `CodeStore`: persists short-lived authorization codes and associated Cognito tokens (backed by Redis/filesystem, default to encrypted filesystem cache).
  - `SessionStore`: tracks browser session state (PHP session + signed cookies).
  - `StateEncoder`: signs/validates state parameters so we can round-trip redirect targets securely.

## Data Flow Overview
1. `/oauth2/authorize` GET validates client + redirect, prompts for login (Tailwind template) unless user session already authenticated and `prompt=none`.
2. Login POST triggers Cognito `InitiateAuth (USER_PASSWORD_AUTH)`.
   - If success → store tokens in `CodeStore`, mint short-lived authorization code, redirect back to `redirect_uri` with `code` + `state`.
   - If `ChallengeName` present → persist Cognito session + challenge type in user session, render MFA challenge page (email OTP or authenticator code) handled via `/mfa` route.
3. `/oauth2/token` accepts standard `application/x-www-form-urlencoded` payload, validates `client_id`/`client_secret`, redeems authorization code from `CodeStore`, returns Cognito token payload (access/id/refresh tokens, expiry) to client.
4. Registration + verification flows mirror hosted UI endpoints but call Cognito `SignUp`, `ConfirmSignUp`, and optionally `AssociateSoftwareToken` + `VerifySoftwareToken` to enrol authenticator app.
5. Password reset flows call `ForgotPassword` / `ConfirmForgotPassword` and surface the forms required for new password entry.

## Configuration & Secrets
- `config/config.php` returns settings sourced from environment variables or `.env` file (via `vlucas/phpdotenv`).
- Keys: Cognito user pool ID, app client ID/secret, AWS region, allowed redirect URIs, session cookie secret, storage driver selection.

## Frontend Stack
- TailwindCSS compiled with `npm` (via `tailwind.config.js` + `package.json`). Build artefacts served from `public/assets/css/app.css`.
- Blade-like lightweight templating (`src/View/View.php`) with layout + component snippets for form fields, alerts, etc.

## Security Considerations
- Authorization codes must be single-use and expire quickly (default 5 minutes).
- Codes stored encrypted at rest (OpenSSL + config secret) when using filesystem driver.
- CSRF protection on POST forms (synchronizer token stored in session).
- Strict validation of `redirect_uri` vs allowlist to prevent open redirect attacks.
- Rate-limit login attempts per IP (pluggable, fallback to temporal session-based throttle).

## Open Questions / Next Steps
- Select default storage for `CodeStore` (filesystem cache vs Redis). MVP will use filesystem under `storage/codes`.
- Determine UX for MFA enrollment during first login (prompt after verification?).
- Add audit logging for admin visibility.
- Confirm whether PKCE support is required; hosted UI supports it, so plan to accept optional `code_challenge` / `code_verifier`.
