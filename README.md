# QR-Code Based Secure Authentication

A runnable event-attendance demo using short-lived **HS256-signed QR tokens**, authenticated attendee and staff sessions, server-side verification, and persistent replay protection.

## Requirements

- Node.js 20 or newer
- npm

## Run locally

```powershell
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000).

## Demo deploy to Vercel

The project includes a Vercel Node.js function for its API and serves the frontend as static assets. For a quick demo, push this folder to a GitHub repository, import the repository in Vercel, and add these environment variables in the Vercel project settings (Production and Preview):

- `QR_HMAC_SECRET`: a private random value of at least 32 UTF-8 bytes.
- `ATTENDEE_PASSWORD`: a non-default demo attendee password.
- `SCANNER_PASSWORD`: a different non-default demo staff password.

Generate a signing secret locally with Node.js:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

Paste the output into Vercel's `QR_HMAC_SECRET` setting; do not commit secrets or put them in frontend variables prefixed with `VITE_`, `NEXT_PUBLIC_`, or similar. Import the project with the repository root as the project root and deploy. Vercel provides HTTPS, required for camera access.

The app refuses to start on Vercel if the signing secret or non-default attendee/staff passwords are missing. The local demo credentials are not displayed on Vercel.

**This Vercel configuration is for presentation/demo use only.** Login sessions are signed and can be verified across function instances, but sign-out cannot revoke a copied session cookie before its expiry. Check-in and replay records are held only in serverless instance memory: instances may disagree, cold starts may erase them, and check-ins are not reliably persistent or one-time across instances. The app shows a warning on Vercel. Do not use this deployment for real attendance until sessions, replay prevention, and attendance are moved to a shared transactional database.

Demo accounts:

| Role | Username | Password |
| --- | --- | --- |
| Attendee | `student` | `student123` |
| Event staff scanner | `staff` | `scanner123` |

Sign in as the attendee to display a QR code that refreshes every 30 seconds and expires after 60 seconds. Sign out, sign in as staff, then scan the attendee's QR code with a supported browser camera or paste its token into the scanner. Successful attendance and used-token IDs persist in `.data/attendance.json`; the signing key is created locally in `.data/signing.key`. Keep `.data/` private and out of version control.

## Security design

- The server signs a minimal JWT payload with HMAC-SHA-256. QR data contains an opaque attendee ID, event ID, issued/expiry times, and random unique token ID—not names or passwords.
- The signing key stays on the server. If `QR_HMAC_SECRET` is not set, a random 256-bit key is created locally. A configured key must be at least 32 UTF-8 bytes.
- Attendee and scanner endpoints require separate authenticated roles. Session cookies are `HttpOnly` and `SameSite=Strict`; production cookies also use `Secure`.
- The scanner submits the token to the server, which checks the signature, algorithm, event, enrolment, and expiry before recording attendance.
- Token consumption and the attendee/event uniqueness check are serialized and saved atomically. Replayed tokens and duplicate attendance are rejected.
- Sign-in attempts are rate-limited per client address. Responses are not cached, and security headers are set.

## Configure before deployment

The built-in accounts and event are **demo fixtures**, not production account management. Before deployment, set non-default credentials and a securely generated key:

```powershell
$env:ATTENDEE_PASSWORD = "replace-with-a-long-random-attendee-password"
$env:SCANNER_PASSWORD = "replace-with-a-different-long-random-staff-password"
$env:QR_HMAC_SECRET = "replace-with-at-least-32-random-utf8-bytes"
$env:NODE_ENV = "production"
npm start
```

Serve the application only over HTTPS in production. For multiple server instances, replace the local JSON state and in-memory session store with a transactional shared database and shared session storage. HMAC proves server issuance and token integrity; it does not prove that the person presenting a copied QR is the account holder, so staff should check attendee identity when that assurance is needed.

## Tests

```powershell
npm test
```
