# Dating App Backend

This Express service handles sign-in, creates private source repositories, and
publishes websites with GitHub Pages. Clients receive an app session, not a
GitHub access token; GitHub API requests stay on the server.

## Sign-in and publishing

Users can sign in with Google or GitHub. Google accounts get a private
repository in the configured organization. The backend names it from the
email address, adding a short numeric suffix only when that name is already in
use. Each Google account is restricted to its assigned repository. Existing
accounts created with the earlier hash-suffixed name are migrated on their next
Google sign-in.

GitHub sign-in continues to use the user's own GitHub OAuth token. Repositories
created through the backend are private for both sign-in methods. When a
GitHub-authenticated user publishes to an existing repository they own, the
backend also makes that repository private. It does not change the visibility
of repositories owned by someone else.

The repository is the private source for the site; GitHub Pages serves the
published website separately. The Pages configuration is left public. GitHub
requires an eligible plan to publish Pages from a private repository, so check
that the organization plan supports this combination.

## Google sign-in

Create a Google OAuth client of type **Web application** and register the
backend callback URL as an authorized redirect URI. The client starts sign-in
at `GET /auth/google/init`, opens the returned `authorization_url`, polls
`GET /auth/desktop/status?transaction=...`, then posts the transaction to
`POST /auth/google/exchange`. Google uses the backend's client secret; this
flow does not require a client-supplied PKCE verifier.

The exchange response includes the app `session_token`, the user's
`repository_name`, `repository_owner`, and `is_new_user`. Send the session token
as `Authorization: Bearer <session_token>` on subsequent requests. The same
session token is also set in an HttpOnly cookie for browser clients.

## GitHub setup

The backend uses a GitHub App installation token for Google users. Install the
app on the organization that will own their repositories. Grant repository
Contents read/write, Pages read/write, and Administration write permissions.
Administration write is needed to create repositories and migrate existing
names or visibility. Generate a private key in the GitHub App settings.

GitHub users sign in separately through the OAuth app at `GET /github/login`.
Desktop clients start at `GET /auth/github` with a PKCE `code_challenge`, then
poll the desktop status endpoint and exchange the transaction plus the original
`code_verifier` at `POST /auth/desktop/exchange`.

## Configuration

Set these variables in Render. Values shown in angle brackets are placeholders.

```text
NODE_ENV=production
GITHUB_CLIENT_ID=<GitHub OAuth client ID>
GITHUB_CLIENT_SECRET=<GitHub OAuth client secret>
GITHUB_OAUTH_STATE_SECRET=<long random string>
GITHUB_CALLBACK_URL=https://<backend-host>/github/callback
GITHUB_APP_SLUG=<GitHub App slug>
GITHUB_APP_ID=<numeric GitHub App ID>
GITHUB_APP_INSTALLATION_ID=<organization installation ID>
GITHUB_APP_PRIVATE_KEY_BASE64=<base64-encoded private key PEM>
GITHUB_REPOSITORY_OWNER=I-m-dating-app
GOOGLE_CLIENT_ID=<Google OAuth client ID>
GOOGLE_CLIENT_SECRET=<Google OAuth client secret>
GOOGLE_CALLBACK_URL=https://<backend-host>/auth/google/callback
DATABASE_URL=<Render PostgreSQL connection string>
TOKEN_ENCRYPTION_KEY=<base64-encoded 32-byte key>
```

Use the exact callback URLs in the corresponding GitHub and Google OAuth
settings. Keep secrets out of source control and client builds. To encode the
downloaded GitHub App PEM key on Linux, run `base64 -w0 private-key.pem`. In
Windows PowerShell, run:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes(".\private-key.pem"))
```

Put the resulting single-line value in `GITHUB_APP_PRIVATE_KEY_BASE64`. Do not
remove the PEM `BEGIN` and `END` lines before encoding. Generate the encryption
key with `openssl rand -base64 32`; keep a secure backup because losing it makes
stored GitHub OAuth tokens unrecoverable.

The GitHub App installation token is minted by the backend and cached only
until shortly before it expires. It is not stored in the database or returned
to clients.

## Deploying

Deploy as a Render Web Service with `npm ci` as the build command and `npm start`
as the start command. Set the health check path to `/healthz`, create a Render
PostgreSQL database, and set `DATABASE_URL` to its connection string. The
service creates or migrates the required tables on startup.

## API overview

Public endpoints are `GET /healthz`, `GET /auth/github`,
`GET /auth/google/init`, `GET /github/login`, and `GET /github/callback` /
`GET /auth/google/callback` for OAuth redirects. `GET /auth/desktop/status`
checks a pending desktop sign-in; the matching exchange endpoint completes it.
Authenticated clients can use `GET /auth-status` and `POST /logout`.

Repository operations are:

```text
POST   /github/repositories
GET    /github/repositories/{owner}/{repo}
DELETE /github/repositories/{owner}/{repo}
POST   /github/publish
POST   /github/repositories/{owner}/{repo}/publish
POST   /github/repositories/{owner}/{repo}/pages
POST   /github/repositories/{owner}/{repo}/pages/build
GET    /github/repositories/{owner}/{repo}/pages/build
```

Publish requests accept up to 200 files and 8 MB of decoded content. Each file
has a relative `path`, string `content`, and optional `encoding` (`utf8` or
`base64`). Successful publish responses include the commit SHA, repository URL,
Pages deployment URL, and Pages build status. Clients should call this backend
rather than GitHub directly.