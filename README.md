# GitHub publishing middleware

This server handles GitHub OAuth and performs GitHub API requests on behalf of
authenticated users without exposing GitHub tokens to clients.

Set these environment variables before starting the server:

```sh
GITHUB_CLIENT_ID="your-github-app-client-id"
GITHUB_CLIENT_SECRET="your-github-client-secret"
GITHUB_OAUTH_STATE_SECRET="a-long-random-secret"
GITHUB_APP_SLUG="your-github-app-slug"
GITHUB_CALLBACK_URL="https://miniature-acorn-97rx7qw5p5g2x7g-3000.app.github.dev/github/callback"
DATABASE_URL="postgresql://..."
TOKEN_ENCRYPTION_KEY="base64-encoded-32-byte-key"
```

In the GitHub App settings, set the user authorization callback URL to the
same `GITHUB_CALLBACK_URL` value. `GITHUB_OAUTH_STATE_SECRET` signs the
short-lived state cookie used to protect the callback. Start the OAuth flow at
`/github/login`; it redirects to GitHub and exchanges the callback code for a
user token.
Use `/github/install` to redirect users to the GitHub App installation page.

Deploy this repository on Render as a Web Service with:

```text
Build command: npm ci
Start command: npm start
Health check path: /healthz
```

Set `NODE_ENV=production` and all environment variables above in Render. Set
`GITHUB_CALLBACK_URL` to the deployed Render URL ending in `/github/callback`,
then use that same URL in the GitHub App settings.

Create a Render PostgreSQL database and copy its internal connection string into
`DATABASE_URL`. Generate `TOKEN_ENCRYPTION_KEY` with:

```sh
openssl rand -base64 32
```

The service creates its `users`, `sessions`, and `oauth_transactions` tables on
startup. OAuth tokens and pending authorization codes are encrypted at rest,
and clients receive opaque app sessions rather than GitHub tokens. The health
endpoint is public; authenticated endpoints are:

```sh
GET /auth-status
GET /github/installation-status
GET /github/user
POST /logout
GET /auth/desktop/status?transaction=...
```

`GET /github/installation-status` requires authentication and returns
`{"installed":true}` when the signed-in user has installed the configured
GitHub App. It returns `{"installed":false}` otherwise.

Desktop clients start OAuth by requesting `GET /auth/github` with a PKCE
`code_challenge`. The response is:

```json
{
	"authorization_url": "https://github.com/...",
	"transaction": "...",
	"expires_at": "..."
}
```

Open `authorization_url` in the browser, then poll
`GET /auth/desktop/status?transaction=...` until `authorized` is true. Exchange
the transaction and original `code_verifier` at `POST /auth/desktop/exchange`.
The response contains an opaque `session_token`; send it as
`Authorization: Bearer` on later backend requests. It is not a GitHub token.

The following endpoints are available for repository operations:

```sh
POST /github/repositories
GET /github/repositories/{owner}/{repo}
DELETE /github/repositories/{owner}/{repo}
POST /github/publish
POST /github/repositories/{owner}/{repo}/publish
POST /github/repositories/{owner}/{repo}/pages
POST /github/repositories/{owner}/{repo}/pages/build
GET /github/repositories/{owner}/{repo}/pages/build
```

Create a repository with a JSON body such as:

```json
{
	"name": "my-site",
	"private": false,
	"description": "Published site"
}
```

Publish text and image files in one commit with:

```json
{
	"branch": "main",
	"commit_message": "Publish site",
	"files": [
		{"path": "index.html", "content": "<h1>Hello</h1>", "encoding": "utf8"},
		{"path": "images/hero.png", "content": "...base64...", "encoding": "base64"}
	]
}
```

The unified client publish form is:

```json
{
	"repository": {"owner": "octocat", "name": "my-site"},
	"files": [
		{"path": "index.html", "content": "<h1>Hello</h1>", "encoding": "utf8"}
	]
}
```

The publish request accepts at most 200 files and 8 MB total decoded content.
The Pages endpoints configure the repository source and trigger or inspect the
latest Pages build. Desktop clients should send the returned app session token
as a bearer token; web clients can retain the backend session cookie. Neither
client type should call GitHub directly.

Successful `/github/publish` responses include `commit_sha`, `repository`,
`deployment_url`, and a `pages` object containing the build request status.
GitHub operations should remain server-side. Never put `TOKEN_ENCRYPTION_KEY`
or a GitHub token in a public client build. Back up the encryption key securely;
losing it makes stored GitHub tokens unrecoverable.