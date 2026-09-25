import express from "express"
import fetch from "node-fetch"
import crypto from "node:crypto"
import jwt from "jsonwebtoken"
import pg from "pg"

const { Pool } = pg

const app = express()

const port = process.env.PORT || 3000
const isProduction = process.env.NODE_ENV === "production"
const databaseUrl = process.env.DATABASE_URL
const tokenEncryptionKey = process.env.TOKEN_ENCRYPTION_KEY

const githubCallbackUrl = process.env.GITHUB_CALLBACK_URL
const oauthStateCookieName = "github_oauth_state"
const sessionCookieName = isProduction
  ? "__Host-app_session"
  : "app_session"
const oauthStateLifetimeSeconds = 10 * 60
const sessionLifetimeSeconds = 7 * 24 * 60 * 60

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: isProduction
    ? { rejectUnauthorized: false }
    : undefined
})

const githubApiUrl = "https://api.github.com"

const githubHeaders = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28"
}

app.use(express.json({ limit: "10mb" }))

app.disable("x-powered-by")
app.set("trust proxy", 1)

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("X-Frame-Options", "DENY")
  res.setHeader("Referrer-Policy", "no-referrer")
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

  if (isProduction) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    )
  }

  next()
})


app.use((req, res, next) => {
  const startedAt = Date.now()

  res.on("finish", () => {
    console.log(
      `${req.method} ${req.path} -> ` +
      `${res.statusCode} (${Date.now() - startedAt}ms)`
    )
  })

  next()
})


function requireGitHubConfiguration(res) {
  const clientId = process.env.GITHUB_CLIENT_ID
  const clientSecret = process.env.GITHUB_CLIENT_SECRET
  const oauthStateSecret = process.env.GITHUB_OAUTH_STATE_SECRET
  const missingConfiguration = [
    ["GITHUB_CLIENT_ID", clientId],
    ["GITHUB_CLIENT_SECRET", clientSecret],
    ["GITHUB_CALLBACK_URL", githubCallbackUrl],
    ["GITHUB_OAUTH_STATE_SECRET", oauthStateSecret]
  ]
    .filter(([, value]) => !value)
    .map(([name]) => name)

  if (
    isProduction &&
    githubCallbackUrl &&
    !githubCallbackUrl.startsWith("https://")
  ) {
    missingConfiguration.push("GITHUB_CALLBACK_URL must use https in production")
  }

  if (missingConfiguration.length > 0) {
    res.status(500).json({
      error: "Missing GitHub OAuth configuration",
      missing: missingConfiguration
    })

    return null
  }

  return {
    clientId,
    clientSecret,
    oauthStateSecret
  }
}


function getTokenEncryptionKey() {
  const key = Buffer.from(tokenEncryptionKey || "", "base64")

  if (key.length !== 32) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY must be a base64-encoded 32-byte key"
    )
  }

  return key
}


function encryptToken(token) {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    getTokenEncryptionKey(),
    iv
  )
  const ciphertext = Buffer.concat([
    cipher.update(token, "utf8"),
    cipher.final()
  ])

  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64")
  }
}


function decryptToken(user) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getTokenEncryptionKey(),
    Buffer.from(user.token_iv, "base64")
  )
  decipher.setAuthTag(Buffer.from(user.token_auth_tag, "base64"))

  return Buffer.concat([
    decipher.update(Buffer.from(user.token_ciphertext, "base64")),
    decipher.final()
  ]).toString("utf8")
}


function hashSessionToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex")
}


function hashValue(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex")
}


function valuesMatch(left, right) {
  const leftBuffer = Buffer.from(left)
  const rightBuffer = Buffer.from(right)

  return leftBuffer.length === rightBuffer.length &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer)
}


function setSessionCookie(res, token) {
  const secureAttribute = isProduction ? "; Secure" : ""

  appendSetCookie(
    res,
    `${sessionCookieName}=${encodeURIComponent(token)}; ` +
    `Max-Age=${sessionLifetimeSeconds}; Path=/; HttpOnly; ` +
    `SameSite=Lax${secureAttribute}`
  )
}


function clearSessionCookie(res) {
  const secureAttribute = isProduction ? "; Secure" : ""

  appendSetCookie(
    res,
    `${sessionCookieName}=; Max-Age=0; Path=/; HttpOnly; ` +
    `SameSite=Lax${secureAttribute}`
  )
}


function appendSetCookie(res, cookie) {
  const existingCookies = res.getHeader("Set-Cookie")
  const cookies = existingCookies
    ? Array.isArray(existingCookies)
      ? existingCookies
      : [existingCookies]
    : []

  res.setHeader("Set-Cookie", [...cookies, cookie])
}


function getCookieValue(req, name) {
  const cookies = req.headers.cookie

  if (!cookies) {
    return null
  }

  const cookie = cookies
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))

  if (!cookie) {
    return null
  }

  try {
    return decodeURIComponent(cookie.slice(name.length + 1))
  } catch {
    return null
  }
}


async function requireSession(req, res, next) {
  try {
    const bearerToken = req.get("Authorization")
      ?.replace(/^Bearer\s+/i, "")
    const token = bearerToken || getCookieValue(req, sessionCookieName)

    if (!token) {
      return res.status(401).json({
        error: "Authentication required"
      })
    }

    const result = await pool.query(
      `SELECT u.id, u.github_login, u.token_ciphertext, u.token_iv,
              u.token_auth_tag
         FROM sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
      [hashSessionToken(token)]
    )

    if (result.rowCount === 0) {
      clearSessionCookie(res)

      return res.status(401).json({
        error: "Session expired"
      })
    }

    res.locals.user = result.rows[0]

    return next()
  } catch (error) {
    console.error("SESSION LOOKUP FAILED:", error.message)

    return res.status(503).json({
      error: "Authentication service unavailable"
    })
  }
}


async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      github_user_id BIGINT UNIQUE NOT NULL,
      github_login TEXT NOT NULL,
      token_ciphertext TEXT NOT NULL,
      token_iv TEXT NOT NULL,
      token_auth_tag TEXT NOT NULL,
      token_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_transactions (
      transaction_hash TEXT PRIMARY KEY,
      state TEXT UNIQUE NOT NULL,
      code_challenge TEXT NOT NULL,
      authorization_code_ciphertext TEXT,
      authorization_code_iv TEXT,
      authorization_code_auth_tag TEXT,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      consumed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)

  await pool.query(
    "CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at)"
  )
}


async function createSession(userId, res) {
  const token = crypto.randomBytes(32).toString("base64url")
  const expiresAt = new Date(
    Date.now() + sessionLifetimeSeconds * 1000
  )

  await pool.query(
    `INSERT INTO sessions (token_hash, user_id, expires_at)
     VALUES ($1, $2, $3)`,
    [hashSessionToken(token), userId, expiresAt]
  )

  setSessionCookie(res, token)

  return {
    token,
    expiresAt
  }
}


async function exchangeGitHubCode(config, code, codeVerifier = null) {
  const body = {
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: githubCallbackUrl
  }

  if (codeVerifier) {
    body.code_verifier = codeVerifier
  }

  const tokenResponse = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      signal: AbortSignal.timeout(10_000),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    }
  )

  const tokenData = await readJsonResponse(tokenResponse)

  if (!tokenResponse.ok || !tokenData.access_token) {
    const error = new Error(
      tokenData.error_description || "Failed to exchange authorization code"
    )
    error.status = 400
    throw error
  }

  return String(tokenData.access_token)
}


async function saveGitHubUser(token) {
  const userResult = await githubRequest(
    `${githubApiUrl}/user`,
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  )

  const login = String(userResult.data.login || "")
  const githubUserId = String(userResult.data.id || "")

  if (!login || !githubUserId) {
    const error = new Error(
      "GitHub response did not contain user identity"
    )
    error.status = 400
    throw error
  }

  const encryptedToken = encryptToken(token)
  const savedUserResult = await pool.query(
    `INSERT INTO users (
       github_user_id,
       github_login,
       token_ciphertext,
       token_iv,
       token_auth_tag
     ) VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (github_user_id) DO UPDATE SET
       github_login = EXCLUDED.github_login,
       token_ciphertext = EXCLUDED.token_ciphertext,
       token_iv = EXCLUDED.token_iv,
       token_auth_tag = EXCLUDED.token_auth_tag,
       token_created_at = NOW(),
       updated_at = NOW()
     RETURNING id`,
    [
      githubUserId,
      login,
      encryptedToken.ciphertext,
      encryptedToken.iv,
      encryptedToken.authTag
    ]
  )

  return {
    id: savedUserResult.rows[0].id,
    login
  }
}


function setOAuthStateCookie(res, state, secret) {
  const token = jwt.sign(
    { state },
    secret,
    { expiresIn: oauthStateLifetimeSeconds }
  )

  const secureAttribute = githubCallbackUrl.startsWith("https:")

  appendSetCookie(
    res,
    `${oauthStateCookieName}=${encodeURIComponent(token)}; ` +
    `Max-Age=${oauthStateLifetimeSeconds}; Path=/; HttpOnly; ` +
    `SameSite=Lax${secureAttribute ? "; Secure" : ""}`
  )
}


function clearOAuthStateCookie(res) {
  const secureAttribute = githubCallbackUrl?.startsWith("https:")

  appendSetCookie(
    res,
    `${oauthStateCookieName}=; Max-Age=0; Path=/; HttpOnly; ` +
    `SameSite=Lax${secureAttribute ? "; Secure" : ""}`
  )
}


async function readJsonResponse(response) {
  const text = await response.text()

  if (!text) {
    return {}
  }

  try {
    return JSON.parse(text)
  } catch {
    return {
      raw: text
    }
  }
}


async function githubRequest(
  url,
  options = {}
) {
  const response = await fetch(url, {
    ...options,
    signal: options.signal || AbortSignal.timeout(10_000),
    headers: {
      ...githubHeaders,
      ...(options.headers || {})
    }
  })

  const data = await readJsonResponse(response)

  if (!response.ok) {
    const error = new Error(
      data.message || "GitHub request failed"
    )

    error.status = response.status
    error.data = data
    error.headers = response.headers
    error.url = url

    throw error
  }

  return {
    status: response.status,
    data,
    headers: response.headers
  }
}


async function githubJsonRequest(token, url, method, body = undefined) {
  const options = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    }
  }

  if (body !== undefined) {
    options.body = JSON.stringify(body)
  }

  return githubRequest(url, options)
}


function repositoryUrl(owner, repo, suffix = "") {
  return `${githubApiUrl}/repos/${encodeURIComponent(owner)}/` +
    `${encodeURIComponent(repo)}${suffix}`
}


function repositoryParams(req) {
  const { owner, repo } = req.params

  if (
    !owner ||
    !repo ||
    owner.length > 100 ||
    repo.length > 100 ||
    !/^[A-Za-z0-9_.-]+$/.test(owner) ||
    !/^[A-Za-z0-9_.-]+$/.test(repo)
  ) {
    return null
  }

  return { owner, repo }
}


function sendGitHubError(res, error) {
  const status = Number.isInteger(error.status)
    ? error.status
    : 502

  console.error(
    `GITHUB REQUEST FAILED: ${status} ${error.url || "unknown URL"} - ` +
    error.message
  )

  return res.status(status).json({
    error: status >= 500
      ? "GitHub request failed"
      : error.message
  })
}


function getPublishFiles(body) {
  if (!Array.isArray(body?.files) || body.files.length === 0) {
    return {
      error: "files must be a non-empty array"
    }
  }

  if (body.files.length > 200) {
    return {
      error: "A publish can contain at most 200 files"
    }
  }

  let totalBytes = 0
  const files = []

  for (const file of body.files) {
    if (
      !file ||
      typeof file.path !== "string" ||
      typeof file.content !== "string" ||
      file.path.length === 0 ||
      file.path.length > 500 ||
      file.path.startsWith("/") ||
      file.path.includes("\\") ||
      file.path.split("/").includes("..")
    ) {
      return {
        error: "Each file needs a safe relative path and string content"
      }
    }

    const encoding = file.encoding || "utf8"
    let content

    if (encoding === "base64") {
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(file.content)) {
        return {
          error: `Invalid base64 content for ${file.path}`
        }
      }

      content = Buffer.from(file.content, "base64")
    } else if (encoding === "utf8") {
      content = Buffer.from(file.content, "utf8")
    } else {
      return {
        error: `Unsupported encoding for ${file.path}`
      }
    }

    totalBytes += content.length

    if (totalBytes > 8 * 1024 * 1024) {
      return {
        error: "A publish cannot exceed 8 MB"
      }
    }

    files.push({
      path: file.path,
      content: content.toString("base64")
    })
  }

  return { files }
}

async function publishFiles(
  token,
  owner,
  repo,
  body,
  { createIfMissing = false } = {}
) {
  const filesResult = getPublishFiles(body)

  if (filesResult.error) {
    const error = new Error(filesResult.error)
    error.status = 400
    throw error
  }

  let repository

  try {
    repository = await githubRequest(
      repositoryUrl(owner, repo),
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    )
  } catch (error) {
    if (error.status !== 404 || !createIfMissing) {
      throw error
    }

    repository = await githubJsonRequest(
      token,
      `${githubApiUrl}/user/repos`,
      "POST",
      {
        name: repo,
        private: false,
        auto_init: true,
        description: "Published site"
      }
    )
  }
  const branch = body.branch || repository.data.default_branch || "main"

  if (
    typeof branch !== "string" ||
    !/^[A-Za-z0-9_.-]+$/.test(branch)
  ) {
    const error = new Error("Invalid branch name")
    error.status = 400
    throw error
  }

  const reference = await githubRequest(
    repositoryUrl(owner, repo, `/git/ref/heads/${encodeURIComponent(branch)}`),
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  )

  const baseCommit = await githubRequest(
    repositoryUrl(owner, repo, `/git/commits/${reference.data.object.sha}`),
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  )

  const blobs = []

  for (const file of filesResult.files) {
    const blob = await githubJsonRequest(
      token,
      repositoryUrl(owner, repo, "/git/blobs"),
      "POST",
      {
        content: file.content,
        encoding: "base64"
      }
    )

    blobs.push({
      path: file.path,
      mode: "100644",
      type: "blob",
      sha: blob.data.sha
    })
  }

  const tree = await githubJsonRequest(
    token,
    repositoryUrl(owner, repo, "/git/trees"),
    "POST",
    {
      base_tree: baseCommit.data.tree.sha,
      tree: blobs
    }
  )

  const commit = await githubJsonRequest(
    token,
    repositoryUrl(owner, repo, "/git/commits"),
    "POST",
    {
      message: body.commit_message || "Publish site",
      tree: tree.data.sha,
      parents: [reference.data.object.sha]
    }
  )

  await githubJsonRequest(
    token,
    repositoryUrl(owner, repo, `/git/refs/heads/${encodeURIComponent(branch)}`),
    "PATCH",
    {
      sha: commit.data.sha,
      force: false
    }
  )

  const deploymentUrl = `https://${owner.toLowerCase()}.github.io/${repo}/`
  let pagesBuild = null
  let pagesStatus = "requested"

  try {
    await githubJsonRequest(
      token,
      repositoryUrl(owner, repo, "/pages"),
      "POST",
      {
        source: {
          branch,
          path: "/"
        }
      }
    )
  } catch (error) {
    if (error.status !== 409) {
      pagesStatus = "not_configured"
    }
  }

  if (pagesStatus === "requested") {
    try {
      const build = await githubJsonRequest(
        token,
        repositoryUrl(owner, repo, "/pages/builds"),
        "POST",
        {}
      )
      pagesBuild = build.data
    } catch (error) {
      pagesStatus = error.status === 409
        ? "already_building"
        : "build_not_requested"
    }
  }

  return {
    branch,
    commit_sha: commit.data.sha,
    files: blobs.map(({ path }) => path),
    repository: repository.data.html_url,
    deployment_url: deploymentUrl,
    pages: {
      status: pagesStatus,
      build: pagesBuild
    }
  }
}


// ---------------------------------------------------------
// INSTALL GITHUB APP
// ---------------------------------------------------------
app.get("/github/install", (req, res) => {
  const appSlug = process.env.GITHUB_APP_SLUG

  if (!appSlug) {
    return res.status(500).json({
      error: "GITHUB_APP_SLUG is not configured"
    })
  }

  return res.redirect(
    `https://github.com/apps/${appSlug}/installations/new`
  )
})


// ---------------------------------------------------------
// AFTER INSTALLATION
// ---------------------------------------------------------
app.get("/github/setup", (req, res) => {
  return res.redirect("/github/login")
})


// ---------------------------------------------------------
// START USER AUTHORIZATION
// ---------------------------------------------------------
app.get("/auth/github", async (req, res) => {
  const config = requireGitHubConfiguration(res)

  if (!config) {
    return
  }

  const codeChallenge = String(req.query.code_challenge || "")

  if (!/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) {
    return res.status(400).json({
      error: "A valid PKCE code_challenge is required"
    })
  }

  const transactionToken = crypto.randomBytes(32).toString("base64url")
  const state = crypto.randomBytes(32).toString("hex")
  const expiresAt = new Date(
    Date.now() + oauthStateLifetimeSeconds * 1000
  )

  await pool.query(
    `INSERT INTO oauth_transactions (
       transaction_hash,
       state,
       code_challenge,
       expires_at
     ) VALUES ($1, $2, $3, $4)`,
    [hashValue(transactionToken), state, codeChallenge, expiresAt]
  )

  const authorizeUrl = new URL(
    "https://github.com/login/oauth/authorize"
  )

  authorizeUrl.searchParams.set("client_id", config.clientId)
  authorizeUrl.searchParams.set("redirect_uri", githubCallbackUrl)
  authorizeUrl.searchParams.set("state", state)
  authorizeUrl.searchParams.set("scope", "repo")
  authorizeUrl.searchParams.set("code_challenge", codeChallenge)
  authorizeUrl.searchParams.set("code_challenge_method", "S256")

  return res.json({
    authorization_url: authorizeUrl.toString(),
    transaction: transactionToken,
    expires_at: expiresAt.toISOString()
  })
})


app.get("/auth/desktop/status", async (req, res) => {
  const transactionToken = String(req.query.transaction || "")

  if (!/^[A-Za-z0-9_-]{43,128}$/.test(transactionToken)) {
    return res.status(400).json({
      error: "transaction is required"
    })
  }

  const result = await pool.query(
    `SELECT authorization_code_ciphertext, expires_at, consumed_at
       FROM oauth_transactions
      WHERE transaction_hash = $1`,
    [hashValue(transactionToken)]
  )

  if (result.rowCount === 0) {
    return res.status(404).json({
      error: "Unknown desktop authorization transaction"
    })
  }

  const transaction = result.rows[0]
  const expired = new Date(transaction.expires_at).getTime() <= Date.now()

  if (expired || transaction.consumed_at) {
    return res.status(410).json({
      authorized: false,
      error: "Desktop authorization transaction expired"
    })
  }

  return res.json({
    authorized: Boolean(transaction.authorization_code_ciphertext),
    exchange_url: "/auth/desktop/exchange",
    expires_at: new Date(transaction.expires_at).toISOString()
  })
})


app.get("/github/login", (req, res) => {
  const config = requireGitHubConfiguration(res)

  if (!config) {
    return
  }

  const state = crypto
    .randomBytes(32)
    .toString("hex")

  setOAuthStateCookie(
    res,
    state,
    config.oauthStateSecret
  )

  const authorizeUrl = new URL(
    "https://github.com/login/oauth/authorize"
  )

  authorizeUrl.searchParams.set(
    "client_id",
    config.clientId
  )

  authorizeUrl.searchParams.set(
    "redirect_uri",
    githubCallbackUrl
  )

  authorizeUrl.searchParams.set(
    "state",
    state
  )

  // For a GitHub App, permissions are configured
  // in the App settings. This parameter is harmless
  // but is mainly used by OAuth Apps.
  authorizeUrl.searchParams.set(
    "scope",
    "repo"
  )

  return res.redirect(
    authorizeUrl.toString()
  )
})


// ---------------------------------------------------------
// USER AUTHORIZATION CALLBACK
// ---------------------------------------------------------
app.get("/github/callback", async (req, res) => {
  try {
    const {
      code,
      state,
      error,
      error_description: errorDescription
    } = req.query

    if (error) {
      return res.status(400).json({
        error,
        error_description: errorDescription || null
      })
    }

    if (!code) {
      return res.status(400).json({
        error: "Authorization code is required"
      })
    }

    if (!state) {
      return res.status(400).json({
        error: "OAuth state is missing"
      })
    }

    const config = requireGitHubConfiguration(res)

    if (!config) {
      return
    }

    const transactionResult = await pool.query(
      `SELECT transaction_hash, code_challenge, expires_at, consumed_at
         FROM oauth_transactions
        WHERE state = $1`,
      [String(state)]
    )

    if (transactionResult.rowCount > 0) {
      const transaction = transactionResult.rows[0]

      if (
        transaction.consumed_at ||
        new Date(transaction.expires_at).getTime() <= Date.now()
      ) {
        return res.status(400).json({
          error: "Desktop authorization transaction expired"
        })
      }

      const encryptedCode = encryptToken(String(code))

      await pool.query(
        `UPDATE oauth_transactions
            SET authorization_code_ciphertext = $1,
                authorization_code_iv = $2,
                authorization_code_auth_tag = $3
          WHERE transaction_hash = $4`,
        [
          encryptedCode.ciphertext,
          encryptedCode.iv,
          encryptedCode.authTag,
          transaction.transaction_hash
        ]
      )

      return res.send(
        "Authorization complete. Return to the application to finish sign-in."
      )
    }

    const stateCookie = getCookieValue(req, oauthStateCookieName)

    let statePayload

    try {
      statePayload = jwt.verify(
        stateCookie || "",
        config.oauthStateSecret
      )
    } catch {
      clearOAuthStateCookie(res)

      return res.status(400).json({
        error: "Invalid or expired OAuth state"
      })
    }

    if (
      typeof statePayload !== "object" ||
      typeof statePayload.state !== "string" ||
      statePayload.state !== String(state)
    ) {
      clearOAuthStateCookie(res)

      return res.status(400).json({
        error: "Invalid OAuth state"
      })
    }

    clearOAuthStateCookie(res)

    const token = await exchangeGitHubCode(config, String(code))
    const user = await saveGitHubUser(token)
    const userId = user.id

    await pool.query(
      "DELETE FROM sessions WHERE user_id = $1 OR expires_at <= NOW()",
      [userId]
    )

    await createSession(userId, res)

    console.log(
      "GitHub user authorization completed:",
      {
        login: user.login
      }
    )

    return res.send(
      "GitHub authorization complete. You can return to the app."
    )
  } catch (error) {
    console.error(
      "GITHUB CALLBACK ERROR:",
      error
    )

    return res.status(500).json({
      error: "Internal server error"
    })
  }
})


app.post("/auth/desktop/exchange", async (req, res) => {
  const transactionToken = String(req.body?.transaction || "")
  const codeVerifier = String(req.body?.code_verifier || "")

  if (
    !/^[A-Za-z0-9_-]{43,128}$/.test(transactionToken) ||
    !/^[A-Za-z0-9_-]{43,128}$/.test(codeVerifier)
  ) {
    return res.status(400).json({
      error: "transaction and code_verifier are required"
    })
  }

  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url")
  const client = await pool.connect()

  try {
    await client.query("BEGIN")

    const transactionResult = await client.query(
      `SELECT transaction_hash, code_challenge,
              authorization_code_ciphertext,
              authorization_code_iv,
              authorization_code_auth_tag,
              expires_at, consumed_at
         FROM oauth_transactions
        WHERE transaction_hash = $1
        FOR UPDATE`,
      [hashValue(transactionToken)]
    )

    if (transactionResult.rowCount === 0) {
      await client.query("ROLLBACK")

      return res.status(400).json({
        error: "Invalid desktop authorization transaction"
      })
    }

    const transaction = transactionResult.rows[0]

    if (
      transaction.consumed_at ||
      new Date(transaction.expires_at).getTime() <= Date.now() ||
      !valuesMatch(transaction.code_challenge, codeChallenge)
    ) {
      await client.query("ROLLBACK")

      return res.status(400).json({
        error: "Invalid or expired desktop authorization transaction"
      })
    }

    if (!transaction.authorization_code_ciphertext) {
      await client.query("ROLLBACK")

      return res.status(202).json({
        authorized: false,
        error: "Browser authorization has not completed"
      })
    }

    const config = requireGitHubConfiguration(res)

    if (!config) {
      await client.query("ROLLBACK")
      return
    }

    const encryptedCode = {
      token_ciphertext: transaction.authorization_code_ciphertext,
      token_iv: transaction.authorization_code_iv,
      token_auth_tag: transaction.authorization_code_auth_tag
    }
    const code = decryptToken(encryptedCode)
    const token = await exchangeGitHubCode(
      config,
      code,
      codeVerifier
    )
    const user = await saveGitHubUser(token)

    await client.query(
      "DELETE FROM sessions WHERE user_id = $1 OR expires_at <= NOW()",
      [user.id]
    )

    const session = await createSession(user.id, res)

    await client.query(
      `UPDATE oauth_transactions
          SET user_id = $1, consumed_at = NOW()
        WHERE transaction_hash = $2`,
      [user.id, transaction.transaction_hash]
    )
    await client.query("COMMIT")

    return res.json({
      session_token: session.token,
      expires_at: session.expiresAt.toISOString(),
      user: {
        login: user.login
      }
    })
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {})
    console.error("DESKTOP AUTH EXCHANGE FAILED:", error.message)

    return res.status(error.status || 502).json({
      error: error.status ? error.message : "Desktop authorization failed"
    })
  } finally {
    client.release()
  }
})


app.get("/auth-status", requireSession, (req, res) => {
  return res.json({
    authenticated: true,
    login: res.locals.user.github_login
  })
})


app.get("/github/installation-status", requireSession, async (req, res) => {
  const appSlug = process.env.GITHUB_APP_SLUG

  if (!appSlug) {
    return res.status(500).json({
      error: "GITHUB_APP_SLUG is not configured"
    })
  }

  try {
    const result = await githubRequest(
      `${githubApiUrl}/user/installations?per_page=100`,
      {
        headers: {
          Authorization: `Bearer ${decryptToken(res.locals.user)}`
        }
      }
    )

    const installed = result.data.installations?.some(
      (installation) => installation.app_slug === appSlug
    ) || false

    return res.json({
      installed
    })
  } catch (error) {
    return sendGitHubError(res, error)
  }
})


app.get("/github/user", requireSession, async (req, res) => {
  try {
    const token = decryptToken(res.locals.user)
    const userResult = await githubRequest(
      `${githubApiUrl}/user`,
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    )

    return res.json({
      id: userResult.data.id,
      login: userResult.data.login,
      name: userResult.data.name || null,
      avatar_url: userResult.data.avatar_url || null
    })
  } catch (error) {
    console.error("GITHUB USER REQUEST FAILED:", error.message)

    return res.status(502).json({
      error: "GitHub request failed"
    })
  }
})


app.post("/github/repositories", requireSession, async (req, res) => {
  try {
    const body = req.body || {}
    const name = body.name

    if (
      typeof name !== "string" ||
      !/^[A-Za-z0-9_.-]{1,100}$/.test(name)
    ) {
      return res.status(400).json({
        error: "name must be a valid repository name"
      })
    }

    const result = await githubJsonRequest(
      decryptToken(res.locals.user),
      `${githubApiUrl}/user/repos`,
      "POST",
      {
        name,
        description: typeof body.description === "string"
          ? body.description.slice(0, 350)
          : undefined,
        private: body.private === true,
        auto_init: true
      }
    )

    return res.status(201).json({
      owner: result.data.owner.login,
      name: result.data.name,
      private: result.data.private,
      default_branch: result.data.default_branch,
      html_url: result.data.html_url
    })
  } catch (error) {
    return sendGitHubError(res, error)
  }
})


app.get("/github/repositories/:owner/:repo", requireSession, async (req, res) => {
  const repository = repositoryParams(req)

  if (!repository) {
    return res.status(400).json({
      error: "Invalid repository owner or name"
    })
  }

  try {
    const result = await githubRequest(
      repositoryUrl(repository.owner, repository.repo),
      {
        headers: {
          Authorization: `Bearer ${decryptToken(res.locals.user)}`
        }
      }
    )

    return res.json(result.data)
  } catch (error) {
    return sendGitHubError(res, error)
  }
})


app.delete("/github/repositories/:owner/:repo", requireSession, async (req, res) => {
  const repository = repositoryParams(req)

  if (!repository) {
    return res.status(400).json({
      error: "Invalid repository owner or name"
    })
  }

  try {
    await githubRequest(
      repositoryUrl(repository.owner, repository.repo),
      {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${decryptToken(res.locals.user)}`
        }
      }
    )

    return res.status(204).end()
  } catch (error) {
    return sendGitHubError(res, error)
  }
})


app.post("/github/repositories/:owner/:repo/publish", requireSession, async (req, res) => {
  const repository = repositoryParams(req)

  if (!repository) {
    return res.status(400).json({
      error: "Invalid repository owner or name"
    })
  }

  try {
    const result = await publishFiles(
      decryptToken(res.locals.user),
      repository.owner,
      repository.repo,
      req.body || {},
      {
        createIfMissing: repository.owner.toLowerCase() ===
          res.locals.user.github_login.toLowerCase()
      }
    )

    return res.json(result)
  } catch (error) {
    return sendGitHubError(res, error)
  }
})


app.post("/github/publish", requireSession, async (req, res) => {
  const body = req.body || {}
  const repository = body.repository || {}
  const owner = body.owner || repository.owner
  const repo = body.repo || repository.name

  if (
    typeof owner !== "string" ||
    typeof repo !== "string" ||
    !/^[A-Za-z0-9_.-]{1,100}$/.test(owner) ||
    !/^[A-Za-z0-9_.-]{1,100}$/.test(repo)
  ) {
    return res.status(400).json({
      error: "repository owner and name are required"
    })
  }

  try {
    const result = await publishFiles(
      decryptToken(res.locals.user),
      owner,
      repo,
      body,
      {
        createIfMissing: owner.toLowerCase() ===
          res.locals.user.github_login.toLowerCase()
      }
    )

    return res.json(result)
  } catch (error) {
    return sendGitHubError(res, error)
  }
})


app.post("/github/repositories/:owner/:repo/pages", requireSession, async (req, res) => {
  const repository = repositoryParams(req)

  if (!repository) {
    return res.status(400).json({
      error: "Invalid repository owner or name"
    })
  }

  try {
    const body = req.body || {}
    const result = await githubJsonRequest(
      decryptToken(res.locals.user),
      repositoryUrl(repository.owner, repository.repo, "/pages"),
      "POST",
      {
        source: {
          branch: body.branch || "main",
          path: body.path || "/"
        }
      }
    )

    return res.status(201).json(result.data)
  } catch (error) {
    return sendGitHubError(res, error)
  }
})


app.post("/github/repositories/:owner/:repo/pages/build", requireSession, async (req, res) => {
  const repository = repositoryParams(req)

  if (!repository) {
    return res.status(400).json({
      error: "Invalid repository owner or name"
    })
  }

  try {
    const result = await githubJsonRequest(
      decryptToken(res.locals.user),
      repositoryUrl(repository.owner, repository.repo, "/pages/builds"),
      "POST"
    )

    return res.status(201).json(result.data)
  } catch (error) {
    return sendGitHubError(res, error)
  }
})


app.get("/github/repositories/:owner/:repo/pages/build", requireSession, async (req, res) => {
  const repository = repositoryParams(req)

  if (!repository) {
    return res.status(400).json({
      error: "Invalid repository owner or name"
    })
  }

  try {
    const result = await githubRequest(
      repositoryUrl(repository.owner, repository.repo, "/pages/builds/latest"),
      {
        headers: {
          Authorization: `Bearer ${decryptToken(res.locals.user)}`
        }
      }
    )

    return res.json(result.data)
  } catch (error) {
    return sendGitHubError(res, error)
  }
})


app.post("/logout", requireSession, async (req, res) => {
  const token = getCookieValue(req, sessionCookieName)

  await pool.query(
    "DELETE FROM sessions WHERE token_hash = $1",
    [hashSessionToken(token)]
  )

  clearSessionCookie(res)

  return res.status(204).end()
})


app.get("/healthz", (req, res) => {
  return res.json({
    ok: true
  })
})


async function startServer() {
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required")
  }

  getTokenEncryptionKey()
  await initializeDatabase()

  app.listen(
    port,
    () => {
      console.log(
        `Server running on port ${port}`
      )
    }
  )
}


startServer().catch((error) => {
  console.error("SERVER STARTUP FAILED:", error.message)
  process.exitCode = 1
})