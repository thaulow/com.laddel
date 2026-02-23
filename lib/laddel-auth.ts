'use strict';

import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import { URL, URLSearchParams } from 'url';
import { Mutex } from './mutex';
import type { TokenSet, KeycloakErrorBody } from './types';

// Keycloak configuration
const KEYCLOAK_REALM_URL = 'https://id.laddel.no/realms/laddel-app-prod';
const TOKEN_URL = `${KEYCLOAK_REALM_URL}/protocol/openid-connect/token`;
const AUTHORIZE_URL = `${KEYCLOAK_REALM_URL}/protocol/openid-connect/auth`;
const CLIENT_ID = 'laddel-app-prod';
const SCOPE = 'openid profile email offline_access';
const REDIRECT_URI = 'laddel://oauth/callback';

// Headers that mimic the Flutter mobile app
const USER_AGENT = 'Dart/3.7 (dart:io)';
const APP_HEADER = 'Laddel_1.23.2+10230201';

// Token refresh buffer - refresh 60 seconds before actual expiry
const TOKEN_REFRESH_BUFFER_MS = 60_000;

/**
 * Custom error for Keycloak authentication failures.
 * Parses error codes to distinguish permanent vs transient failures.
 */
export class KeycloakError extends Error {
  public readonly status: number;
  public readonly errorCode: string;
  public readonly errorDescription: string;

  constructor(status: number, body: KeycloakErrorBody) {
    super(`Keycloak error: ${body.error || 'unknown'} - ${body.error_description || ''}`);
    this.name = 'KeycloakError';
    this.status = status;
    this.errorCode = body.error || 'unknown';
    this.errorDescription = body.error_description || '';
  }
}

/**
 * Laddel authentication layer with OAuth2 + PKCE against Keycloak.
 *
 * Fixes all 4 bugs from the Home Assistant PoC:
 * 1. Mutex prevents concurrent token refresh (race condition fix)
 * 2. Persist-before-use ensures tokens are saved before being used
 * 3. Auto re-authentication using stored credentials when refresh token is permanently invalid
 * 4. Keycloak error parsing distinguishes invalid_grant (permanent) from transient errors
 */
export class LaddelAuth {
  private tokenSet: TokenSet | null = null;
  private refreshMutex = new Mutex();
  private persistCallback: ((tokens: TokenSet) => Promise<void>) | null = null;
  private credentials: { username: string; password: string } | null = null;
  private log: (...args: any[]) => void;

  constructor(options: {
    log: (...args: any[]) => void;
    persistCallback?: (tokens: TokenSet) => Promise<void>;
  }) {
    this.log = options.log;
    this.persistCallback = options.persistCallback || null;
  }

  /** Set user credentials (used during pairing and stored for re-auth) */
  setCredentials(username: string, password: string): void {
    this.credentials = { username, password };
  }

  /** Set callback to persist tokens (e.g. device.setStoreValue) */
  setPersistCallback(cb: (tokens: TokenSet) => Promise<void>): void {
    this.persistCallback = cb;
  }

  /** Load previously saved tokens (called on device init) */
  loadTokens(tokens: TokenSet): void {
    this.tokenSet = tokens;
  }

  /** Clear in-memory tokens (forces re-auth on next call) */
  invalidateTokens(): void {
    this.tokenSet = null;
  }

  /**
   * Get a valid access token. This is the single entry point for all API calls.
   *
   * BUG FIX #1: Uses mutex to prevent concurrent refresh calls.
   * BUG FIX #3: Falls back to full re-authentication if refresh token is permanently invalid.
   */
  async getValidAccessToken(): Promise<string> {
    return this.refreshMutex.runExclusive(async () => {
      // 1. If we have a valid, non-expired access token, return it
      if (this.tokenSet && !this.isAccessTokenExpired()) {
        return this.tokenSet.access_token;
      }

      // 2. If we have a refresh token, try refreshing
      if (this.tokenSet?.refresh_token) {
        try {
          await this.refreshTokens();
          return this.tokenSet!.access_token;
        } catch (err) {
          if (this.isPermanentAuthError(err)) {
            // BUG FIX #3: Re-authenticate using stored credentials
            this.log('Refresh token permanently invalid, attempting re-authentication...');
            if (!this.credentials) {
              throw new Error('No credentials stored - device must be repaired to re-enter credentials');
            }
            await this.fullAuthenticate();
            return this.tokenSet!.access_token;
          }
          throw err;
        }
      }

      // 3. No tokens at all - full authenticate
      if (!this.credentials) {
        throw new Error('No tokens or credentials available - device must be repaired');
      }
      await this.fullAuthenticate();
      return this.tokenSet!.access_token;
    });
  }

  /**
   * Test credentials by performing a full authentication.
   * Returns true if successful, false otherwise.
   */
  async testCredentials(username: string, password: string): Promise<boolean> {
    const savedCredentials = this.credentials;
    try {
      this.credentials = { username, password };
      await this.fullAuthenticate();
      return true;
    } catch (err) {
      this.log('Credential test failed:', err);
      return false;
    } finally {
      // Restore original credentials if test fails
      if (!this.tokenSet) {
        this.credentials = savedCredentials;
      }
    }
  }

  /**
   * Refresh tokens using the refresh_token grant.
   *
   * BUG FIX #2: Persists new tokens BEFORE updating in-memory state.
   * BUG FIX #4: Parses Keycloak error responses to distinguish error types.
   */
  private async refreshTokens(): Promise<void> {
    if (!this.tokenSet?.refresh_token) {
      throw new Error('No refresh token available');
    }

    this.log('Refreshing access token...');

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: CLIENT_ID,
      refresh_token: this.tokenSet.refresh_token,
      scope: SCOPE,
    });

    const response = await this.httpPost(TOKEN_URL, body.toString(), {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': USER_AGENT,
      'Accept': 'application/json',
    });

    if (response.status !== 200) {
      let errorBody: KeycloakErrorBody;
      try {
        errorBody = JSON.parse(response.body);
      } catch {
        errorBody = { error: 'unknown', error_description: response.body };
      }
      throw new KeycloakError(response.status, errorBody);
    }

    const newTokens: TokenSet = JSON.parse(response.body);
    newTokens.obtained_at = Date.now();

    // BUG FIX #2: PERSIST FIRST, then update in-memory state
    if (this.persistCallback) {
      await this.persistCallback(newTokens);
    }
    this.tokenSet = newTokens;

    this.log(`Access token refreshed - expires in ${newTokens.expires_in}s`);
  }

  /**
   * Full authentication flow: programmatic Keycloak login with PKCE.
   * Steps:
   * 1. Generate PKCE verifier + challenge
   * 2. GET authorize URL → HTML login page + cookies
   * 3. Parse form action URL from HTML
   * 4. POST credentials → 302 redirect with auth code
   * 5. Exchange auth code for tokens
   */
  private async fullAuthenticate(): Promise<void> {
    if (!this.credentials) {
      throw new Error('No credentials available for authentication');
    }

    this.log('Performing full Keycloak authentication...');

    // Step 1: Generate PKCE parameters
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = this.generateCodeChallenge(codeVerifier);
    const state = crypto.randomBytes(16).toString('base64url');
    const nonce = crypto.randomBytes(16).toString('base64url');

    // Step 2: GET the authorize URL to get the login form
    const authorizeParams = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'code',
      ui_locales: 'en',
      state,
      nonce,
      scope: SCOPE,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    const authorizeUrl = `${AUTHORIZE_URL}?${authorizeParams.toString()}`;
    const authorizeResponse = await this.httpGet(authorizeUrl);

    if (authorizeResponse.status !== 200) {
      throw new Error(`Failed to get authorization page: HTTP ${authorizeResponse.status}`);
    }

    // Extract cookies from the response for the next request
    const cookies = this.extractCookies(authorizeResponse.headers);

    // Step 3: Parse the form action URL from HTML
    const formActionUrl = this.parseFormActionUrl(authorizeResponse.body);
    if (!formActionUrl) {
      this.log('HTML snippet:', authorizeResponse.body.substring(0, 500));
      throw new Error('Could not find login form action URL in Keycloak HTML');
    }

    // Step 4: POST credentials to the form action URL
    const loginBody = new URLSearchParams({
      username: this.credentials.username,
      password: this.credentials.password,
      credentialId: '',
    });

    const loginHeaders: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': USER_AGENT,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Origin': 'https://id.laddel.no',
    };
    if (cookies) {
      loginHeaders['Cookie'] = cookies;
    }

    const loginResponse = await this.httpPost(formActionUrl, loginBody.toString(), loginHeaders, false);

    // Expect a 302 redirect with the auth code
    if (loginResponse.status !== 302) {
      throw new Error(`Login failed: expected 302, got ${loginResponse.status}`);
    }

    const locationHeader = loginResponse.headers['location'];
    const location = Array.isArray(locationHeader) ? locationHeader[0] : locationHeader;
    if (!location || !location.includes('code=')) {
      throw new Error('No authorization code in redirect URL - invalid credentials?');
    }

    // Extract auth code from the redirect URL
    const codeMatch = location.match(/code=([^&]+)/);
    if (!codeMatch) {
      throw new Error('Failed to extract authorization code from redirect');
    }
    const authCode = codeMatch[1];

    // Step 5: Exchange auth code for tokens
    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      code: authCode,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    });

    const tokenResponse = await this.httpPost(TOKEN_URL, tokenBody.toString(), {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': USER_AGENT,
      'Accept': 'application/json',
    });

    if (tokenResponse.status !== 200) {
      let errorBody: KeycloakErrorBody;
      try {
        errorBody = JSON.parse(tokenResponse.body);
      } catch {
        errorBody = { error: 'unknown', error_description: tokenResponse.body };
      }
      throw new KeycloakError(tokenResponse.status, errorBody);
    }

    const newTokens: TokenSet = JSON.parse(tokenResponse.body);
    newTokens.obtained_at = Date.now();

    // BUG FIX #2: Persist before updating in-memory
    if (this.persistCallback) {
      await this.persistCallback(newTokens);
    }
    this.tokenSet = newTokens;

    this.log('Full authentication completed successfully');
  }

  // --- Helper Methods ---

  private isAccessTokenExpired(): boolean {
    if (!this.tokenSet || !this.tokenSet.obtained_at) return true;
    const expiresAt = this.tokenSet.obtained_at + (this.tokenSet.expires_in * 1000);
    return Date.now() >= (expiresAt - TOKEN_REFRESH_BUFFER_MS);
  }

  /**
   * BUG FIX #4: Detect permanent auth errors.
   * 'invalid_grant' means the refresh token has been revoked or is permanently invalid.
   */
  private isPermanentAuthError(err: unknown): boolean {
    if (err instanceof KeycloakError) {
      return err.errorCode === 'invalid_grant';
    }
    return false;
  }

  private generateCodeVerifier(): string {
    return crypto.randomBytes(32).toString('base64url');
  }

  private generateCodeChallenge(verifier: string): string {
    return crypto.createHash('sha256').update(verifier).digest('base64url');
  }

  /**
   * Parse the form action URL from Keycloak's HTML login page.
   * Looks for: <form ... action="...login-actions/authenticate?..."
   */
  private parseFormActionUrl(html: string): string | null {
    const match = html.match(/<form[^>]*action="([^"]*login-actions\/authenticate[^"]*)"/);
    if (!match) return null;
    // Decode HTML entities (Keycloak encodes & as &amp;)
    return match[1].replace(/&amp;/g, '&');
  }

  /**
   * Extract cookies from response headers for forwarding.
   * Node.js doesn't auto-manage cookies, so we must do it manually.
   */
  private extractCookies(headers: Record<string, string | string[]>): string {
    const setCookieHeader = headers['set-cookie'];
    if (!setCookieHeader) return '';

    const cookies = Array.isArray(setCookieHeader)
      ? setCookieHeader
      : [setCookieHeader];

    return cookies
      .map((cookie) => cookie.split(';')[0]) // Take only name=value part
      .join('; ');
  }

  // --- HTTP helpers using Node.js built-in https module ---

  private httpGet(url: string): Promise<{ status: number; headers: Record<string, string | string[]>; body: string }> {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const options: https.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        headers: {
          'User-Agent': USER_AGENT,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      };

      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          resolve({
            status: res.statusCode || 0,
            headers: res.headers as Record<string, string | string[]>,
            body,
          });
        });
      });

      req.on('error', reject);
      req.setTimeout(30000, () => {
        req.destroy(new Error('Request timeout'));
      });
      req.end();
    });
  }

  private httpPost(
    url: string,
    body: string,
    headers: Record<string, string>,
    followRedirects: boolean = true,
  ): Promise<{ status: number; headers: Record<string, string | string[]>; body: string }> {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const options: https.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'POST',
        headers: {
          ...headers,
          'Content-Length': Buffer.byteLength(body),
        },
      };

      const req = https.request(options, (res) => {
        // If not following redirects and we got a redirect, return immediately
        if (!followRedirects && res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
          resolve({
            status: res.statusCode,
            headers: res.headers as Record<string, string | string[]>,
            body: '',
          });
          res.resume(); // Drain the response
          return;
        }

        let responseBody = '';
        res.on('data', (chunk: Buffer) => { responseBody += chunk.toString(); });
        res.on('end', () => {
          resolve({
            status: res.statusCode || 0,
            headers: res.headers as Record<string, string | string[]>,
            body: responseBody,
          });
        });
      });

      req.on('error', reject);
      req.setTimeout(30000, () => {
        req.destroy(new Error('Request timeout'));
      });
      req.write(body);
      req.end();
    });
  }
}
