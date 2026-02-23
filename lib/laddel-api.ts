'use strict';

import * as https from 'https';
import { URL } from 'url';
import { LaddelAuth } from './laddel-auth';
import type {
  ChargingSession,
  ChargerOperatingMode,
  FacilityInfo,
  SubscriptionData,
  LatestChargersResponse,
  SessionHistoryResponse,
} from './types';

const BASE_URL = 'https://api.laddel.no/v1';
const USER_AGENT = 'Dart/3.7 (dart:io)';
const APP_HEADER = 'Laddel_1.23.2+10230201';

export class LaddelApiError extends Error {
  public readonly status: number;
  public readonly responseBody: string;
  public readonly errorKey: string | null;

  constructor(status: number, body: string) {
    super(`Laddel API error ${status}: ${body}`);
    this.name = 'LaddelApiError';
    this.status = status;
    this.responseBody = body;
    // Try to extract errorKey from JSON response
    try {
      const parsed = JSON.parse(body);
      this.errorKey = parsed.errorKey || null;
    } catch {
      this.errorKey = null;
    }
  }
}

/**
 * API client for the Laddel backend.
 * Delegates all authentication to LaddelAuth.
 * Retries on 401 (forces token refresh) with exponential backoff.
 */
export class LaddelApi {
  private auth: LaddelAuth;
  private log: (...args: any[]) => void;

  constructor(auth: LaddelAuth, log: (...args: any[]) => void) {
    this.auth = auth;
    this.log = log;
  }

  // --- Public API Methods ---

  async getSubscription(): Promise<SubscriptionData> {
    return this.request<SubscriptionData>('GET', '/api/facility/subscription');
  }

  async getCurrentSession(): Promise<ChargingSession | null> {
    try {
      const data = await this.request<ChargingSession>('GET', '/api/session/get-current-session');
      if (data && (data as any).errorKey === 'noSession') {
        return null;
      }
      return data;
    } catch (err) {
      // API returns HTTP 400 with errorKey "noSession" when no active session
      if (err instanceof LaddelApiError && err.errorKey === 'noSession') {
        return null;
      }
      throw err;
    }
  }

  async getChargerOperatingMode(chargerId: string): Promise<ChargerOperatingMode | null> {
    try {
      return await this.request<ChargerOperatingMode>(
        'GET',
        `/api/charger/operating-mode?chargerId=${encodeURIComponent(chargerId)}`,
      );
    } catch (err) {
      // API returns HTTP 400 when charger is offline or not found
      if (err instanceof LaddelApiError && err.errorKey === 'chargerNotFound') {
        return null;
      }
      throw err;
    }
  }

  async getFacilityInfo(facilityId: string): Promise<FacilityInfo> {
    return this.request<FacilityInfo>(
      'GET',
      `/api/facility/information?id=${encodeURIComponent(facilityId)}`,
    );
  }

  async getLatestUsedChargers(): Promise<LatestChargersResponse> {
    return this.request<LatestChargersResponse>('GET', '/api/history/latest-used-chargers');
  }

  async getPreviousSessions(page: number = 0): Promise<SessionHistoryResponse> {
    return this.request<SessionHistoryResponse>(
      'GET',
      `/api/history/previous-sessions?page=${page}`,
    );
  }

  async startCharging(data: {
    chargerId: string;
    scheduledStartTime?: string | null;
    scheduledEndTime?: string | null;
    registrationNumber?: string | null;
    requestPrivateSession?: boolean;
  }): Promise<any> {
    return this.request('POST', '/api/session/start/jobs/schedule', data);
  }

  async stopCharging(sessionId: string): Promise<any> {
    return this.request('POST', '/api/session/stop/jobs/schedule', { sessionId });
  }

  // --- Internal Request Logic ---

  private async request<T>(
    method: string,
    path: string,
    body?: any,
    retries: number = 2,
  ): Promise<T> {
    for (let attempt = 0; attempt <= retries; attempt++) {
      const token = await this.auth.getValidAccessToken();

      const headers: Record<string, string> = {
        'User-Agent': USER_AGENT,
        'x-app': APP_HEADER,
        'Authorization': `Bearer ${token}`,
        'Host': 'api.laddel.no',
      };

      if (body && method === 'POST') {
        headers['Content-Type'] = 'application/json';
      }

      const response = await this.httpRequest(
        method,
        `${BASE_URL}${path}`,
        headers,
        body ? JSON.stringify(body) : undefined,
      );

      if (response.status === 401) {
        this.log(`API returned 401 on attempt ${attempt + 1}/${retries + 1}, invalidating token`);
        // Invalidate cached token so getValidAccessToken() will refresh
        this.auth.invalidateTokens();
        if (attempt < retries) {
          // Exponential backoff: 1s, 2s
          await this.delay(1000 * (attempt + 1));
          continue;
        }
        throw new LaddelApiError(401, 'Authentication failed after retries');
      }

      if (response.status < 200 || response.status >= 300) {
        throw new LaddelApiError(response.status, response.body);
      }

      try {
        return JSON.parse(response.body) as T;
      } catch {
        throw new LaddelApiError(response.status, `Invalid JSON response: ${response.body.substring(0, 200)}`);
      }
    }

    throw new Error('Max retries exceeded');
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private httpRequest(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: string,
  ): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const options: https.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers,
      };

      if (body) {
        (options.headers as Record<string, string>)['Content-Length'] = String(Buffer.byteLength(body));
      }

      const req = https.request(options, (res) => {
        let responseBody = '';
        res.on('data', (chunk: Buffer) => { responseBody += chunk.toString(); });
        res.on('end', () => {
          resolve({
            status: res.statusCode || 0,
            body: responseBody,
          });
        });
      });

      req.on('error', reject);
      req.setTimeout(30000, () => {
        req.destroy(new Error('Request timeout'));
      });

      if (body) {
        req.write(body);
      }
      req.end();
    });
  }
}
