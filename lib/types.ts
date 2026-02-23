'use strict';

/** OAuth2 token set from Keycloak */
export interface TokenSet {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  refresh_expires_in: number;
  token_type: string;
  id_token?: string;
  scope: string;
  /** Timestamp (Date.now()) when the token was obtained */
  obtained_at: number;
}

/** Current charging session from /api/session/get-current-session */
export interface ChargingSession {
  sessionId: string;
  chargerId: string;
  facilityId: string;
  type: string; // "ACTIVE", "COMPLETED", "CANCELLED"
  chargerOperatingMode: string; // "CHARGING", "COMPLETED", "IDLE"
  startTime: string;
  endTime?: string;
  charged?: number; // kWh
  latitude?: number;
  longitude?: number;
  vehicle?: string;
  chargingPrivately?: boolean;
  errorKey?: string; // "noSession" when no active session
}

/** Charger operating mode from /api/charger/operating-mode */
export interface ChargerOperatingMode {
  chargerId: string;
  operatingMode: string; // "CAR_CONNECTED", "DISCONNECTED", "CHARGING", "IDLE", etc.
  errorKey?: string;
}

/** Facility info from /api/facility/information */
export interface FacilityInfo {
  facilityId: string;
  facilityName: string;
  address?: string;
  postalCode?: string;
  city?: string;
  country?: string;
  county?: string;
  latitude?: number;
  longitude?: number;
  kweffect?: number;
  total?: number; // electricity price
  averageElectricityPriceAndDeliveryFee?: number;
  averageSurCharge?: number;
  markup?: number;
  priceType?: string;
  chargingFeeIncludingVAT?: number;
  chargers?: Array<{
    chargerId: string;
    name: string;
    chargerReference: string;
    availabilityCode: string; // "AVAILABLE", "IN_SESSION", etc.
    session: { start: string; end: string | null } | null;
    favorited?: boolean;
    whitelisted?: boolean;
  }>;
}

/** Subscription data from /api/facility/subscription */
export interface SubscriptionData {
  activeSubscriptions?: Array<{
    facilityId: string;
    facilityName: string;
    status: string;
    monthlyFee?: number;
    monthlyFeeCurrency?: string;
    activationDate?: string;
    expirationDate?: string;
  }>;
}

/** Latest charger from /api/history/latest-used-chargers */
export interface LatestChargersResponse {
  errorKey: string | null;
  chargers: Array<{
    information: {
      chargerId: string;
      facilityId: string;
      facilityName: string;
      name: string;
      chargerReference: string;
      address?: string;
      postalCode?: string;
      city?: string;
      country?: string;
      kweffect?: number;
      total?: number;
      priceType?: string;
      favorited?: boolean;
      chargingFeeIncludingVAT?: number;
    };
    availability: {
      code: string; // "AVAILABLE", "CHARGING", etc.
      session: any | null;
      errorKeyObject: string;
    };
    lastUsed: string;
  }>;
}

/** Session history from /api/history/previous-sessions */
export interface SessionHistoryResponse {
  receipts?: Array<{
    sessionId: string;
    sessionStart: string;
    sessionEnd: string;
    chargerName: string;
    facilityName: string;
    powerConsumption: number;
    totalAmount: number;
    totalPriceExclVat?: number;
    totalVat?: number;
    paymentStatus: string;
    currency: string;
  }>;
  monthlySummaries?: Array<{
    month: string;
    totalAmount: number;
    sessionCount: number;
  }>;
}

/** Keycloak error response body */
export interface KeycloakErrorBody {
  error: string;
  error_description?: string;
}
