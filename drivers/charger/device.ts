'use strict';

import Homey from 'homey';
import { LaddelAuth } from '../../lib/laddel-auth';
import { LaddelApi, LaddelApiError } from '../../lib/laddel-api';
import type { TokenSet, ChargingSession, ChargerOperatingMode, SessionHistoryResponse } from '../../lib/types';

// Default polling intervals (in milliseconds)
const DEFAULT_POLL_IDLE_MS = 5 * 60 * 1000;     // 5 minutes
const DEFAULT_POLL_CHARGING_MS = 30 * 1000;      // 30 seconds
// Facility/price info changes less frequently - cache for 10 minutes
const FACILITY_CACHE_MS = 10 * 60 * 1000;
// Session history changes even less frequently - cache for 30 minutes
const HISTORY_CACHE_MS = 30 * 60 * 1000;

class LaddelChargerDevice extends Homey.Device {
  private auth!: LaddelAuth;
  private api!: LaddelApi;
  private pollInterval: ReturnType<typeof setInterval> | null = null;
  private isCharging = false;
  private lastOperatingMode: string = '';
  private lastPrice: number | null = null;
  private facilityCacheTime: number = 0;
  private cachedPrice: number | null = null;
  private historyCacheTime: number = 0;
  private isCarConnected = false;

  async onInit(): Promise<void> {
    this.log('Laddel Charger device initializing:', this.getName());

    await this.initializeAuth();
    await this.initializeCapabilities();

    // Do initial poll and start scheduling
    await this.poll();
    this.schedulePoll();
  }

  async onUninit(): Promise<void> {
    this.clearPollInterval();
  }

  async onDeleted(): Promise<void> {
    this.clearPollInterval();
  }

  async onSettings(event: {
    oldSettings: Record<string, any>;
    newSettings: Record<string, any>;
    changedKeys: string[];
  }): Promise<string | void> {
    // If polling intervals changed, reschedule
    if (event.changedKeys.includes('pollIntervalIdle') ||
        event.changedKeys.includes('pollIntervalCharging')) {
      this.schedulePoll();
    }
  }

  /**
   * Called from the repair flow in the driver to reinitialize auth
   * after credentials have been updated.
   */
  async reinitializeAuth(): Promise<void> {
    this.log('Reinitializing authentication...');
    await this.initializeAuth();
    await this.poll();
    this.schedulePoll();
  }

  // --- Initialization ---

  private async initializeAuth(): Promise<void> {
    this.auth = new LaddelAuth({
      log: this.log.bind(this),
      persistCallback: async (tokens: TokenSet) => {
        await this.setStoreValue('tokens', tokens);
      },
    });

    // Load credentials
    const username = this.getStoreValue('username') as string | undefined;
    const password = this.getStoreValue('password') as string | undefined;
    if (username && password) {
      this.auth.setCredentials(username, password);
    }

    // Load saved tokens
    const savedTokens = this.getStoreValue('tokens') as TokenSet | undefined;
    if (savedTokens) {
      this.auth.loadTokens(savedTokens);
    }

    this.api = new LaddelApi(this.auth, this.log.bind(this));
  }

  private async initializeCapabilities(): Promise<void> {
    // Ensure all required capabilities exist
    const requiredCapabilities = [
      'onoff', 'measure_power', 'meter_power', 'charging_duration',
      'electricity_price', 'charging_cost', 'last_session_cost',
      'monthly_cost', 'monthly_sessions', 'charger_mode',
      'car_connected', 'max_power_capacity',
    ];
    for (const cap of requiredCapabilities) {
      if (!this.hasCapability(cap)) {
        await this.addCapability(cap);
      }
    }

    // Register listener for the onoff capability (start/stop charging toggle)
    this.registerCapabilityListener('onoff', async (value: boolean) => {
      if (value) {
        await this.startCharging();
      } else {
        await this.stopCharging();
      }
    });
  }

  // --- Polling ---

  private getIdleInterval(): number {
    const setting = this.getSetting('pollIntervalIdle');
    return (setting ? setting * 1000 : DEFAULT_POLL_IDLE_MS);
  }

  private getChargingInterval(): number {
    const setting = this.getSetting('pollIntervalCharging');
    return (setting ? setting * 1000 : DEFAULT_POLL_CHARGING_MS);
  }

  private schedulePoll(): void {
    this.clearPollInterval();
    const interval = this.isCharging ? this.getChargingInterval() : this.getIdleInterval();
    this.log(`Scheduling poll every ${interval / 1000}s (${this.isCharging ? 'charging' : 'idle'})`);
    this.pollInterval = this.homey.setInterval(async () => {
      await this.poll();
    }, interval);
  }

  private clearPollInterval(): void {
    if (this.pollInterval) {
      this.homey.clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  private async poll(): Promise<void> {
    try {
      const chargerId = this.getData().id;
      this.log('Polling charger state...');

      // Fetch operating mode and current session in parallel
      const [operatingMode, currentSession] = await Promise.all([
        this.api.getChargerOperatingMode(chargerId).catch((err) => {
          this.log('Failed to fetch operating mode:', err);
          return null;
        }),
        this.api.getCurrentSession().catch((err) => {
          this.log('Failed to fetch current session:', err);
          return null;
        }),
      ]);

      this.log('Poll results - operatingMode:', operatingMode ? JSON.stringify(operatingMode) : 'null');
      this.log('Poll results - currentSession:', currentSession ? JSON.stringify(currentSession) : 'null');

      // Update state from operating mode
      if (operatingMode) {
        await this.updateFromOperatingMode(operatingMode);
      }

      // Update state from current session
      if (currentSession) {
        await this.updateFromSession(currentSession);
      } else {
        // No active session
        await this.setCapabilityValue('meter_power', 0).catch(this.error);
        await this.setCapabilityValue('charging_cost', 0).catch(this.error);
        await this.setCapabilityValue('charging_duration', 0).catch(this.error);
      }

      // Fetch facility info for price (cached, refreshed every 10 min)
      await this.updatePrice();

      // Fetch session history for last session cost and monthly stats (cached)
      await this.updateSessionHistory();

      // Mark device available if it was previously unavailable
      if (!this.getAvailable()) {
        await this.setAvailable();
      }
    } catch (err) {
      this.error('Poll failed:', err);
      await this.handlePollError(err);
    }
  }

  // --- State Updates ---

  private async updateFromOperatingMode(mode: ChargerOperatingMode): Promise<void> {
    const wasCharging = this.isCharging;
    const wasCarConnected = this.isCarConnected;
    const previousMode = this.lastOperatingMode;
    const currentMode = mode.operatingMode || 'UNKNOWN';

    // Determine if currently charging
    this.isCharging = currentMode === 'CHARGING';

    // Determine if car is connected
    const connectedModes = ['CAR_CONNECTED', 'CHARGING', 'IDLE', 'OCCUPIED', 'COMPLETED'];
    this.isCarConnected = connectedModes.includes(currentMode);

    // Update capabilities
    await this.setCapabilityValue('onoff', this.isCharging).catch(this.error);
    await this.setCapabilityValue('charger_mode', this.mapModeToDisplay(currentMode)).catch(this.error);
    await this.setCapabilityValue('car_connected', this.isCarConnected).catch(this.error);

    // If not charging, set power to 0
    if (!this.isCharging) {
      await this.setCapabilityValue('measure_power', 0).catch(this.error);
    }

    // Detect charging state transitions
    if (!wasCharging && this.isCharging) {
      this.log('Charging started');
      await this.homey.flow.getDeviceTriggerCard('charging_started')
        .trigger(this, {}, {})
        .catch(this.error);
    } else if (wasCharging && !this.isCharging) {
      this.log('Charging stopped');
      await this.homey.flow.getDeviceTriggerCard('charging_stopped')
        .trigger(this, {}, {})
        .catch(this.error);

      // Fire detailed charging stopped trigger with session info
      const energy = this.getCapabilityValue('meter_power') || 0;
      const duration = this.getCapabilityValue('charging_duration') || 0;
      const cost = this.getCapabilityValue('charging_cost') || 0;
      await this.homey.flow.getDeviceTriggerCard('charging_stopped_with_details')
        .trigger(this, { energy, duration, cost }, {})
        .catch(this.error);

      // Invalidate session history cache so next poll fetches fresh data
      this.historyCacheTime = 0;
    }

    // Detect car connection transitions
    if (!wasCarConnected && this.isCarConnected && previousMode !== '') {
      this.log('Car connected');
      await this.homey.flow.getDeviceTriggerCard('car_connected')
        .trigger(this, {}, {})
        .catch(this.error);
    } else if (wasCarConnected && !this.isCarConnected && previousMode !== '') {
      this.log('Car disconnected');
      await this.homey.flow.getDeviceTriggerCard('car_disconnected')
        .trigger(this, {}, {})
        .catch(this.error);
    }

    // Fire status changed trigger if mode changed
    if (currentMode !== previousMode && previousMode !== '') {
      await this.homey.flow.getDeviceTriggerCard('charger_status_changed')
        .trigger(this, { status: currentMode }, {})
        .catch(this.error);
    }

    this.lastOperatingMode = currentMode;

    // Reschedule poll if charging state changed
    if (wasCharging !== this.isCharging) {
      this.schedulePoll();
    }
  }

  private async updateFromSession(session: ChargingSession): Promise<void> {
    // Energy consumed this session (kWh)
    const energyKwh = session.charged ?? 0;
    await this.setCapabilityValue('meter_power', energyKwh).catch(this.error);

    // Calculate duration and power from session start time
    if (session.startTime) {
      const startTime = new Date(session.startTime).getTime();
      const now = Date.now();
      const durationMinutes = Math.round((now - startTime) / (1000 * 60));
      const durationHours = (now - startTime) / (1000 * 60 * 60);

      // Update charging duration
      await this.setCapabilityValue('charging_duration', durationMinutes).catch(this.error);

      // Calculate average power from energy and duration
      if (this.isCharging && energyKwh > 0 && durationHours > 0) {
        const avgPowerKw = energyKwh / durationHours;
        const powerW = Math.round(avgPowerKw * 1000);
        await this.setCapabilityValue('measure_power', powerW).catch(this.error);
      }
    }

    // Calculate estimated session cost (energy * price)
    if (this.cachedPrice != null && energyKwh > 0) {
      const cost = Math.round(energyKwh * this.cachedPrice * 100) / 100;
      await this.setCapabilityValue('charging_cost', cost).catch(this.error);
    }

    // Update settings with facility info
    const facilityName = this.getStoreValue('facilityName');
    const chargerName = this.getStoreValue('chargerName');
    if (facilityName || chargerName) {
      await this.setSettings({
        facilityName: facilityName || '-',
        chargerName: chargerName || '-',
      }).catch(this.error);
    }
  }

  private async updatePrice(): Promise<void> {
    const now = Date.now();

    // Only refresh price from API every FACILITY_CACHE_MS
    if (this.cachedPrice != null && (now - this.facilityCacheTime) < FACILITY_CACHE_MS) {
      return;
    }

    const facilityId = this.getStoreValue('facilityId') as string | undefined;
    if (!facilityId) return;

    try {
      const facilityInfo = await this.api.getFacilityInfo(facilityId);
      if (!facilityInfo) return;

      this.log('Facility info:', JSON.stringify(facilityInfo));

      const price = facilityInfo.total;
      if (price != null) {
        this.cachedPrice = price;
        this.facilityCacheTime = now;

        await this.setCapabilityValue('electricity_price', Math.round(price * 100) / 100).catch(this.error);

        // Fire price changed trigger if price actually changed
        if (this.lastPrice !== null && this.lastPrice !== price) {
          await this.homey.flow.getDeviceTriggerCard('electricity_price_changed')
            .trigger(this, { price }, {})
            .catch(this.error);
        }
        this.lastPrice = price;
      }

      // Update max power capacity from facility info
      if (facilityInfo.kweffect != null) {
        await this.setCapabilityValue('max_power_capacity', facilityInfo.kweffect).catch(this.error);
      }
    } catch (err) {
      this.log('Failed to fetch facility info for price:', err);
    }
  }

  private async updateSessionHistory(): Promise<void> {
    const now = Date.now();

    // Only refresh session history every HISTORY_CACHE_MS
    if ((now - this.historyCacheTime) < HISTORY_CACHE_MS) {
      return;
    }

    try {
      const history = await this.api.getPreviousSessions(0);
      if (!history) return;

      this.historyCacheTime = now;

      // Last session cost from most recent receipt
      if (history.receipts?.length) {
        const lastReceipt = history.receipts[0];
        if (lastReceipt.totalAmount != null) {
          await this.setCapabilityValue('last_session_cost',
            Math.round(lastReceipt.totalAmount * 100) / 100).catch(this.error);
        }
      }

      // Monthly cost and session count from current month summary
      if (history.monthlySummaries?.length) {
        const currentMonth = new Date().toISOString().substring(0, 7); // "YYYY-MM"
        const currentSummary = history.monthlySummaries.find(
          (s) => s.month === currentMonth,
        );
        if (currentSummary) {
          if (currentSummary.totalAmount != null) {
            await this.setCapabilityValue('monthly_cost',
              Math.round(currentSummary.totalAmount * 100) / 100).catch(this.error);
          }
          if (currentSummary.sessionCount != null) {
            await this.setCapabilityValue('monthly_sessions',
              currentSummary.sessionCount).catch(this.error);
          }
        }
      }
    } catch (err) {
      this.log('Failed to fetch session history:', err);
    }
  }

  private mapModeToDisplay(apiMode: string): string {
    const modeMap: Record<string, string> = {
      'CAR_CONNECTED': 'Car Connected',
      'DISCONNECTED': 'Disconnected',
      'AVAILABLE': 'Available',
      'CHARGING': 'Charging',
      'IDLE': 'Idle',
      'OCCUPIED': 'Occupied',
      'OUT_OF_ORDER': 'Out of Order',
      'OFFLINE': 'Offline',
      'COMPLETED': 'Completed',
    };
    return modeMap[apiMode] || apiMode;
  }

  // --- Error Handling ---

  private async handlePollError(err: unknown): Promise<void> {
    const message = err instanceof Error ? err.message : String(err);

    // Permanent auth failure - needs user intervention (repair)
    if (message.includes('No credentials') ||
        message.includes('must be repaired')) {
      await this.setUnavailable(
        this.homey.__('errors.auth_failed'),
      );
      return;
    }

    // Transient errors - device stays available, will retry next poll
    if (err instanceof LaddelApiError && err.status >= 500) {
      this.log('Transient API error, will retry next poll');
      return;
    }
  }

  // --- Public methods for flow actions ---

  async startCharging(): Promise<void> {
    const chargerId = this.getData().id;
    this.log('Starting charging session for charger:', chargerId);
    try {
      await this.api.startCharging({ chargerId });
    } catch (err) {
      if (err instanceof LaddelApiError) {
        throw new Error(this.mapApiErrorToMessage(err.errorKey, 'start'));
      }
      throw err;
    }
    // The API schedules the start - charger takes a few seconds to begin.
    // Switch to rapid polling to catch the state change quickly.
    this.startRapidPolling();
  }

  async stopCharging(): Promise<void> {
    // We need the session ID to stop. Get it from the current session.
    const session = await this.api.getCurrentSession();
    if (!session?.sessionId) {
      throw new Error(this.homey.__('errors.no_active_session'));
    }
    this.log('Stopping charging session:', session.sessionId);
    try {
      await this.api.stopCharging(session.sessionId);
    } catch (err) {
      if (err instanceof LaddelApiError) {
        throw new Error(this.mapApiErrorToMessage(err.errorKey, 'stop'));
      }
      throw err;
    }
    // The API schedules the stop - charger takes a few seconds to stop.
    this.startRapidPolling();
  }

  private mapApiErrorToMessage(errorKey: string | null, action: string): string {
    switch (errorKey) {
      case 'userAlreadyInSession':
        return this.homey.__('errors.already_in_session');
      case 'chargerNotAvailable':
        return this.homey.__('errors.charger_not_available');
      case 'chargerOffline':
        return this.homey.__('errors.charger_offline');
      case 'outstandingDebt':
        return this.homey.__('errors.outstanding_debt');
      case 'noSession':
        return this.homey.__('errors.no_active_session');
      default:
        return this.homey.__('errors.action_failed', { action });
    }
  }

  /**
   * After a start/stop action, poll rapidly (every 5s) for up to 60s
   * to catch the state change, then return to normal polling.
   */
  private startRapidPolling(): void {
    this.clearPollInterval();
    let rapidPollCount = 0;
    const maxRapidPolls = 12; // 12 x 5s = 60s

    this.log('Starting rapid polling to detect state change...');

    this.pollInterval = this.homey.setInterval(async () => {
      rapidPollCount++;
      await this.poll();

      // Stop rapid polling after max attempts or once we've detected the change
      if (rapidPollCount >= maxRapidPolls) {
        this.log('Rapid polling complete, returning to normal schedule');
        this.schedulePoll();
      }
    }, 5000);
  }
}

module.exports = LaddelChargerDevice;
