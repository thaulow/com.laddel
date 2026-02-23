'use strict';

import Homey from 'homey';
import { LaddelAuth } from '../../lib/laddel-auth';
import { LaddelApi } from '../../lib/laddel-api';

class LaddelChargerDriver extends Homey.Driver {

  async onInit(): Promise<void> {
    this.log('Laddel Charger driver initialized');
    this.registerFlowCards();
  }

  async onPair(session: any): Promise<void> {
    let username = '';
    let password = '';
    let auth: LaddelAuth | null = null;
    let api: LaddelApi | null = null;

    // Handle the login_credentials step
    session.setHandler('login', async (data: { username: string; password: string }) => {
      username = data.username;
      password = data.password;

      this.log('Pairing: validating credentials...');
      auth = new LaddelAuth({ log: this.log.bind(this) });
      auth.setCredentials(username, password);

      try {
        const valid = await auth.testCredentials(username, password);
        if (valid) {
          this.log('Pairing: credentials validated successfully');
          api = new LaddelApi(auth, this.log.bind(this));
        } else {
          this.log('Pairing: invalid credentials');
        }
        return valid;
      } catch (err) {
        this.error('Pairing: login failed:', err);
        return false;
      }
    });

    // Handle the list_devices step
    session.setHandler('list_devices', async () => {
      if (!api || !auth) {
        this.error('Pairing: no authenticated API client');
        return [];
      }

      this.log('Pairing: discovering chargers...');

      try {
        // Get chargers the user has recently used
        const latestChargers = await api.getLatestUsedChargers();

        if (!latestChargers?.chargers?.length) {
          this.log('Pairing: no chargers found');
          return [];
        }

        this.log(`Pairing: found ${latestChargers.chargers.length} charger(s)`);
        this.log('Pairing: raw API response:', JSON.stringify(latestChargers, null, 2));

        return latestChargers.chargers.map((charger: any) => {
          // API nests charger details under charger.information
          const info = charger.information || {};
          const chargerId = info.chargerId || '';
          const chargerName = info.name || info.chargerReference || 'Charger';
          const facilityName = info.facilityName || '';
          const facilityId = info.facilityId || '';

          this.log(`Pairing: charger ${chargerId} - ${chargerName} at ${facilityName}`);

          return {
            name: facilityName ? `${chargerName} (${facilityName})` : chargerName,
            data: {
              id: String(chargerId),
            },
            store: {
              facilityId: String(facilityId),
              facilityName,
              chargerName,
              username,
              password,
            },
          };
        });
      } catch (err) {
        this.error('Pairing: failed to discover chargers:', err);
        return [];
      }
    });
  }

  async onRepair(session: any, device: any): Promise<void> {
    session.setHandler('login', async (data: { username: string; password: string }) => {
      this.log('Repair: validating new credentials...');

      const auth = new LaddelAuth({ log: this.log.bind(this) });
      auth.setCredentials(data.username, data.password);

      try {
        const valid = await auth.testCredentials(data.username, data.password);
        if (valid) {
          this.log('Repair: credentials validated, updating device store');
          // Update stored credentials
          await device.setStoreValue('username', data.username);
          await device.setStoreValue('password', data.password);
          // Clear old tokens to force fresh auth on next poll
          await device.setStoreValue('tokens', null);
          // Mark device available again
          await device.setAvailable();
          // Reinitialize the device's auth
          if (typeof device.reinitializeAuth === 'function') {
            await device.reinitializeAuth();
          }
        }
        return valid;
      } catch (err) {
        this.error('Repair: login failed:', err);
        return false;
      }
    });
  }

  private registerFlowCards(): void {
    // Action: Start Charging
    this.homey.flow.getActionCard('start_charging')
      .registerRunListener(async (args: any) => {
        const device = args.device;
        if (typeof device.startCharging === 'function') {
          await device.startCharging();
        }
      });

    // Action: Stop Charging
    this.homey.flow.getActionCard('stop_charging')
      .registerRunListener(async (args: any) => {
        const device = args.device;
        if (typeof device.stopCharging === 'function') {
          await device.stopCharging();
        }
      });

    // Condition: Is Charging
    this.homey.flow.getConditionCard('is_charging')
      .registerRunListener(async (args: any) => {
        const device = args.device;
        return device.getCapabilityValue('onoff') === true;
      });

    // Condition: Electricity price below threshold
    this.homey.flow.getConditionCard('electricity_price_below')
      .registerRunListener(async (args: any) => {
        const device = args.device;
        const currentPrice = device.getCapabilityValue('electricity_price') || 0;
        return currentPrice < args.price;
      });

    // Condition: Is Car Connected
    this.homey.flow.getConditionCard('is_car_connected')
      .registerRunListener(async (args: any) => {
        const device = args.device;
        return device.getCapabilityValue('car_connected') === true;
      });
  }
}

module.exports = LaddelChargerDriver;
