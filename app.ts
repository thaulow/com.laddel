'use strict';

import Homey from 'homey';

module.exports = class LaddelApp extends Homey.App {

  async onInit() {
    this.log('Laddel EV Charging app initialized');
  }

}
