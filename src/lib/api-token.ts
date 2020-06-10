import { MissingApiTokenError } from '../lib/errors';

import * as config from './config';
import { config as userConfig } from './user-config';

export function api() {
  // note: config.TOKEN will potentially come via the environment
  return config.api || config.TOKEN || userConfig.get('api');
}

export function dockerIdExists(options) {
  // TODO: determine config key name
  return (
    options.dockerSnykID ||
    config.dockerSnykID ||
    userConfig.get('dockerSnykID')
  );
}

export function apiTokenExists() {
  const configured = api();
  if (!configured) {
    throw new MissingApiTokenError();
  }
  return configured;
}
