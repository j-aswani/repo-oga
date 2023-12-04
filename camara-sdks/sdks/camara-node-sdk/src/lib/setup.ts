import type { TokenService } from '../services/tokens';
import type { CacheService } from '../services/cache';
import AuthserverClient from '../clients/AuthserverClient';
import Token from '../services/tokens';
import Cache from '../services/cache';

/**
 * Configuration for the Camara SDK
 */
export interface CamaraConfig {
  /** the baseURL for the authorization server. Defaults to CAMARA_AUTHSERVER_URL env var */
  authBaseURL?: string;
  /** the baseURL for the api server. Defaults to CAMARA_API_URL env var */
  apiBaseURL?: string;
  /** The oauth client_id for your app. Defaults to CAMARA_CLIENT_ID env var */
  clientId?: string;
  /** The oauth client_secret for your app. Defaults to CAMARA_CLIENT_SECRET env var */
  clientSecret?: string;
  /** Your issuer configured to use jwt-bearer. Defaults to CAMARA_ISSUER */
  issuer?: string;
  /**
   * PEM encoded of PKCS8 / SPKI / PKIX Client key encoded in base64
   * Used to sign your assertions when using jwt-bearer.
   * Defaults to CAMARA_CLIENT_KEY env var
   */
  clientKey?: string;

  // XXX: we can setup caches providers, loggers, etc etc here
}

export type CamaraSetupId = 'default' | string;

/**
 * Context for the Camara SDK
 */
export interface CamaraSetup {
  id: CamaraSetupId;
  //TODO: This can be syncronous if we use another lib for managing keys than node-jose
  jwks(): Promise<object>;
  authserverClient: AuthserverClient;
  tokenService: TokenService;
  cacheService: CacheService;
}

const setups = new Map<string, CamaraSetup>();

export const defaultSetupId: CamaraSetupId = 'default';

export type Setup = (config?: CamaraConfig, id?: CamaraSetupId) => CamaraSetup;

export const createSetup: Setup = (config = {}, id = defaultSetupId) => {
  const setup = createSdkSetup(config, id);
  setups.set(id, setup);
  return getSetup(id);
};

export const getSetup = (id: CamaraSetupId = defaultSetupId): CamaraSetup => {
  const setup = setups.get(id);
  if (!setup) {
    throw new Error(`Camara setup ${id} not found`);
  }
  return setup;
};

const createSdkSetup = (config: CamaraConfig = {}, id: CamaraSetupId = defaultSetupId): CamaraSetup => {
  const authserverClient = new AuthserverClient({
    ...config,
    baseURL: config.authBaseURL,
  });

  const cacheService = Cache(id, config);
  const tokenService = Token(id, config, { authserverClient, cacheService });
  return {
    id,
    jwks() {
      return authserverClient.jwks();
    },
    authserverClient,
    tokenService,
    cacheService,
  };
};
