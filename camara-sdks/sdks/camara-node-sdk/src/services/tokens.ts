import type { CamaraConfig, CamaraSetupId } from '../lib/setup';
import type { AuthserverRequestContext, TokenSet } from '../clients/AuthserverClient';
import type AuthserverClient from '../clients/AuthserverClient';
import type { CacheService, TokenCacheKey } from './cache';

export interface CamaraTokenSet extends TokenSet {
  expires_at: number;
}
export interface TokenService {
  getLoginTokenSet: (
    params: { sub: string; scope?: string },
    context?: AuthserverRequestContext
  ) => Promise<CamaraTokenSet>;
}

const createService = (
  id: CamaraSetupId,
  config: CamaraConfig,
  {
    authserverClient,
    cacheService,
  }: { authserverClient: InstanceType<typeof AuthserverClient>; cacheService: CacheService }
): TokenService => {
  /** Safe period where the token is considered expired (seconds) */
  const TOKEN_EXPIRATION_SAFE_WINDOW = 2 * 60;

  const getLoginTokenSet: TokenService['getLoginTokenSet'] = async ({ sub, scope }, context) => {
    const cache = await cacheService.getCache('token');
    const cacheKey: TokenCacheKey = `${id}:token:login:${sub}`;
    const token = await cache.get(cacheKey);
    if (token) {
      return token;
    }
    // XXX: The authorization method is not decided yet.
    // For now, we will use the JWT Bearer Token with an ipport subject with an special syntax (ipport@ip:port)
    const tokenSet = await authserverClient.getJWTBearerToken({ sub, scope }, context);
    const camaraTokenSet = toCamaraTokenSet(tokenSet);

    cache.set(`${id}:token:login:${sub}`, camaraTokenSet, {
      ttl: tokenSet.expires_in,
    });
    return camaraTokenSet;
  };

  function toCamaraTokenSet(tokenSet: TokenSet): CamaraTokenSet {
    return {
      ...tokenSet,
      expires_at: Date.now() + (tokenSet.expires_in - TOKEN_EXPIRATION_SAFE_WINDOW) * 1000,
    };
  }

  return {
    getLoginTokenSet,
  };
};

export default createService;
