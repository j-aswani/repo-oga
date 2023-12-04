import type { CamaraConfig, CamaraSetupId } from '../lib/setup';
import { LRUCache } from 'lru-cache';
import type { CamaraTokenSet } from './tokens';

export interface CacheService {
  getCache: <T extends CacheId>(id: T) => Promise<CacheType<T>>;
}

interface Cache<K, V> {
  get: (key: K) => Promise<V | undefined>;
  set: (key: K, value: V, opts?: { ttl?: number }) => Promise<void>;
}
type CacheType<T> = T extends 'token' ? TokenCache : never;

type CacheId = 'token';

// Token Cache stuff
type TokenCacheData = `login:${string}`;
export type TokenCacheKey = `${CamaraSetupId}:token:${TokenCacheData}`;
type TokenCache = Cache<TokenCacheKey, CamaraTokenSet>;

// Default cache implementation
const defaultTokenCache = createMemoryCache<TokenCacheKey, CamaraTokenSet>({
  // number of tokens to cache
  max: 100,
  // time to live: 3500 seconds = 58 minutes. 2 minutes less than the token expiration time
  ttl: 1000 * 3500,
});

const createService = (setupId: CamaraSetupId, config: CamaraConfig): CacheService => {
  // XXX: Let the user provide the cache implementation in the configuration
  async function getCache<T extends CacheId>(id: T): Promise<CacheType<T>> {
    switch (id) {
      case 'token':
        return defaultTokenCache as CacheType<T>;
      default:
        // XXX: casting "as never" should not be needed
        assertCacheId(id as never);
    }
  }
  return {
    getCache,
  };
};

function assertCacheId(id: never): never {
  throw new Error(`Cache ${id} not found`);
}

function createMemoryCache<K extends {}, V extends {}>(options: LRUCache.Options<K, V, any>): Cache<K, V> {
  const cache = new LRUCache(options);
  return {
    get: async (key) => cache.get(key),
    set: async (key, value, opts) => {
      cache.set(key, value, opts);
    },
  };
}

export default createService;
