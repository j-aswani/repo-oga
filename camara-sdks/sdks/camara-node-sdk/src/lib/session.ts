import type { CamaraRequestContext } from '../clients/CamaraClient';
import type { CamaraTokenSet } from '../services/tokens';
import { login } from '../lib/login';

/**
 * Session for the Camara SDK
 */
export interface CamaraSession {
  access_token: string;
  expires_at: number;
  // This should not be needed if we use refresh tokens
  login: {
    ipport?: string;
    scope?: string;
    setupId: string;
  };
}

export interface SessionService {
  createSession: (args: {
    camaraTokenSet: CamaraTokenSet;
    login: { ipport?: string; scope?: string; setupId: string };
  }) => Promise<CamaraSession>;
  restoreSession: (args: CamaraSession, context?: CamaraRequestContext) => Promise<CamaraSession>;
}

export const createSession: SessionService['createSession'] = async ({ login, camaraTokenSet }) => {
  const session: CamaraSession = {
    login,
    access_token: camaraTokenSet.access_token,
    expires_at: camaraTokenSet.expires_at,
  };
  return session;
};

export const restoreSession: SessionService['restoreSession'] = async (session, context) => {
  const {
    login: { setupId, ipport, scope },
    expires_at,
  } = session;

  if (!setupId || !ipport) {
    throw new Error('Missing login information in session');
  }

  const now = Date.now();
  const isExpired = expires_at < now;
  // TODO: We may use a refresh token here (if available)
  if (isExpired) {
    session = await login({ ipport, scope }, { ...context, setupId });
  }

  return session;
};
