import type { BaseRequestContext } from '../clients/BaseClient';
import type { CamaraSetupId } from './setup';
import type { CamaraSession } from './session';
import { createSession } from './session';
import { defaultSetupId, getSetup } from './setup';

export interface LoginContext extends BaseRequestContext {
  /** the setup id containing sdk configuration to use. Defaults to 'default' */
  setupId?: CamaraSetupId;
}

export type Login = (
  { ipport, scope }: { ipport: string; scope?: string },
  context?: LoginContext
) => Promise<CamaraSession>;

export const login: Login = async ({ ipport, scope }, context = {}) => {
  const { setupId = defaultSetupId } = context;
  const sub = `ipport:${ipport}`;
  const setup = getSetup(setupId);
  const { tokenService } = setup;

  const camaraTokenSet = await tokenService.getLoginTokenSet({ sub, scope }, context);
  const session = await createSession({ camaraTokenSet, login: { ipport, scope, setupId } });
  return session;
};
