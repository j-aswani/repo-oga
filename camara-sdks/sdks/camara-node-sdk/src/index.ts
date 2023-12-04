import type { CamaraSetupId, CamaraSetup, CamaraConfig } from './lib/setup';
import type { Login } from './lib/login';
import { createSetup, getSetup} from './lib/setup';
import { login } from './lib/login';

export default class Camara {

  session: Login;
  camaraSetupId?: CamaraSetupId;

  constructor(config?: CamaraConfig, id?: CamaraSetupId) {
    createSetup(config, id);
    this.session = login;
    this.camaraSetupId = id;
  }

  setup(config?: CamaraConfig, id?: CamaraSetupId): CamaraSetup {
    return createSetup(config, id);
  }

  getSetup(id?: CamaraSetupId): CamaraSetup {
    return getSetup(id);
  }

  async jwks(setupId: CamaraSetupId = 'default') {
    const setup = getSetup(setupId);
    return setup.jwks();
  }

}
