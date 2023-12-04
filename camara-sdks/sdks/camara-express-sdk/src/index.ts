import type { Passport } from './lib/passport';
import { passport } from './lib/passport';

interface CamaraExpress {
  passport: Passport;
}

const CamaraExpress: CamaraExpress = {
  passport,
};

export default CamaraExpress;
