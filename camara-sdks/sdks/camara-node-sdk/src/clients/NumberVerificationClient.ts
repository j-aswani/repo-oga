import type { CamaraClientConfig, CamaraRequestContext } from './CamaraClient';
import CamaraClient from './CamaraClient';

export interface VerifyResponse {
  /**
   * Verification request result:
   *
   * - match when the phone is the same as the token has
   * - not_match when the phone is not the same as the token has
   */
  device_phone_number_verified: 'match' | 'not_match';

}

export interface VerifyParams {
  /** SHA-256 hash of the clients's Phone number */
  hashed_phone_number: string;
}

/**
 * Service Enabling Network Function API for number verification
 */
export default class NumberVerificationClient extends CamaraClient {
  constructor(configuration?: CamaraClientConfig) {
    super({
      pathname: '/number-verification-rc/v1',
      ...configuration,
    });
  }

  /**
   * Execute number verification for a user equipment
   */
  async verify(params: VerifyParams, context?: CamaraRequestContext): Promise<VerifyResponse> {
    const { data } = await this.client.post<VerifyResponse>('/verify-hashed', params, context);
    return data;
  }
}
