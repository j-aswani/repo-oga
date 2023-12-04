import type { CamaraClientConfig, CamaraRequestContext } from './CamaraClient';
import CamaraClient from './CamaraClient';

export interface VerifyResponse {
  /**
   * Verification request result:
   *
   * - match when the Network locates the device within the requested area
   * - not_match when the requested area completely differs from the area where the Network locates the device
   * - partial_match when the requested area is partially included in the area where the Network locates the device but not entirely. In this case success_rate must be included in the response
   * - undetermined when the area included in the request body is smaller than the network capacities to locate the device.
   */
  verification_result: 'match' | 'not_match' | 'partial_match' | 'undetermined';
  /**
   * It will be returned when verification_result == partial_match and it indicates a percentage to represent the possibility
   * of success in locating the device in the given area. If for example there is a probability of 74%, success_rate will be 74
   */
  success_rate?: number;
}

export interface VerifyParams {
  /** Coordinates of a geographical location */
  coordinates?: {
    /** latitude coordinate of a geographical location expressed in decimal degrees. */
    latitude: number;
    /** longitude coordinate of a geographical location expressed in decimal degrees. */
    longitude: number;
    /** Filter to limit the returned venues to the ones that are located within the provided radius. It MUST be a positive value. Unit is km. */
    radius?: number;
  };
  /** Zip code or postal code of location */
  postcode?: string;
}

/**
 * Service Enabling Network Function API for device location verification
 */
export default class DeviceLocationVerificationClient extends CamaraClient {
  constructor(configuration?: CamaraClientConfig) {
    super({
      pathname: '/device-location-verification/v1',
      ...configuration,
    });
  }

  /**
   * Execute location verification for a user equipment
   */
  async verify(params: VerifyParams, context?: CamaraRequestContext): Promise<VerifyResponse> {
    const { data } = await this.client.post<VerifyResponse>('/verify', params, context);
    return data;
  }
}
