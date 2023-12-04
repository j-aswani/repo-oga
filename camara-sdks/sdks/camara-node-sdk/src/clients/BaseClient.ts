import type { AxiosInstance, AxiosRequestConfig, AxiosResponse, InternalAxiosRequestConfig } from 'axios';
import type { AgentOptions } from 'http';
import axios from 'axios';
import { Agent as HTTPAgent } from 'http';
import { Agent as HTTPSAgent } from 'https';

const options: AgentOptions = { keepAlive: true };
export const httpAgent = new HTTPAgent(options);
export const httpsAgent = new HTTPSAgent(options);

/**
 * options for the Base client
 */
export interface BaseClientConfig {
  /** the server URL name where the api is located. Ex: https://api.example.com. Defaults to '/' */
  baseURL?: string;
  /** the connection timeout for the requests. Defaults to 0 (none) */
  timeout?: number;
  headers?: any;
}

export interface BaseRequestContext {
  headers?: Record<string, string>;
  timeout?: number;
}

/**
 * Base implementation for a SDK Client
 */
export default abstract class BaseClient {
  client: AxiosInstance;

  constructor(configuration?: BaseClientConfig) {
    const clientConfig: AxiosRequestConfig = {
      httpAgent,
      httpsAgent,
      ...configuration,
      timeout: configuration?.timeout ?? Number(process.env.CAMARA_REQUEST_TIMEOUT || 0),
      headers: {
        ...configuration?.headers,
        'User-Agent': `Camara NodeJS SDK`, // TODO: set the sdk version here
      },
    };

    this.client = axios.create(clientConfig);
    this.client.interceptors.request.use(logRequest);
    this.client.interceptors.response.use(logResponse);
  }
}

function logRequest(config: InternalAxiosRequestConfig) {
  console.log(`--> ${config.method?.toUpperCase()} ${getURLInRequest(config)}`);
  return config;
}

function logResponse(res: AxiosResponse) {
  console.log(
    `<-- ${res.status} ${res.statusText} (${res?.config?.method?.toUpperCase()} ${getURLInRequest(res.config)})`
  );
  return res;
}

function getURLInRequest(config: InternalAxiosRequestConfig) {
  if (config.url?.startsWith('http')) {
    return config.url;
  }
  return `${config.baseURL}${config.url}`;
}
