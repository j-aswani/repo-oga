import type { BaseRequestContext } from './BaseClient';
import BaseClient from './BaseClient';
import { v4 as uuid } from 'uuid';
import jose from 'node-jose';
import memoize from 'memoizee';

/** Supported grant_types */
type GrantType = 'client_credentials' | 'authorization_code' | 'urn:ietf:params:oauth:grant-type:jwt-bearer';

/** Supported AuthMethods to get tokens */
type AuthMethod = 'client_secret_basic' | 'private_key_jwt';

/** Supported algoritms for signing */
type Alg = 'RS256';

/** Specifies whether the Authorization Server prompts the End-User for reauthentication and consent */
type PromptValue = 'none' | 'login' | 'consent' | 'select_account';

type Prompt =
  | `${PromptValue}`
  | `${PromptValue} ${PromptValue}`
  | `${PromptValue} ${PromptValue} ${PromptValue}`
  | `${PromptValue} ${PromptValue} ${PromptValue} ${PromptValue}`;

/**
 * Simplified OpenID configuration as defined in
 * https://openid.net/specs/openid-connect-discovery-1_0.html
 */
export interface OpenIDInfo {
  /**
   * URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.
   * If Issuer discovery is supported, this value MUST be identical to the issuer value returned by WebFinger.
   * This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
   */
  issuer: string;
  /**
   * URL of the OP's OAuth 2.0 Authorization Endpoint
   */
  authorization_endpoint: string;
  /**
   * URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate
   * signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s),
   * which are used by RPs to encrypt requests to the Server.
   * When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED
   * for all keys in the referenced JWK Set to indicate each key's intended usage.
   * Although some algorithms allow the same key to be used for both signatures and encryption,
   * doing so is NOT RECOMMENDED, as it is less secure.
   * The JWK x5c parameter MAY be used to provide X.509 representations of keys provided.
   * When used, the bare key values MUST still be present and MUST match those in the certificate.
   */
  jwks_uri: string;
  /**
   * URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core].
   * This is REQUIRED unless only the Implicit Flow is used.
   */
  token_endpoint: string;
  /**
   * JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
   * Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values
   * and MAY support other Grant Types. If omitted, the default value is ["authorization_code", "implicit"].
   */
  grant_types_supported?: GrantType[];
  /**
   * JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
   * The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt,
   * as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core].
   * Other authentication methods MAY be defined by extensions.
   * If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified
   * in Section 2.3.1 of OAuth 2.0 [RFC6749].
   */
  token_endpoint_auth_methods_supported?: AuthMethod[];
  /**
   * JSON array containing a list of the JWS signing algorithms (alg values) supported by the
   * Token Endpoint for the signature on the JWT [JWT] used to authenticate the Client at the
   * Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods.
   * Servers SHOULD support RS256. The value none MUST NOT be used.
   */
  token_endpoint_auth_signing_alg_values_supported?: Alg[];
}

/** the result set of asking for a token */
export interface TokenSet {
  /** the token you will use to consume the APIs */
  access_token: string;
  /** how much time the token expires in seconds (3599 seconds, which means 1 hour). */
  expires_in: number;
  /**
   * an IDToken. You will only get this field if you have sent
   * the value openid within the scope parameter of the initial request
   */
  id_token?: string;
  /**
   * this is the token you can use to refresh the session and get a
   * new  access_token without having to log the user in again. You will
   * only get this field if you have sent, and are allowed to request,
   * the value offline_access within the scope parameter of the initial
   * redirection.
   */
  refresh_token?: string;
  /** The token type. Always is Bearer */
  token_type: string;
  scope?: string;
}

/**
 * In order to issue an access token response as described in OAuth 2.0
 * [RFC6749] or to rely on a JWT for client authentication, the
 * authorization server MUST validate the JWT according to the criteria
 * below.
 */
interface JWT extends Record<string, any> {
  /**
   * Subject claim identifying the principal that is the subject of the JWT.
   * Two cases need to be  differentiated:
   * - For the authorization grant, the subject typically identifies an authorized accessor for which the access token
   *   is being requested (i.e., the resource owner or an authorized delegate), but in some cases, may be a
   *   pseudonymous identifier or other value denoting an anonymous user.
   * - For client authentication, the subject MUST be the "client_id" of the OAuth client.
   */
  sub: string;
  /**
   * Issuer Identifier for the Issuer. The iss value is a case sensitive
   * URL using the https scheme that contains scheme, host, and optionally, port number
   * and path components and no query or fragment components.
   */
  iss: string;
  /**
   * audience claim containing a value that identifies the authorization server as an intended
   * audience.  The token endpoint URL of the authorization server MAY be used as a value for an "aud" element to identify the
   * authorization server as an intended audience of the JWT
   */
  aud: string;
  /**
   * this refer to the expiration of the token you provided to make the call,
   * but it is no the expiration of the access session. Remember that, in some cases,
   * you can extend validity by refreshing the session.
   *
   * JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time
   */
  exp: number;
  /**
   * Time at which the JWT was issued. Its value is a JSON number representing the
   * number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
   */
  iat?: number;
  /**
   * JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token.
   */
  jti?: string;
}

/**
 * /authorize endpoint parameters
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 */
export interface AuthorizeParams {
  /**
   * list of scopes your app wants to request authorization for
   * These scopes must be the same (or a subset of the ones) requested when the app was created.
   * If you omit this parameter, the access_token will be issued for all the scopes declared when
   * the app was created.
   */
  scope: string;
  /**
   * Should be the HTTP endpoint on your server that will receive the response from 4th platform.
   * The value must exactly match one of the authorized redirect URIs for the OAuth 2.0 client,
   * which you configured during app registration within the 4th Platform.
   * If this value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch' error.
   */
  redirect_uri: string;
  /**
   * Must include the value of the anti-forgery unique session token,
   * as well as optionally any other information needed to recover the context when the user returns to
   * your application, e.g., the starting URL.
   * If nothing is provided, one random is autogenerated
   *
   * State is there to protect the end user from cross site request forgery(CSRF) attacks.
   * oauth protocol states that once authorization has been obtained from the end-user, the
   * authorization server redirects the end-user's user-agent back to the client with the
   * required binding value contained in the "state" parameter. The binding value enables
   * the client to verify the validity of the request by matching the binding value to the
   * user-agent's authenticated state
   */
  state?: string;
  /** can be the user's email address or the sub string, which is equivalent to the user's ID */
  login_hint?: string;
  /** specifies whether the Authorization Server prompts the End-User for reauthentication and consent
   * - 'none':
   *   The Authorization Server will not display any authentication or consent user interface pages.
   *   An error is returned if an End-User is not already authenticated or the Client does not have
   *   pre-configured consent for the requested Claims or does not fulfill other conditions for
   *   processing the request. The error code will typically be login_required, interaction_required,
   *   or another code defined in Section 3.1.2.6.
   *   This can be used as a method to check for existing authentication and/or consent.
   * - 'login'
   *   The Authorization Server will prompt the End-User for reauthentication. If it cannot
   *   reauthenticate the End-User, it will return an error, typically login_required.
   */
  prompt?: Prompt;
  /**
   * Requested Authentication Context Class Reference values.
   * Specifies the acr values that the Authorization Server is being requested to use for processing
   * this Authentication Request, with the values appearing in order of preference. The Authentication
   * Context Class satisfied by the authentication performed is returned as the acr Claim Value.
   * The acr Claim is requested as a Voluntary Claim by this parameter.
   */
  acr_values?: string;
  /**
   * select what fields should be returned in the userinfo or id_token
   */
  claims?: object;

  nonce?: string;
}

/**
 * Session object you should save and read using your session manager
 */
export interface AuthorizeSession {
  /** oauth redirect_uri used for the auth code flow */
  redirect_uri: string;
  /** oauth state checked for CSRF protection */
  state: string;
  /**
   * It binds the tokens with the client. It serves as a token validation parameter
   * and is only returned and managed when the scope `openid` is requested in the
   * `client.authorize` method
   */
  nonce?: string;
}

export interface Authorize {
  /** the url the browser should be redirected to */
  url: string;
  /**
   * The session you must save using your session manager, and pass back to the
   * `client.grantCode` method for managing the oauth callback
   */
  session: AuthorizeSession;
}

type AuthorizeRequest = Record<string, string | undefined> &
  Pick<AuthorizeParams, 'redirect_uri' | 'nonce' | 'state' | 'login_hint' | 'prompt' | 'scope' | 'acr_values'> & {
    client_id: string;
    response_type: 'code';
    claims?: string;
  };

export interface AuthorizeCallbackParams {
  error?: string;
  error_description?: string;
  state?: string;
  code?: string;
}

/**
 * options for getting a client_credentials token
 */
export interface GetClientCredentialsTokenParams {
  scope?: string;
}
export interface GetJWTBearerTokenParams {
  /** the user identifier for this access session */
  sub: string;
  scope?: string;
}

interface InternalGetJWTBearerTokenParams {
  grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer';
  assertion: string;
}
interface InternalGetClientCredentialsTokenParams extends GetClientCredentialsTokenParams {
  grant_type: 'client_credentials';
  scope?: string;
}
interface InternalGetAuthorizationCodeTokenParams {
  grant_type: 'authorization_code';
  code: string;
  redirect_uri: string;
}
/** params sent to the /token endpoint */
type GetTokenParams =
  | InternalGetClientCredentialsTokenParams
  | InternalGetAuthorizationCodeTokenParams
  | InternalGetJWTBearerTokenParams;

/**
 * options for the authserver client
 */
export interface AuthserverClientConfig {
  /** the baseURL for the server. Defaults to CAMARA_AUTHSERVER_URL env var */
  baseURL?: string;
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
}

export interface AuthserverRequestContext extends BaseRequestContext {}

const CACHE_TIMEOUT = 10 * 60 * 1000; // 10min

/**
 * Client for communication with an authserver
 */
export default class AuthserverClient extends BaseClient {
  protected configuration: AuthserverClientConfig;

  constructor(configuration: AuthserverClientConfig = {}) {
    const config: AuthserverClientConfig = {
      ...configuration,
      baseURL: configuration.baseURL || process.env.CAMARA_AUTH_URL,
      clientId: configuration.clientId || process.env.CAMARA_CLIENT_ID,
      clientSecret: configuration.clientSecret || process.env.CAMARA_CLIENT_SECRET,
      issuer: configuration.issuer || process.env.CAMARA_ISSUER,
      clientKey: configuration.clientKey || process.env.CAMARA_CLIENT_KEY,
    };
    super(config);
    this.configuration = config;

    // memoize not-meant-to-be-changed data functions
    // we use length: 0 because the request config is optional and gives context to each request
    this.getOpenIDInfo = memoize(this.getOpenIDInfo.bind(this), { maxAge: CACHE_TIMEOUT, promise: true, length: 0 });
    this.getIssuerKeyStore = memoize(this.getIssuerKeyStore.bind(this), {
      maxAge: CACHE_TIMEOUT,
      promise: true,
      length: 0,
    });
    this.getKeyStore = memoize(this.getKeyStore.bind(this), { promise: true });
  }

  /**
   * Gets the OpenID info for the server from the well-known endpoint
   */
  async getOpenIDInfo(context?: AuthserverRequestContext): Promise<OpenIDInfo> {
    const { data } = await this.client.get<OpenIDInfo>('/.well-known/openid-configuration', context);
    return data;
  }

  /**
   * Verifies the jwt issued by the server and returns the payload it contains
   */
  public async verify<T = any>(jwt: string, context?: AuthserverRequestContext): Promise<T> {
    const keystore = await this.getIssuerKeyStore(context);
    const { payload } = await jose.JWS.createVerify(keystore).verify(jwt);
    return JSON.parse(payload.toString());
  }

  /**
   * Gets a client_credentials access token
   */
  public async getClientCredentialsToken(
    { scope }: GetClientCredentialsTokenParams = {},
    context?: AuthserverRequestContext
  ): Promise<TokenSet> {
    const grant_type: GrantType = 'client_credentials';
    return this.getToken({ grant_type, scope }, context);
  }

  /**
   * Gets an access token using the jwt-bearer code flow
   */
  public async getJWTBearerToken(
    params: GetJWTBearerTokenParams,
    context?: AuthserverRequestContext
  ): Promise<TokenSet> {
    const grant_type: GrantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    const assertion = await this.createJWT({ ...params }, context);
    return this.getToken({ grant_type, assertion }, context);
  }

  /**
   * Authorization Code Flow 1st step
   *
   * Creates the URL needed for redirecting the browser, and the session
   * that MUST be saved in order to verify at the second step in the
   * `client.getAuthorizationCodeToken` method.
   *  It's recommened that you save the session in a `secure` `httpOnly` cookie
   *
   * It's hightly recommended that a `state` param is provided. The primary
   * reason for using the state parameter is to mitigate CSRF attacks.
   */
  public async authorize(params: AuthorizeParams, context?: AuthserverRequestContext): Promise<Authorize> {
    try {
      const { authorization_endpoint } = await this.getOpenIDInfo(context);

      if (!this.configuration.clientId) {
        throw new Error('Missing client_id');
      }
      const url = new URL(authorization_endpoint);

      // as a sane default security mechanism, if the user has not provided
      // any state, we generate one
      const state = params.state || random();

      const requestParams: AuthorizeRequest = {
        ...params,
        claims: params.claims ? JSON.stringify(params.claims) : undefined,
        client_id: this.configuration.clientId,
        nonce: params.scope.includes('openid') ? random() : undefined,
        response_type: 'code',
        state,
      };

      // add query params to url, removing undefined values
      Object.entries(requestParams)
        .filter(([, value]) => value)
        .forEach(([key, value]) => url.searchParams.append(key, value!));

      const session: AuthorizeSession = {
        redirect_uri: requestParams.redirect_uri,
        state,
      };

      if (requestParams.nonce) {
        session.nonce = requestParams.nonce;
      }

      return {
        session,
        url: url.toString(),
      };
    } catch (cause) {
      // @ts-ignore
      throw new Error('Cannot create authorization url', { cause });
    }
  }

  /**
   * Authorization Code Flow 2nd step
   *
   * Gets the access_token (and optionally the id_token) for an authentication session
   * using authorization_code flow
   */
  public async getAuthorizationCodeToken(
    params: AuthorizeCallbackParams,
    session: AuthorizeSession,
    context?: AuthserverRequestContext
  ) {
    const { code, error, error_description, state } = params;

    if (error) {
      const message = getErrorMessageFromOAuth({ error, error_description });
      throw new Error(`Unable to authorize: ${message}`);
    }

    if (!session) {
      throw new Error(`Session is mandatory`);
    }

    if (!code) {
      throw new Error(`code missing`);
    }

    const { state: sessionState, nonce, redirect_uri } = session;

    if (state !== sessionState) {
      throw new Error('State mismatch');
    }

    const grant_type: GrantType = 'authorization_code';

    const tokenSet = await this.getToken(
      {
        code,
        redirect_uri,
        grant_type,
      },
      context
    );

    if (tokenSet.id_token) {
      // TODO: More verifications here!
      const claims = await this.verify(tokenSet.id_token, context);

      if (nonce !== claims.nonce) {
        throw new Error('Invalid nonce');
      }
      // TODO: set id_token_claims in tokenSet
    }

    return tokenSet;
  }
  /**
   * export the public keys of a keystore as a JWK-set
   */
  public async jwks(): Promise<object> {
    const keyStore = await this.getKeyStore();
    return keyStore.toJSON();
  }

  /**
   * Executes a /token endpoint request
   */
  private async getToken(params: GetTokenParams, context?: AuthserverRequestContext): Promise<TokenSet> {
    const { grant_type } = params;
    const {
      token_endpoint,
      grant_types_supported = ['authorization_code'],
      token_endpoint_auth_methods_supported = ['client_secret_basic'],
    } = await this.getOpenIDInfo(context);

    if (!grant_types_supported.find((grant) => grant === grant_type)) {
      throw new Error(`OpenIDProvider does not support the "${grant_type}" grant_type`);
    }

    // Select the best auth_method to use
    // TODO: let the user select the auth_method
    let auth_method: AuthMethod;
    if (
      this.configuration.clientId &&
      this.configuration.clientKey &&
      token_endpoint_auth_methods_supported.find((method) => method === 'private_key_jwt')
    ) {
      auth_method = 'private_key_jwt';
    } else if (
      this.configuration.clientId &&
      this.configuration.clientSecret &&
      token_endpoint_auth_methods_supported.find((method) => method === 'client_secret_basic')
    ) {
      auth_method = 'client_secret_basic';
    } else {
      throw new Error('No valid auth_method found to use against the token endpoint');
    }

    if (auth_method === 'client_secret_basic') {
      const { data } = await this.client.post<TokenSet>(token_endpoint, new URLSearchParams({ ...params }), {
        ...context,
        headers: { ...context?.headers, 'content-type': 'application/x-www-form-urlencoded' },
        auth: {
          password: this.configuration.clientSecret!,
          username: this.configuration.clientId,
        },
      });
      return data;
    } else if (auth_method === 'private_key_jwt') {
      const { data } = await this.client.post<TokenSet>(
        token_endpoint,
        new URLSearchParams({
          ...params,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: await this.createJWT(
            {
              sub: this.configuration.clientId,
              iss: this.configuration.clientId,
            },
            context
          ),
        }),
        { ...context, headers: { ...context?.headers, 'content-type': 'application/x-www-form-urlencoded' } }
      );
      return data;
    } else {
      throw new Error(`Unsupported auth_method "${auth_method}"`);
    }
  }

  /**
   * Creates a JWT signed with the client key for the server
   */
  private async createJWT(payload: Partial<JWT> & { sub: string }, context?: AuthserverRequestContext) {
    if (!payload.iss && !this.configuration.issuer) {
      throw new Error('create JWT requires issuer to be set');
    }

    const { issuer: serverIssuer } = await this.getOpenIDInfo(context);
    const key = await this.getSigningKey(context);

    const now = Math.floor(Date.now() / 1000);
    const jwtPayload: JWT = {
      ...payload,
      aud: payload.aud ?? serverIssuer,
      iss: (payload.iss ?? this.configuration.issuer)!,
      jti: payload.jti ?? uuid(),
      exp: payload.exp ?? now + 60,
      iat: payload.iat ?? now,
    };
    try {
      const jwt = await jose.JWS.createSign({ format: 'compact' }, key)
        .update(JSON.stringify(jwtPayload), 'utf-8')
        .final();
      return jwt as unknown as string;
    } catch (cause) {
      // @ts-ignore
      throw new Error('Unable to sign JWT', { cause });
    }
  }

  /**
   * Gets a suitable key to sign the assertion.
   */
  private async getSigningKey(context?: AuthserverRequestContext) {
    const { token_endpoint_auth_signing_alg_values_supported: algs = [] } = await this.getOpenIDInfo(context);
    const keystore = await this.getKeyStore();

    // keystore does not support searching in arrays. Do it manually
    const keys = algs.flatMap((alg) => keystore.all({ alg }));
    if (!keys.length) {
      throw new Error(`Not suitable key is available for server algoritmhs "${algs}"`);
    }
    // return the first key that matches
    return keys[0];
  }

  /**
   * Gets the server KeyStore to verify tokens emmited by this server
   */
  private async getIssuerKeyStore(context?: AuthserverRequestContext): Promise<jose.JWK.KeyStore> {
    const { jwks_uri } = await this.getOpenIDInfo(context);
    const { data } = await this.client.get(jwks_uri, context);
    return jose.JWK.asKeyStore(data);
  }

  /**
   * Gets the KeyStore to sign requests against the server
   */
  private async getKeyStore(): Promise<jose.JWK.KeyStore> {
    const { clientKey } = this.configuration;
    const keystore = jose.JWK.createKeyStore();
    if (clientKey) {
      // decode base64 encoded key
      const decodedKey = Buffer.from(clientKey, 'base64').toString('utf8');
      await keystore.add(decodedKey, 'pem');
    }
    return keystore;
  }
}

/** generates a random 32 urlencoded string compatible with WAF services */
function random() {
  return uuid().replace(/-/g, '');
}

function getErrorMessageFromOAuth({ error_description, error }: { error_description?: string; error?: string }) {
  return error_description ? error_description : error ? error : 'OAuthError';
}
