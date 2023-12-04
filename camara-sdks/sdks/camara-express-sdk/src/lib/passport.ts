import type { BaseRequestContext } from 'camara-node-sdk/src/clients/BaseClient';
import type { CamaraSetupId } from 'camara-node-sdk/src/lib/setup';
import { defaultSetupId } from 'camara-node-sdk/src/lib/setup';
import type { AuthorizeParams, AuthorizeCallbackParams, AuthorizeSession } from 'camara-node-sdk/src/clients/AuthserverClient';
import type { TokenSet } from 'camara-node-sdk/src/clients/AuthserverClient';
import type Camara from 'sdks/camara-node-sdk/src';

export interface PassportContext extends BaseRequestContext {
  /** the setup id containing sdk configuration to use. Defaults to 'default' */
  setupId?: CamaraSetupId;
}

export type Passport = (
  { redirect_uri, scope }: { redirect_uri: string, scope?: string },
  camara: Camara
) => { authorize: any, callback: any}


const retrieveParametersFromRequest = (req: any) => {
  const state: string = (req.query.state ?? '') as string;
  const scope: string = req.session?.scope as string;
  let error = '';
  return {
    state,
    scope,
    error
  }
};

export const passport: Passport = ({ redirect_uri, scope }, camara ) => {

  const setupId  = camara.camaraSetupId || defaultSetupId;
  const setup = camara.getSetup(setupId);
  const { authserverClient } = setup;


  const authorize =  async function (req: any, res: any, next: any) {
    const {scope: parameterScope, state, error } = retrieveParametersFromRequest(req);

    if (error) {
      console.log(error);
      return res.redirect('/logout');
    }

    try {
      // Set the right scopes, redirect_uri and state to perform the flow.
      const authorizeParams: AuthorizeParams = {
        scope: '',
        redirect_uri,
      };
      if (state) {
        authorizeParams.state = state;
      }
      if (parameterScope) {
        authorizeParams.scope = parameterScope;
      }

      if (scope) {
        authorizeParams.scope = scope;
      }

      // Retrieve the authorized url and the session data.
      const { url, session } = await authserverClient.authorize(authorizeParams);
      // Store the session data in the cookie session
      if (req.session) req.session.oauth = session;

      // Redirect to the Authorize Endpoint.
      return res.redirect(url);

    } catch (err) {
      next(err);
    }
  };

  const callback = async function (req: any, res: any, next: any) {
  try {

    // Get code value to request an access token.
    const code = req.query.code as string;
    if (!code) {
      if (req.query?.error) {
        return next(
          {
            error: req.query.error,
            error_description: req.query.error_description
          }
        );
      }
      console.warn('Code not found. Please, complete the flow again.');
      return res.redirect('/logout');
    }


    // Build the Callback Parameters
    const params: AuthorizeCallbackParams = { code: code };
    const state = req.session?.oauth?.state as string;
    if (state) {
      params.state = state;
    }

    // Recover the Authorized sessión from the previous step.
    const authorizeSession: AuthorizeSession = req.session?.oauth;

    // We get the access_token and other information such as refresh_token, id_token, etc....
    const tokenSet: TokenSet = await authserverClient.getAuthorizationCodeToken(params, authorizeSession);

    // We store the token in the request context for future uses
    res.locals = {
      token: tokenSet.access_token
    };
    if (req.session) {
      delete req.session.oauth;
    }
    next();
  } catch(err) {
    next(err);
  }
  };

  return {
    authorize,
    callback
  }
};
