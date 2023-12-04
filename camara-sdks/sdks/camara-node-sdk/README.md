# camara-node-sdk

Public SDK used by applications to operate with the OpenGateway platform.
Written in Node.js

# Usage for JWT Bearer Flow

```js
import Camara from 'camara-node-sdk';
import DeviceLocationVerificationClient from 'camara-node-sdk/clients/DeviceLocationVerificationClient';

// Autoconfigure the SDK with env vars
const camara: Camara = new Camara();
const deviceLocationVerificationClient = new DeviceLocationVerificationClient();

// Create a CAMARA Session using your client IP as identifier and some scopes
const session = await camara.session({ ipport: '127.0.0.1:3000', scope: 'scope1 scope2' });
// Call CAMARA APIs using the session
const params = { coordinates: { longitude: 3.8044, latitude: 42.3408 } };
const location = await deviceLocationVerificationClient.verify({ postcode: '28080' }, { session });

console.log(location);
```


# Usage for JWT Authorization Code Flow.

To execute the authorization flow you only need an event that enables your browser to perform a GET to:

```https://{your_service_host}:{your_service_port}/authcode/numver/flow?state={state}```

```js
import Camara from 'camara-node-sdk';
import NumberVerificationClient from 'camara-node-sdk/clients/NumberVerificationClient';
import type { AuthorizeParams, AuthorizeCallbackParams, AuthorizeSession } from 'camara-node-sdk/src/clients/AuthserverClient';
import type { TokenSet } from 'camara-node-sdk/src/clients/AuthserverClient';

const camara: Camara = new Camara();
const setup = camara.getSetup();
const deviceLocationVerificationClient = new DeviceLocationVerificationClient();

const { authserverClient } = setup;

const authorizeParams: AuthorizeParams = {
        scope: 'scope1 scope2',
        redirect_uri: 'https://{your_service_host}:{your_service_port}/authcode/callback',
      };
// The SDK calculates the url for doing redirect and the data you have to store in session system {calculated_session} in the next step.      
const { url, session } = await authserverClient.authorize(authorizeParams);


// Build the Callback Parameters
const params: AuthorizeCallbackParams = { code: code };
const state = req.session?.oauth?.state as string;
if (state) {
  params.state = state;
}
// Once yo receive the code in your callback or redirect_uri endpoint you can do the following:
const authorizeSession: AuthorizeSession = {calculated_session}
// We get the access_token and other information such as refresh_token, id_token, etc....
const tokenSet: TokenSet = await authserverClient.getAuthorizationCodeToken(params, authorizeSession);

// Now you have an access_token inside the TokenSet and you can consume a Camara API

// We set how are we going to retrieve our access_token. Prepared to use other system like cache or database.
const getToken = () => new Promise<string>((resolve) => {
    resolve(tokenSet.access_token as string);
});
//We consume the number verification API
const params = { coordinates: { longitude: 3.8044, latitude: 42.3408 } };
const result = await deviceLocationVerificationClient.verify(params, {
    getToken
});

```

# Get JWKS information

```js
import Camara from 'camara-node-sdk';

const camara: Camara = new Camara();

const data = await camara.jwks());
```
