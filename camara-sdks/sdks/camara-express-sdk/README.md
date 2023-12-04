# camara-express-sdk

Public SDK used by applications to operate with the OpenGateway platform.
Written in Node.js for Express JS Framework and Authorization Code Flow. Take into account that this SDK depends on ```camara-node-sdk```

# Usage for JWT Authorization Code Flow. Express JS 

To execute the authorization flow you only need an event that enables your browser to perform a GET to:

```http://{your_service_host}:{your_service_port}/authcode/numver/flow?state={state}```

```js
import Camara from 'camara-node-sdk';
import NumberVerificationClient from 'camara-node-sdk/clients/NumberVerificationClient';
import CamaraExpress from 'camara-express-sdk/src';

const camara = new Camara();
const numberVerificationClient = new NumberVerificationClient();
const camaraPassportNumVerification = CamaraExpress.passport({
  redirect_uri: `${process.env.HOST}/authcode/numver/callback`,
  fixed_scope: "openid number-verification-verify-hashed-read"
}, camara);

/**
 * Authcode Section - Number Verification API. Scope openid number-verification-verify-hashed-read.
 */
/**
 * Calculate authorize url and redirect to it in order to retrive a Oauth2 code.
 */

app.get('/authcode/numver/flow', camaraPassportNumVerification.authorize);


/**
 * Get an access_token by using a code and perform the API call. Callback url must be configured in the application redirect_uri.
 */
app.get('/authcode/numver/callback', camaraPassportNumVerification.callback, async (req, res, next) => {
  try {
    // We set how are we going to retrieve our access_token. Prepared to use other system like cache or database.
    const getToken = () => new Promise<string>((resolve) => {
      resolve(res.locals.token as string);
    });
    //We consume the number verification API
    const result = await numberVerificationClient.verify(
      { 
        hashed_phone_number: createHash('sha256').update(req.session.phonenumber).digest('hex')
      },{
        getToken,
      });
    
    // We render the view with the API result.
    return res.render('pages/verify', { 
      phonenumber: req.session.phonenumber,
      result: JSON.stringify(result, null, 4),
      state: uuid(),
      clientIp: getIpAddress(req)
    });
  } catch(err) {
    next(err);
  }
});
/**
 * End Authcode Section - Number Verification API.
 */

```


# Expose JWKS Endpoint

```js
import Camara from 'camara-node-sdk';

const camara: Camara = new Camara();

app.get('/jwks', async (req, res, next) => {
  try {
    res.json(await camara.jwks());
  } catch (err) {
    next(err);
  }
});
```
