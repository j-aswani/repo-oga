import express from 'express';
import { v4 as uuid } from 'uuid';
import { createHash } from 'node:crypto'
import type DeviceLocationVerificationClient from 'camara-node-sdk/src/clients/DeviceLocationVerificationClient';
import getIpAddress from '../utils/getIpAddress';
import type NumberVerificationClient from 'camara-node-sdk/src/clients/NumberVerificationClient';
import type { Router } from 'express';
import CamaraExpress from 'camara-express-sdk/src';
import type Camara from 'camara-node-sdk/src';

const AuthCodeRoutes = (camara: Camara, deviceLocationVerificationClient: DeviceLocationVerificationClient, numberVerificationClient: NumberVerificationClient): Router => {
    const router = express.Router();
    const camaraPassportDevLocation = CamaraExpress.passport({
        redirect_uri: `${process.env.HOST}/authcode/devloc/callback`,
        scope: "device-location-verification-verify-read"
    }, camara);
    const camaraPassportNumVerification = CamaraExpress.passport({
        redirect_uri: `${process.env.HOST}/authcode/numver/callback`,
        scope: "openid number-verification-verify-hashed-read"
    }, camara);

    /**
    * Authcode Section - Number Verification API. Scope openid number-verification-verify-hashed-read.
    */
    /**
     * Calculate authorize url and redirect to it in order to retrive a Oauth2 code.
     */

    router.get('/numver/flow', camaraPassportNumVerification.authorize);


    /**
     * Get an access_token by using a code and perform the API call. Callback url must be configured in the application redirect_uri.
     */
    router.get('/numver/callback', camaraPassportNumVerification.callback, async (req, res, next) => {

        if (!req.session?.login || !req.session?.login?.phonenumber) {
            console.log("No phone number found. Performing logout");
            return res.redirect("/logout");
        }
        const phonenumber = req.session?.login?.phonenumber;

        try {
            // We set how are we going to retrieve our access_token. Prepared to use other system like cache or database.
            const getToken = () => new Promise<string>((resolve) => {
                resolve(res.locals.token as string);
            });
            //We consume the number verification API
            const result = await numberVerificationClient.verify(
                {
                    hashed_phone_number: createHash('sha256').update(phonenumber).digest('hex')
                }, {
                getToken,
            });

            // We render the view with the API result.
            return res.render('pages/verify', {
                phonenumber,
                result: JSON.stringify(result, null, 4),
                state: uuid(),
                clientIp: getIpAddress(req),
                error: false
            });
        } catch (err) {
            next(err);
        }
    }, (err: any, req: any, res: any, next: any) => {
        // Handle error
        delete req.session.login;
        if (err.error) {
            return res.render('pages/login', {
                clientIp: getIpAddress(req),
                error: err
            });
        }
        return next(err);
    });
    /**
     * End Authcode Section - Number Verification API.
     */

    /**
     * Authcode Section - Device Location Verification API. Scope device-location-verification-verify-read.
     */
    /**
     * Calculate authorize url and redirect to it in order to retrive a Oauth2 code.
     */

    router.get('/devloc/flow', camaraPassportDevLocation.authorize);


    /**
     * Get an access_token by using a code and perform the API call. Callback url must be configured in the application redirect_uri.
     */
    router.get('/devloc/callback', camaraPassportDevLocation.callback, async (req, res, next) => {
        if (!req.session?.login || !req.session?.login?.phonenumber) {
            console.log("No phone number found. Performing logout");
            return res.redirect("/logout");
        }
        const phonenumber = req.session?.login?.phonenumber;

        try {
            // We set how are we going to retrieve our access_token. Prepared to use other system like cache or database.
            const getToken = () => new Promise<string>((resolve) => {
                resolve(res.locals.token as string);
            });
            //We consume the number verification API
            const params = { coordinates: { longitude: 3.8044, latitude: 42.3408 } };
            const result = await deviceLocationVerificationClient.verify(params, {
                getToken
            });

            // We render the view with the API result.
            return res.render('pages/verify', {
                phonenumber,
                result: JSON.stringify(result, null, 4),
                state: uuid(),
                clientIp: getIpAddress(req),
                error: false
            });
        } catch (err) {
            next(err);
        }
    }, (err: any, req: any, res: any, next: any) => {
        // Handle error
        const phonenumber = req.session?.login?.phonenumber;
        if (err.error) {
            return res.render('pages/verify', {
                phonenumber,
                result: JSON.stringify(err, null, 4),
                state: uuid(),
                clientIp: getIpAddress(req),
                error: true
            });
        }
        return next(err);
    });
    /**
     * End Authcode Section -  Device Location Verification API.
     */

    return router;
};

export default AuthCodeRoutes;
