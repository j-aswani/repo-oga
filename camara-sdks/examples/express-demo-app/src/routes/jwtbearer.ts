import express from 'express';
import Camara from 'camara-node-sdk/src';
import { v4 as uuid } from 'uuid';
import type DeviceLocationVerificationClient from 'camara-node-sdk/src/clients/DeviceLocationVerificationClient';
import type { Router } from 'express';
import getIpAddress from '../utils/getIpAddress';

const JWTbearerRoutes = (camara: Camara, deviceLocationVerificationClient: DeviceLocationVerificationClient): Router => {
    const router = express.Router();
    /**
     * JWTbearer Section
     */
    router.get('/verify', async (req, res, next) => {
        console.log('jwtbearer device location verify', req.session);
        if (!req.session?.login?.phonenumber) {
            return res.redirect('/')
        }

        try {
            if (!req.session?.camara) {
                req.session = req.session || {};

                /**
                 * We perform the SDK session operation that internally gets an access token using
                 * the jwt bearer flow (3 legged token). We store the token in the session to reuse it.
                 *
                 * The user identifier is the ip:port but the model is generic to be extended
                 * with other identifiers (MSISDN, etc).
                 */
                req.session.camara = await camara.session({
                    ipport: req.query.ip as string
                });
            }

            /**
             * Once we have a token, we can consume a CAMARA API.
             */
            const params = { coordinates: { longitude: 3.8044, latitude: 42.3408 } };
            const location = await deviceLocationVerificationClient.verify(params, { session: req.session.camara });
            delete req.session.camara;
            res.render('pages/verify', {
                phonenumber: req.session?.login?.phonenumber,
                result: JSON.stringify(location, null, 4),
                state: uuid(),
                clientIp: getIpAddress(req),
                error: false
            });
        } catch (err: any) {
            return err.response?.data ? res.render('pages/verify', {
                phonenumber: req.session?.login?.phonenumber,
                result: JSON.stringify(err.response?.data, null, 4),
                state: uuid(),
                clientIp: getIpAddress(req),
                error: true
            }) : next(err);

        }
    });
    /**
     * End JWTbearer Section
     */

    return router;
};

export default JWTbearerRoutes;
