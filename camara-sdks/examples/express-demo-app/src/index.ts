import express from 'express';
import cookieSession from 'cookie-session';
import { v4 as uuid } from 'uuid';
import * as path from 'path';


import Camara from 'camara-node-sdk/src';
import DeviceLocationVerificationClient from 'camara-node-sdk/src/clients/DeviceLocationVerificationClient';
import NumberVerificationClient from 'camara-node-sdk/src/clients/NumberVerificationClient';
import {fileURLToPath} from 'url';
import getIpAddress from './utils/getIpAddress';

import JWTbearerRoutes from './routes/jwtbearer';
import AuthCodeRoutes from './routes/authcode';
import ApiRoutes from './routes/api';

/////////////////////////////////////////////////
// Initialize the SDK offering networking services (device location verification in the example)
// When the aggregator is an hyperscaler, this could be its own SDK (e.g., Azure SDK)
/////////////////////////////////////////////////
const camara: Camara = new Camara();
const deviceLocationVerificationClient = new DeviceLocationVerificationClient();
const numberVerificationClient = new NumberVerificationClient();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.enable('trust proxy');
app.use(cookieSession({ keys: ['secret'] }));
app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }))

app.use(express.json())

app.use('/jwtbearer', JWTbearerRoutes(camara, deviceLocationVerificationClient));

app.use('/authcode', AuthCodeRoutes(camara, deviceLocationVerificationClient, numberVerificationClient))

app.use('/api', ApiRoutes(camara))

app.get('/', (req, res) => {
  console.log('Client IP Address: ' + getIpAddress(req));
  const userLogged = req.session?.login?.phonenumber;
  if (userLogged) {
    res.render('pages/verify', { phonenumber: req.session?.login?.phonenumber, result:'', state: uuid(), clientIp: getIpAddress(req), error: false });
  } else {
    res.render('pages/login', { clientIp: getIpAddress(req), error: false});
  }
});

app.post('/login', (req, res) => {
  let body = req.body
  console.log(JSON.stringify(body))
  req.session = req.session || {}
  req.session.login = {
    phonenumber: body.phonenumber || "+3462534724337623",
  }
  res.redirect('/authcode/numver/flow?state=' + uuid())
});

app.get('/auth/verify', async (req, res, next) => {
  
  if (!req.session) {
    console.warn('Not valid session. Doing logout')
    return res.redirect('/logout');
  }
  delete req.session?.login.token;
  delete req.session?.camara;
  return res.redirect('/authcode/devloc/flow?state=' + uuid())
});

app.get('/logout', (req, res) => {
  if (req.session) {
    delete req.session.login;
    delete req.session.camara;
  }
  res.redirect('/')
});



const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Demo App listening on http://localhost:${PORT}`);
});
