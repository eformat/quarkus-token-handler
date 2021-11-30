import cors from 'cors';
import express from 'express';
import fs from 'fs';
import https from 'https';
import {InMemoryCache, jwksService, secure} from 'express-oauth-jwt';
import {Configuration} from './configuration';

const buffer = fs.readFileSync('config.json');
const configuration = JSON.parse(buffer.toString()) as Configuration;

const app = express();
const auth = jwksService(new InMemoryCache(), configuration.jwksUrl, https as any);

// FIXME
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

// Grant access to the web origin and allow it to send the secure cookie
const corsOptions = { 
    origin: configuration.trustedWebOrigin,
    credentials: true,
};

app.set('etag', false);
app.use('/api/data', cors(corsOptions) as any);
app.use('/api/data', secure(auth));

app.post('/api/data', (request: express.Request, response: express.Response) => {
    
    const data = {message: 'Success response from the Business API'};
    response.setHeader('content-type', 'application/json');
    response.status(200).send(JSON.stringify(data, null, 2));

    console.log(`Business API returned a success result at ${new Date().toISOString()}`);
});

app.listen(configuration.port, () => {
    console.log(`Business API is listening on internal HTTP port ${configuration.port}`);
});
