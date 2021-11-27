"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const cors_1 = __importDefault(require("cors"));
const express_1 = __importDefault(require("express"));
const fs_1 = __importDefault(require("fs"));
const http_1 = __importDefault(require("http"));
const express_oauth_jwt_1 = require("express-oauth-jwt");
const buffer = fs_1.default.readFileSync('config.json');
const configuration = JSON.parse(buffer.toString());
const app = express_1.default();
const auth = express_oauth_jwt_1.jwksService(new express_oauth_jwt_1.InMemoryCache(), configuration.jwksUrl, http_1.default);
// Grant access to the web origin and allow it to send the secure cookie
const corsOptions = {
    origin: configuration.trustedWebOrigin,
    credentials: true,
};
app.set('etag', false);
app.use('/data', cors_1.default(corsOptions));
app.use('/data', express_oauth_jwt_1.secure(auth));
app.post('/data', (request, response) => {
    const data = { message: 'Success response from the Business API' };
    response.setHeader('content-type', 'application/json');
    response.status(200).send(JSON.stringify(data, null, 2));
    console.log(`Business API returned a success result at ${new Date().toISOString()}`);
});
app.listen(configuration.port, () => {
    console.log(`Business API is listening on internal HTTP port ${configuration.port}`);
});
