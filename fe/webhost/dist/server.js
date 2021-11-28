"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const fs_1 = __importDefault(require("fs"));
const https_1 = __importDefault(require("https"));
const path_1 = __importDefault(require("path"));
/*
 * First load configuration
 */
const buffer = fs_1.default.readFileSync('config.json');
const configuration = JSON.parse(buffer.toString());
/*
 * Write security headers when a request is first received
 */
const app = express_1.default();
app.use((request, response, next) => {
    let policy = "default-src 'none';";
    policy += " script-src 'self';";
    policy += ` connect-src 'self' ${configuration.apiBaseUrl};`;
    policy += " img-src 'self';";
    policy += " style-src 'self' https://cdn.jsdelivr.net;";
    policy += " object-src 'none'";
    response.setHeader('content-security-policy', policy);
    // A production ready implementation would also include other recommended headers:
    // https://infosec.mozilla.org/guidelines/web_security
    next();
});
/*
 * Then serve static content, which is done from a different path when running in a deployed container
 */
if (process.env.NODE_ENV === 'production') {
    app.use(express_1.default.static('./content'));
}
else {
    app.use(express_1.default.static(path_1.default.resolve(__dirname, '../../spa/dist')));
}
/*
 * Start listening on either HTTP or HTTPS, depending on configuration
 */
if (configuration.keystoreFilePath) {
    const keystore = fs_1.default.readFileSync(configuration.keystoreFilePath);
    const sslOptions = {
        pfx: keystore,
        passphrase: configuration.keystorePassword,
    };
    const httpsServer = https_1.default.createServer(sslOptions, app);
    httpsServer.listen(configuration.port, () => {
        console.log(`Web Host is listening on HTTPS port ${configuration.port}`);
    });
}
else {
    app.listen(configuration.port, () => {
        console.log(`Web Host is listening on HTTP port ${configuration.port}`);
    });
}
