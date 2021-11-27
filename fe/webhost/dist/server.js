"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const path_1 = __importDefault(require("path"));
const app = express_1.default();
/*
 * First write security headers
 */
app.use((request, response, next) => {
    let policy = "default-src 'none';";
    policy += " script-src 'self';";
    policy += " connect-src 'self' https://api.example.com:9443;";
    policy += " img-src 'self';";
    policy += " style-src 'self' https://cdn.jsdelivr.net;";
    policy += " object-src 'none'";
    response.setHeader('content-security-policy', policy);
    // A production ready implementation would also include other recommended headers:
    // https://infosec.mozilla.org/guidelines/web_security
    next();
});
/*
 * Then serve static content
 */
let port = 0;
if (process.env.NODE_ENV === 'production') {
    app.use(express_1.default.static('./content'));
    port = 3000;
}
else {
    app.use(express_1.default.static(path_1.default.resolve(__dirname, '../../spa/dist')));
    port = 80;
}
app.listen(port, () => {
    console.log(`Web Host is listening on internal HTTP port ${port}`);
});
