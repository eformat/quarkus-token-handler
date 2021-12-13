# 🔐 quarkus-token-handler 🔐

SPA using Keycloak, OIDC, OAuth2, FAPI, Encrypted Cookies.

- https://curity.io/resources/learn/the-token-handler-pattern
- https://www.pingidentity.com/en/company/blog/posts/2021/refresh-token-rotation-spa.html

An re-implementation using Quarkus and Keycloak based on the the fantastic curity.io examples. 👏👏

![images/token-handler.png](images/token-handler.png)

SPA (single page apps) use access tokens that grant access to backend resources. SPA's are run in an insecure environment (the user's browser) and can be served off of CDN hosting. The risk of Token attacks is high e.g. XSS from malicious javascript code stealing tokens.

Modern browsers offer ways to secure cookies and limit their usage to secure HTTPS traffic only (thus inaccessible to scripts or insecure traffic). By setting `SameSite=strict` we can limit requests from only the originating domain. CORS headers are set to further limit CSRF attacks. Content Security Policy headers are set to block malicious code from sending requests outside the app.

The only way to protect tokens from being accessed by any malicious code is to keep them away from the browser. Tokens are encrypted and stored on the client using `SameSite, HttpOnly, Secure` cookies. This is stateless from a backend perspective (cookies are not stored on the server side). The `Token Handler Pattern` is a back-end-for-frontend approach. All communication from the front end goes through the token handler. The token handler is made up of two apps. The handler itself communicates to the identity service (Keycloak) using signed client secrets (JARM) and Pushed Authentication requests (PAR). These include PKCE and other best in breed Oauth2.0 practices. The business api call is proxied through to the backend application, converting the cookie to a bearer token which is checked against the JWK auth endpoint.

In this example the Keycloak client (`bff_client`) is conformant to security standards and profiles set at the realm level - i.e. Financial-grade API baseline and advanced `Policy` is met (with one exception - we disable holder-of-key enforcer i.e mTLS clients - which is a WIP).

![images/fe.png](images/fe.png)

## Certificate Setup

Token Handler and Proxy needs SSL Certificates generated
```bash
cd test/certs
./create-certs.sh
cp example.server.p12 ../../th/src/main/resources/
cp example.client.p12 ../../th/src/main/resources/
cp example.ca.pem ../../keycloak/
cp example.server.pem ../../proxy/src/main/resources/
cp example.server.key ../../proxy/src/main/resources/
cp example.server.p12 ../../fe/webhost/
```

Load the CA `example.ca.pem` into your Web Browser trust store for demoing.

Generate bff-client JWT certs
```bash
cd test/certs
go get github.com/lestrrat-go/jwx/cmd/jwx
jwx jwk generate --type RSA --keysize 2048 --template '{"alg":"PS256","use":"sig"}' > private.key
jwx jwk format --public-key private.key > public.key
cp private.key ../../th/src/main/resources/
echo '{"keys":['`cat public.key`']}'| jq . > public-jwk.key
cp public.key ../../th/src/main/resources/
```

After Keycloak has started, put its self-signed cert into a keystore:
```bash
cd th
keytool -genkey -alias secure-server -storetype PKCS12 -keyalg RSA -keysize 2048 -keystore keystore.p12 -validity 3650 -dname "CN=DEV, OU=DEV, O=ACME, L=Brisbane, ST=QLD, C=AU" -storepass password
openssl s_client -showcerts -connect localhost:8443 </dev/null 2>/dev/null | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ {print $0}' > /tmp/kc.pem
keytool -trustcacerts -keystore keystore.p12 -storepass password -importcert -alias login.example.com -file "/tmp/kc.pem" -noprompt
keytool -list -keystore keystore.p12 -storepass password -noprompt
```

## Running Locally

Keycloak
```bash
cd keycloak
podman-compose up -d
```

Login to Keycloak admin web console and Add a new realm using `keycloak/bff-openid-code-grant-realm.json` file.

Run the Proxy
```bash
cd proxy
mvn quarkus:dev -Ddebug=5006
```

Build the Front End
```bash
cd fe/spa
npm run build
```

Run the example Front End
```bash
cd fe/webhost
npm run start
```

Run the example Business API
```bash
cd be/api
npm run start
```

Run the Token Handler
```bash
cd th
# we need the truststore for JARM (jwt validation)
mvn clean quarkus:dev -Djavax.net.ssl.trustStore=keystore.p12 -Djavax.net.ssl.trustStorePassword=password
```

Run the Test suite
```bash
cd test
./test-token-handler.sh
>>> 🌈 TESTING COMPLETED OK 🌈
```


## Deploy to OpenShift

As cluster-admin, create `token-handler` Project, Keycloak Operator, Keycloak instance, Applications
```bash
cd deploy
oc apply -k dev
```
