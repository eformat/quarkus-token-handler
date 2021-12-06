# quarkus-token-handler

- https://curity.io/resources/learn/the-token-handler-pattern

## Certificate Setup

Token Handler needs a server SSL Certificate generated
```bash
cd th/certs
./create-certs.sh
cp example.server.p12 ../th/src/main/resources/example.server.p12
```

Load the CA `example.ca.pem` into your Web Browser trust store for demoing.

Generate certs, libraries and a signed JWT for the bff-client
```bash
cd test/certs
./create-jwt.sh
cp bff-client-pkcs8.key ../../th/src/main/resources/
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
