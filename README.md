# quarkus-token-handler

- https://curity.io/resources/learn/the-token-handler-pattern

Keycloak
```bash
podman-compose up -d
```

Getting keycloak cert put it in a keystore
```bash
keytool -genkey -alias secure-server -storetype PKCS12 -keyalg RSA -keysize 2048 -keystore keystore.p12 -validity 3650 -dname "CN=DEV, OU=DEV, O=ACME, L=Brisbane, ST=QLD, C=AU" -storepass password
-- add certs from keycloak
openssl s_client -showcerts -connect localhost:8443 </dev/null 2>/dev/null | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ {print $0}' > /tmp/kc.pem
keytool -trustcacerts -keystore keystore.p12 -storepass password -importcert -alias login.example.com -file "/tmp/kc.pem"
keytool -list -keystore keystore.p12 -storepass password -noprompt
```

Run the Proxy
```bash
cd proxy
mvn quarkus:dev -Ddebug=5006
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
