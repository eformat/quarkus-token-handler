# quarkus-token-handler

- https://curity.io/resources/learn/the-token-handler-pattern

Keycloak
```bash
podman-compose up -d
```

Front End
```bash
cd fe/webhost
npm run start
```

Token Handler
```bash
cd th
export CLIENT_SECRET=<from keycloak the bff client credential secret>
mvn quarkus:dev
```
