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
export CLIENT_SECRET=1cd70bdf-db5b-4346-83da-babe16dae1d8
mvn quarkus:dev
```
