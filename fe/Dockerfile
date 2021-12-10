FROM node:15.11.0-alpine

WORKDIR /usr/webhost
COPY webhost/dist          /usr/webhost/dist
COPY webhost/package*.json /usr/webhost/
COPY spa/dist              /usr/webhost/content

RUN npm install --production

RUN addgroup -g 1001 webgroup
RUN adduser -u 1001 -G webgroup -h /home/webuser -D webuser

USER webuser

# FIXME
COPY webhost/config-dev.json   /usr/webhost/config.json
COPY webhost/example.server.p12   /usr/webhost/example.server.p12

CMD ["node", "dist/server.js"]