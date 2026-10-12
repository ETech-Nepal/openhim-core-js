FROM node:20-alpine AS build

WORKDIR /build

COPY . .

RUN npm install && npm run build

FROM node:20-alpine

ENV NODE_ENV=production

RUN apk upgrade --update-cache --available && \
    apk add openssl && \
    rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=build ./build/lib ./lib

COPY . .

RUN npm install --production --ignore-scripts

CMD ["node", "lib/server.js"]
