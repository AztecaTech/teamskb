FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /srv
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY test ./test
RUN npm test

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1
ENV NODE_ENV=production
WORKDIR /srv
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /srv/dist ./dist
RUN mkdir -p /var/lib/iqkb-msal /run/iqkb && chown -R 65532:65532 /var/lib/iqkb-msal /run/iqkb
USER 65532:65532
EXPOSE 3978
CMD ["node", "dist/server.js"]
