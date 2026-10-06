FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS node
FROM node AS frontend
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM node AS gateway
WORKDIR /src/gateway
COPY gateway/package*.json ./
RUN npm ci
COPY gateway/ ./
RUN npm test && npm prune --omit=dev

FROM golang:1.27.1@sha256:e0174e51e81218523251d85d248a90d24c3d5e81543b4f07a5d66229397db190 AS go
WORKDIR /src
COPY app/go.mod app/go.sum ./
RUN go mod download
COPY app/ ./
COPY --from=frontend /src/frontend/dist ./internal/web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/iqkb ./cmd/iqkb && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/iqkb-db ./cmd/iqkb-db

FROM caddy:2@sha256:13b7fbadd017b042956fddbceedeeea12bb1e560534f9b3df281269dbcc61813 AS caddy
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 libatomic1 libseccomp2 libcap2-bin ca-certificates && rm -rf /var/lib/apt/lists/*
COPY parser/requirements.txt /opt/iqkb/requirements.txt
RUN pip install --no-cache-dir -r /opt/iqkb/requirements.txt
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy
# The upstream binary has a low-port capability; port 8088 needs none.
RUN setcap -r /usr/local/bin/caddy
COPY --from=go /out/ /usr/local/bin/
COPY --from=gateway /src/gateway/dist /opt/iqkb/gateway/dist
COPY --from=gateway /src/gateway/node_modules /opt/iqkb/gateway/node_modules
COPY --from=gateway /src/gateway/package.json /opt/iqkb/gateway/package.json
COPY parser/parser.py /opt/iqkb/parser.py
COPY deploy/single/ /opt/iqkb/
RUN mkdir -p /var/lib/iqkb /var/lib/iqkb-msal && chown 65532:65532 /var/lib/iqkb /var/lib/iqkb-msal && chmod 0700 /var/lib/iqkb /var/lib/iqkb-msal
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8088
ENTRYPOINT ["python", "/opt/iqkb/launcher.py"]
