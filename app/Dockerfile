FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM golang:1.27.1@sha256:e0174e51e81218523251d85d248a90d24c3d5e81543b4f07a5d66229397db190 AS build
WORKDIR /src
COPY app/go.mod app/go.sum ./
RUN go mod download
COPY app/ ./
COPY --from=frontend /src/frontend/dist ./internal/web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/iqkb ./cmd/iqkb
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/iqkb-db ./cmd/iqkb-db
RUN mkdir -p /runtime/var/lib/iqkb /runtime/run/iqkb /runtime/run/parser && chmod 0700 /runtime/var/lib/iqkb /runtime/run/iqkb /runtime/run/parser && chown -R 65532:65532 /runtime

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/iqkb /iqkb
COPY --from=build /out/iqkb-db /iqkb-db
COPY --from=build --chown=65532:65532 /runtime/var/lib/iqkb /var/lib/iqkb
COPY --from=build --chown=65532:65532 /runtime/run/iqkb /run/iqkb
COPY --from=build --chown=65532:65532 /runtime/run/parser /run/parser
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/iqkb"]
