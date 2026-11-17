# syntax=docker/dockerfile:1
# Lightweight test image: SPA + single Go binary (migrations embedded).
FROM node:20-alpine AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -o /identityhub ./cmd/identityhub

FROM alpine:3.20
RUN adduser -D -u 10001 app && apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=go /identityhub ./identityhub
RUN mkdir -p ./var/uploads && chown -R app:app /app
USER app
EXPOSE 8080 1389 1812/udp
ENTRYPOINT ["/app/identityhub"]
CMD ["serve"]
