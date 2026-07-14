# Multi-stage minimal image for CI usage
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X github.com/GhanshyamJha05/Sentinel/pkg/version.Version=${VERSION} -X github.com/GhanshyamJha05/Sentinel/pkg/version.Commit=${COMMIT} -X github.com/GhanshyamJha05/Sentinel/pkg/version.Date=${DATE}" -o /sentinel .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /sentinel /sentinel
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/sentinel"]
CMD ["--help"]
