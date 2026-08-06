# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache modules first.
COPY go.mod ./
RUN go mod download

# Build a static binary (UI assets are embedded via go:embed).
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/ghe-wizard/ghe-wizard/internal/buildinfo.Version=${VERSION} \
        -X github.com/ghe-wizard/ghe-wizard/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/ghe-wizard/ghe-wizard/internal/buildinfo.Date=${DATE}" \
      -o /out/ghe-wizard ./cmd/ghe-wizard

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="ghe-wizard" \
      org.opencontainers.image.description="Assess, modify and implement GitHub Enterprise Cloud best practices" \
      org.opencontainers.image.source="https://github.com/heisenberg-alt/ghe-wizard" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/ghe-wizard /usr/local/bin/ghe-wizard

# Web dashboard default port.
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/ghe-wizard"]
CMD ["serve", "--addr", ":8080"]
