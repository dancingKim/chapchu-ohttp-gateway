FROM --platform=$BUILDPLATFORM golang:1.24.4-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH=arm64
WORKDIR /app
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOTOOLCHAIN=local go build \
    -mod=vendor -trimpath -ldflags='-w -s' -o /privacy-gateway-server .

FROM gcr.io/distroless/static-debian12:nonroot
ARG GIT_REVISION=unknown
LABEL revision=${GIT_REVISION}
COPY --from=build /privacy-gateway-server /privacy-gateway-server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/privacy-gateway-server"]
