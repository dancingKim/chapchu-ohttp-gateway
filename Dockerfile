FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
ARG TARGETOS=linux
ARG TARGETARCH=arm64
WORKDIR /app
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOTOOLCHAIN=local go build \
    -mod=vendor -trimpath -ldflags='-w -s' -o /privacy-gateway-server .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG GIT_REVISION=unknown
LABEL revision=${GIT_REVISION}
COPY --from=build /privacy-gateway-server /privacy-gateway-server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/privacy-gateway-server"]
