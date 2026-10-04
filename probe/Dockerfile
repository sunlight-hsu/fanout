FROM --platform=linux/x86_64 golang:1.24-bookworm AS build

WORKDIR /src

COPY ./go.mod ./go.sum /src/
RUN go mod download

COPY ./probe.go /src/
RUN set -xe; \
    go build \
      -buildmode=pie \
      -ldflags "-linkmode external -extldflags -static-pie" \
      -tags netgo \
      -o /probe probe.go \
    ;

FROM scratch

COPY --from=build /probe /probe

CMD ["/probe"]
