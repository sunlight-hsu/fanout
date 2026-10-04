FROM --platform=linux/x86_64 golang:1.24-bookworm AS build

WORKDIR /src

COPY ./go.mod ./go.sum /src/
RUN go mod download

COPY . .
RUN set -xe; \
    go build \
      -buildmode=pie \
      -ldflags "-linkmode external -extldflags -static-pie" \
      -tags netgo \
      -o /fanout . \
    ;

FROM scratch

COPY --from=build /fanout /fanout

ENTRYPOINT ["/fanout"]
