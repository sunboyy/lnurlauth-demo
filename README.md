# LNURL-auth demo

A Go simple client-server application implementing LNURL-auth based on the [LUD-04 RFC](https://github.com/fiatjaf/lnurl-rfc/blob/luds/04.md).

## Server

```sh
go run ./cmd/server \
    --hostname http://localhost:8080 \
    --port 8080
```

## Client
