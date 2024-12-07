# Building
FROM golang:1.23.2-alpine3.20 AS build

WORKDIR /build
COPY go.mod .
COPY *.go .
RUN go get gargantua

RUN CGO_ENABLED=0 GOOS=linux go build -o /build/bin/main
RUN chmod o+x /build/bin/main

# Running
FROM debian:bullseye-slim AS app

WORKDIR /app
COPY --from=build /build/bin/main .

EXPOSE 3000

ENTRYPOINT ["./main"]
