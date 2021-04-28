FROM golang:1.16 AS build

ENV CGO_ENABLED=0
ENV GO111MODULE=on
ENV GOOS=linux

WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
WORKDIR /app
RUN go build -o ./bin/currency.d ./cmd/currency.d

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/bin/currency.d .
RUN mkdir key_pairs && echo "[]" > key_pairs/keys.json

CMD ["/app/currency.d"]
