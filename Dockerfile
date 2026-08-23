# ChatNet self-service real-host bot.
# Hand-rolled IRC over stdlib rather than a library -- the protocol
# surface this bot needs is small (SASL PLAIN, OPER, WHOIS,
# PRIVMSG/NOTICE), not worth the dependency.

FROM golang:1.22-alpine AS build

WORKDIR /app
COPY go.mod ./
COPY main.go irc.go commands.go ./
RUN go build -o /opt/realhost-bot/realhost-bot .

FROM alpine:latest

COPY --from=build /opt/realhost-bot/realhost-bot /opt/realhost-bot/realhost-bot

ENTRYPOINT ["/opt/realhost-bot/realhost-bot"]
