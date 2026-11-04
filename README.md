# realhost-bot

Self-service IRC bot for [ChatNet](https://www.chatnet.gg/). A user who is
identified to NickServ can, in the bot's channel:

- `!realhost` -- drop the account cloak and show their real host
- `!cloakme` -- put the standard `user/<account>` cloak back

The bot checks the requester's account and current host with WHOIS before
doing anything, and refuses requests that make no sense (already showing the
real host, already cloaked, internal gateway addresses).

## Requirements

- Go (or just Docker)
- A NickServ account for the bot and an IRC operator account with the
  privileges needed to change a user's host
- Channel access for the bot in its channel

## Run

```sh
docker build -t realhost-bot .
docker run -d --name realhost-bot \
  -e IRC_HOST=irc.example.org \
  -e NICKSERV_PASSWORD=... \
  -e OPER_PASSWORD=... \
  realhost-bot
```

Optional environment variables: `IRC_PORT` (6667), `BOT_NICK` and
`NICKSERV_ACCOUNT` (`realhostbot`), `OPER_NICK` (`realhostbot`),
`IRC_CHANNEL` (`#CN-RealHost`).

## License

MIT, see `LICENSE`.
