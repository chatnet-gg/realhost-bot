package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	IRCHost          string
	IRCPort          string
	Nick             string
	NickservAccount  string
	NickservPassword string
	OperNick         string
	OperPassword     string
	Channel          string
}

func loadConfig() Config {
	return Config{
		IRCHost:          mustEnv("IRC_HOST"),
		IRCPort:          getenv("IRC_PORT", "6667"),
		Nick:             getenv("BOT_NICK", "realhostbot"),
		NickservAccount:  getenv("NICKSERV_ACCOUNT", "realhostbot"),
		NickservPassword: mustEnv("NICKSERV_PASSWORD"),
		OperNick:         getenv("OPER_NICK", "realhostbot"),
		OperPassword:     mustEnv("OPER_PASSWORD"),
		Channel:          getenv("IRC_CHANNEL", "#CN-RealHost"),
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s must be set", key)
	}
	return v
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type Bot struct {
	cfg Config

	mu   sync.Mutex
	conn net.Conn

	waitMu sync.Mutex
	waitFn func(Line) bool
	waitCh chan Line

	saslDone  bool
	processMu sync.Mutex
}

func main() {
	cfg := loadConfig()
	b := &Bot{cfg: cfg}

	backoff := time.Second
	for {
		if err := b.connectAndRun(); err != nil {
			log.Printf("connection error: %v (reconnecting in %s)", err, backoff)
		}
		time.Sleep(backoff)
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

// SASL PLAIN pre-registration avoids a post-connect NickServ IDENTIFY
// causing a CHGHOST blip. Plaintext credentials over PLAIN (no client
// cert) match the trust tier the bot's other secrets are already held
// at (plain env vars).
func (b *Bot) connectAndRun() error {
	addr := net.JoinHostPort(b.cfg.IRCHost, b.cfg.IRCPort)
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	b.mu.Lock()
	b.conn = conn
	b.saslDone = false
	b.mu.Unlock()

	b.send("CAP LS 302")
	b.send("NICK " + b.cfg.Nick)
	b.send("USER " + b.cfg.Nick + " 0 * :ChatNet real-host self-service bot")
	log.Printf("connecting to %s as %s", addr, b.cfg.Nick)

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		b.dispatch(parseLine(line))
	}
}

func (b *Bot) send(s string) {
	b.mu.Lock()
	conn := b.conn
	b.mu.Unlock()
	if conn == nil {
		return
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "%s\r\n", s)
}

func saslPlainPayload(account, password string) string {
	raw := account + "\x00" + account + "\x00" + password
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func (b *Bot) dispatch(l Line) {
	b.waitMu.Lock()
	fn, ch := b.waitFn, b.waitCh
	b.waitMu.Unlock()
	if fn != nil && ch != nil && fn(l) {
		select {
		case ch <- l:
		default:
		}
	}

	switch l.Command {
	case "PING":
		b.send("PONG :" + l.Trailing)

	case "CAP":
		if len(l.Params) < 2 {
			break
		}
		switch strings.ToUpper(l.Params[1]) {
		case "LS":
			if strings.Contains(l.Trailing, "sasl") {
				b.send("CAP REQ :sasl")
			} else {
				b.send("CAP END")
			}
		case "ACK":
			if strings.Contains(l.Trailing, "sasl") {
				b.send("AUTHENTICATE PLAIN")
			}
		case "NAK":
			b.send("CAP END")
		}

	case "AUTHENTICATE":
		if len(l.Params) > 0 && l.Params[0] == "+" {
			b.send("AUTHENTICATE " + saslPlainPayload(b.cfg.NickservAccount, b.cfg.NickservPassword))
		}

	case "903":
		if !b.saslDone {
			b.saslDone = true
			b.send("CAP END")
		}

	case "904", "905", "906", "907":
		log.Printf("SASL failed (%s: %s) -- oper/vhost commands will not work", l.Command, l.Trailing)
		if !b.saslDone {
			b.saslDone = true
			b.send("CAP END")
		}

	case "001":
		b.send(fmt.Sprintf("OPER %s %s", b.cfg.OperNick, b.cfg.OperPassword))
		b.send("JOIN " + b.cfg.Channel)
		log.Printf("registered, joined %s, opering up as %s", b.cfg.Channel, b.cfg.OperNick)

	case "381":
		log.Printf("oper-up succeeded")

	case "464":
		log.Printf("oper-up FAILED (password mismatch) -- real-host lookups will not work until fixed")

	case "PRIVMSG":
		b.onPrivmsg(l)
	}
}

func (b *Bot) awaitReply(ctx context.Context, fn func(Line) bool) (Line, bool) {
	ch := make(chan Line, 20)
	b.waitMu.Lock()
	b.waitFn, b.waitCh = fn, ch
	b.waitMu.Unlock()
	defer func() {
		b.waitMu.Lock()
		if b.waitCh == ch {
			b.waitFn, b.waitCh = nil, nil
		}
		b.waitMu.Unlock()
	}()

	select {
	case l := <-ch:
		return l, true
	case <-ctx.Done():
		return Line{}, false
	}
}

func withTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
