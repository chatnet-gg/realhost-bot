package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	whoisTimeout    = 10 * time.Second
	nickservTimeout = 10 * time.Second
	k9Timeout       = 10 * time.Second
	cooldownWindow  = 24 * time.Hour
)

// Same numeric/regex convention as K9/sentry's own WHOIS-378 handling --
// RPL_WHOISHOST's trailing text is "is connecting from <ident>@<realhost>
// <ip>", oper-only (auspex:hostname-gated).
var whoisHostRe = regexp.MustCompile(`is connecting from \S+@(\S+)`)

// For a connection that comes in through a shared gateway with a fixed
// auth{} spoof (Matrix/Telegram bridge puppets, the Tor hidden service
// sidecar), WHOIS 378 doesn't reveal anything personal -- it shows that
// gateway's own configured spoof string, identical for every single
// user who comes through it, because solanum's auth{} "spoof" overwrites
// orighost itself at connection registration, before any per-user cloak
// module ever runs. Running !realhost for one of these accounts would
// strip their real, meaningful cloak (user/<account>, or Tor's own
// dedicated gateway/tor-sasl/<account>) in exchange for that same
// shared, non-identifying value everyone else behind the gateway
// already has -- a straight downgrade, not a privacy trade a user meant
// to make. Refuse rather than let someone do this to themselves by
// accident.
var sharedGatewayHosts = map[string]string{
	"chatnet/bridge/matrix":  "the Matrix bridge",
	"chatnet/bot/telegram":   "the Telegram bridge",
	"tor-pending.chatnet.gg": "the Tor gateway",
	"127.0.0.1":              "an internal gateway",
	// The ZNC bouncer container has no auth{} spoof block of its own,
	// so it falls through to the generic "*@*" catch-all -- its real
	// docker-internal IP is exactly what shows up here, identical for
	// every bouncer user regardless of who they are. Same
	// shared-gateway problem as the bridges, just via omission instead
	// of an explicit spoof.
	"172.29.0.16": "the ZNC bouncer",
}

var (
	cooldownMu sync.Mutex
	cooldown   = make(map[string]time.Time)
)

func (b *Bot) onPrivmsg(l Line) {
	if l.target() != b.cfg.Channel {
		return
	}
	text := l.text()
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return
	}
	cmd := fields[0]
	if cmd != "!realhost" && cmd != "!cloakme" {
		return
	}
	if len(fields) != 2 {
		b.send(fmt.Sprintf("PRIVMSG %s :Usage: %s <your-account-name>", b.cfg.Channel, cmd))
		return
	}
	requestedName := fields[1]
	requester := l.Nick

	b.processMu.Lock()
	go func() {
		defer b.processMu.Unlock()
		if cmd == "!realhost" {
			b.handleRealhostRequest(requester, requestedName)
		} else {
			b.handleCloakmeRequest(requester, requestedName)
		}
	}()
}

func (b *Bot) handleRealhostRequest(requester, requestedName string) {
	log.Printf("!realhost request from %s for account %q", requester, requestedName)

	account, identified := b.whoisAccount(requester)
	if !identified {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: you need to be logged into NickServ to use this.", b.cfg.Channel, requester))
		return
	}
	if !strings.EqualFold(account, requestedName) {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: the account name must match your own logged-in account (%s).", b.cfg.Channel, requester, account))
		return
	}

	if wait, onCooldown := checkCooldown(account); onCooldown {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: you already requested this recently, try again in %s.", b.cfg.Channel, requester, wait.Round(time.Minute)))
		return
	}

	displayedHost, realHost, ok := b.whoisHosts(requester)
	if !ok {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: couldn't determine your real host -- try again in a moment.", b.cfg.Channel, requester))
		return
	}
	if strings.EqualFold(displayedHost, realHost) {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: you're already showing your real host (%s) -- nothing to do. Use !cloakme %s if you want your cloak back instead.", b.cfg.Channel, requester, realHost, account))
		return
	}

	if gateway, blocked := sharedGatewayHosts[strings.ToLower(realHost)]; blocked {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: you're connecting through %s, which doesn't have a real host of its own to show -- every user behind it looks identical here. Using this command would just replace your normal cloak with that same shared, non-identifying value. Not doing that.", b.cfg.Channel, requester, gateway))
		return
	}

	if err := b.setVhost(account); err != nil {
		log.Printf("VHOST OFF failed for %s: %v", account, err)
		b.send(fmt.Sprintf("PRIVMSG %s :%s: couldn't remove your cloak -- ask abcX to check.", b.cfg.Channel, requester))
		return
	}

	markCooldown(account)
	b.send(fmt.Sprintf("PRIVMSG %s :Done, %s -- your cloak is removed, your real host (currently %s) will show live from now on and update automatically if it ever changes. Reconnect to see it take effect.", requester, account, realHost))
	b.send(fmt.Sprintf("PRIVMSG %s :%s: check your PMs.", b.cfg.Channel, requester))
	log.Printf("cloak removed for %s (real host at request time: %s)", account, realHost)

	b.banKick(account, requester)
}

// handleCloakmeRequest: the reverse of !realhost -- puts the standard
// user/<account> cloak back for someone who used !realhost earlier and
// changed their mind, self-service, no staff needed. Named after
// Libera.Chat's own public "cloakme" bot (github.com/Libera-Chat/cloaks),
// which runs the exact same underlying command
// (`NickServ DEFAULTCLOAK <account> FORCE`) -- borrowed the *command
// name and the specific NickServ call* from reading their source,
// nothing else (different language, no other logic in common).
func (b *Bot) handleCloakmeRequest(requester, requestedName string) {
	log.Printf("!cloakme request from %s for account %q", requester, requestedName)

	account, identified := b.whoisAccount(requester)
	if !identified {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: you need to be logged into NickServ to use this.", b.cfg.Channel, requester))
		return
	}
	if !strings.EqualFold(account, requestedName) {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: the account name must match your own logged-in account (%s).", b.cfg.Channel, requester, account))
		return
	}

	if wait, onCooldown := checkCooldown(account); onCooldown {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: you already requested this recently, try again in %s.", b.cfg.Channel, requester, wait.Round(time.Minute)))
		return
	}

	displayedHost, realHost, ok := b.whoisHosts(requester)
	if !ok {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: couldn't check your current host -- try again in a moment.", b.cfg.Channel, requester))
		return
	}
	if !strings.EqualFold(displayedHost, realHost) {
		b.send(fmt.Sprintf("PRIVMSG %s :%s: you already have a cloak set (%s) -- nothing to do.", b.cfg.Channel, requester, displayedHost))
		return
	}

	if err := b.setDefaultCloak(account); err != nil {
		log.Printf("DEFAULTCLOAK FORCE failed for %s: %v", account, err)
		b.send(fmt.Sprintf("PRIVMSG %s :%s: couldn't reassign your cloak -- ask abcX to check.", b.cfg.Channel, requester))
		return
	}

	markCooldown(account)
	b.send(fmt.Sprintf("PRIVMSG %s :Done, %s -- your standard user/%s cloak is back, your real host is hidden again. Reconnect to see it take effect.", requester, account, account))
	b.send(fmt.Sprintf("PRIVMSG %s :%s: check your PMs.", b.cfg.Channel, requester))
	log.Printf("default cloak reassigned for %s", account)

	b.banKick(account, requester)
}

// setDefaultCloak runs NickServ DEFAULTCLOAK <account> FORCE, the same
// command Libera's public cloakme bot uses for its own single
// direction. FORCE is required here since this bot is never the
// account's own logged-in session -- without it, Services blocks the
// command with "You are attempting to set your own cloak to default"
// for anyone other than an oper acting on someone else's account.
// Success text is "Assigned default cloak to <account>."
func (b *Bot) setDefaultCloak(account string) error {
	ctx, cancel := withTimeout(nickservTimeout)
	defer cancel()

	b.send(fmt.Sprintf("PRIVMSG NickServ :DEFAULTCLOAK %s FORCE", account))

	l, ok := b.awaitReply(ctx, func(l Line) bool {
		return (l.Command == "NOTICE" || l.Command == "PRIVMSG") && strings.EqualFold(l.Nick, "NickServ")
	})
	if !ok {
		return fmt.Errorf("no reply from NickServ")
	}
	reply := l.text()
	if !strings.HasPrefix(reply, "Assigned default cloak") {
		return fmt.Errorf("%s", reply)
	}
	return nil
}

// banKick bans by $a:<account> (an account extban, passed through
// unresolved by the ban-list handler rather than resolved to a host
// mask) rather than by the user's current host. Banning by host here
// would be actively wrong --
// !realhost's whole point is setting the user's REAL host, which can
// be shared infrastructure (a bridge, NAT, VPN exit) -- a host-mask ban
// would collaterally ban everyone else behind that same host too. $a:
// is immune to that and to nick/host changes. Still only needs the
// already-granted K9 channel access (level 75, CA_REMOVE) -- no
// channel-operator status, no privilege escalation.
func (b *Bot) banKick(account, nick string) {
	if err := b.k9Cmd(fmt.Sprintf("BAN %s $a:%s", b.cfg.Channel, account)); err != nil {
		log.Printf("K9 BAN failed for %s: %v", account, err)
	}
	if err := b.k9Cmd(fmt.Sprintf("KICK %s %s real host set, check your PMs", b.cfg.Channel, nick)); err != nil {
		log.Printf("K9 KICK failed for %s: %v", nick, err)
	}
}

func (b *Bot) k9Cmd(cmd string) error {
	ctx, cancel := withTimeout(k9Timeout)
	defer cancel()

	b.send("PRIVMSG K9 :" + cmd)

	l, ok := b.awaitReply(ctx, func(l Line) bool {
		return l.Command == "PRIVMSG" && strings.EqualFold(l.Nick, "K9")
	})
	if !ok {
		return fmt.Errorf("no reply from K9 to %q", cmd)
	}
	// K9's own denial/error text conventions vary by command; log the raw
	// reply either way rather than pattern-match every possible phrasing --
	// a failed ban/kick isn't itself a reason to withhold the vhost change
	// already made.
	log.Printf("K9 reply to %q: %s", cmd, l.text())
	return nil
}

// whoisAccount reads the account name (330), or reports not-identified
// on 318 (end of WHOIS, no account line seen) or 401 (no such nick).
func (b *Bot) whoisAccount(nick string) (account string, identified bool) {
	ctx, cancel := withTimeout(whoisTimeout)
	defer cancel()

	b.send("WHOIS " + nick)

	for {
		l, ok := b.awaitReply(ctx, func(l Line) bool {
			if l.Command != "330" && l.Command != "318" && l.Command != "401" {
				return false
			}
			return len(l.Params) > 1 && strings.EqualFold(l.Params[1], nick)
		})
		if !ok {
			return "", false
		}
		switch l.Command {
		case "330":
			if len(l.Params) > 2 {
				return l.Params[2], true
			}
			return "", false
		case "318", "401":
			return "", false
		}
	}
}

// whoisRealHost sends a second WHOIS and waits for 378 (RPL_WHOISHOST,
// only visible to us because we hold auspex:hostname as an oper) or 318
// (end of whois with no 378 -- shouldn't happen for an oper, but fail
// closed rather than guess).
func (b *Bot) whoisRealHost(nick string) (string, bool) {
	_, realHost, ok := b.whoisHosts(nick)
	return realHost, ok
}

// whoisHosts reads both the displayed host (311, whatever mask/cloak
// is currently showing to everyone) and the real host (378, oper-only
// via auspex:hostname) from a single WHOIS. Comparing the two tells us
// whether the account is currently cloaked at all -- equal means no
// cloak/vhost is active (their displayed host already IS their real
// one), different means something (default cloak, a custom vhost,
// anything) is currently masking it. Used to guard !cloakme against
// clobbering an account that already has some cloak on it, not just
// the exact default one (ns_defaultcloak.c's own "already has a
// default cloak" check only catches the latter, narrower case).
func (b *Bot) whoisHosts(nick string) (displayedHost, realHost string, ok bool) {
	ctx, cancel := withTimeout(whoisTimeout)
	defer cancel()

	// Register ONE channel/predicate for the whole WHOIS burst and read
	// from it repeatedly, rather than calling awaitReply per-numeric in
	// a loop. awaitReply tears down its channel/predicate the instant it
	// returns one match and only re-arms on the *next* call -- a real
	// race when two matching numerics (311 then 378) arrive back-to-back
	// in the same burst: whichever one lands in that gap gets silently
	// dropped, since nothing is armed to catch it. Registering once and
	// draining the same channel for the whole burst closes that gap.
	ch := make(chan Line, 20)
	matches := func(l Line) bool {
		if l.Command != "311" && l.Command != "378" && l.Command != "318" && l.Command != "401" {
			return false
		}
		return len(l.Params) > 1 && strings.EqualFold(l.Params[1], nick)
	}
	b.waitMu.Lock()
	b.waitFn, b.waitCh = matches, ch
	b.waitMu.Unlock()
	defer func() {
		b.waitMu.Lock()
		if b.waitCh == ch {
			b.waitFn, b.waitCh = nil, nil
		}
		b.waitMu.Unlock()
	}()

	b.send("WHOIS " + nick)

	for {
		select {
		case l := <-ch:
			switch l.Command {
			case "311":
				if len(l.Params) > 3 {
					displayedHost = l.Params[3]
				}
			case "378":
				m := whoisHostRe.FindStringSubmatch(l.text())
				if m != nil {
					realHost = m[1]
				}
			case "318":
				return displayedHost, realHost, displayedHost != "" && realHost != ""
			case "401":
				return "", "", false
			}
		case <-ctx.Done():
			return "", "", false
		}
	}
}

// setVhost runs NickServ VHOST <account> OFF -- NOT "ON <realhost>".
// "ON <host>" still assigns a vhost, just one that happens to equal the
// real host at the moment of the request -- a frozen snapshot that
// goes stale the next time the user's real IP/rDNS changes. "OFF"
// instead calls metadata_delete(mu, "private:usercloak") -- with that
// metadata gone entirely, vhost_on_identify()'s very first check
// (`if (!(md = metadata_find(mu, "private:usercloak"))) return;`) skips
// applying anything on every future login, so the user's live,
// currently-real host always shows through on its own. Genuinely no
// cloak at all, not a vhost dressed up to look like one. Success text
// is "Deleted vhost for <account>." (same file) -- anything else
// (already off, marked account, etc.) is surfaced as failure.
func (b *Bot) setVhost(account string) error {
	ctx, cancel := withTimeout(nickservTimeout)
	defer cancel()

	b.send(fmt.Sprintf("PRIVMSG NickServ :VHOST %s OFF", account))

	l, ok := b.awaitReply(ctx, func(l Line) bool {
		return (l.Command == "NOTICE" || l.Command == "PRIVMSG") && strings.EqualFold(l.Nick, "NickServ")
	})
	if !ok {
		return fmt.Errorf("no reply from NickServ")
	}
	reply := l.text()
	if !strings.HasPrefix(reply, "Deleted vhost") {
		return fmt.Errorf("%s", reply)
	}
	return nil
}

func checkCooldown(account string) (time.Duration, bool) {
	cooldownMu.Lock()
	defer cooldownMu.Unlock()
	last, ok := cooldown[strings.ToLower(account)]
	if !ok {
		return 0, false
	}
	elapsed := time.Since(last)
	if elapsed >= cooldownWindow {
		return 0, false
	}
	return cooldownWindow - elapsed, true
}

func markCooldown(account string) {
	cooldownMu.Lock()
	defer cooldownMu.Unlock()
	cooldown[strings.ToLower(account)] = time.Now()
}
