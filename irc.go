package main

import (
	"strings"
)

// Line is a parsed IRC protocol line: ":prefix COMMAND param1 param2 :trailing"
// No IRCv3 tag parsing -- the servers/pseudo-users this bot talks to
// never send tags it cares about.
type Line struct {
	Prefix   string
	Nick     string
	Command  string
	Params   []string
	Trailing string
	Raw      string
}

func parseLine(raw string) Line {
	l := Line{Raw: raw}
	s := raw

	if strings.HasPrefix(s, ":") {
		sp := strings.IndexByte(s, ' ')
		if sp == -1 {
			l.Prefix = s[1:]
			return l
		}
		l.Prefix = s[1:sp]
		s = s[sp+1:]
	}

	if bang := strings.IndexByte(l.Prefix, '!'); bang != -1 {
		l.Nick = l.Prefix[:bang]
	} else if l.Prefix != "" && !strings.Contains(l.Prefix, ".") {
		l.Nick = l.Prefix
	}

	if idx := strings.Index(s, " :"); idx != -1 {
		l.Trailing = s[idx+2:]
		s = s[:idx]
	} else if strings.HasPrefix(s, ":") {
		l.Trailing = s[1:]
		s = ""
	}

	fields := strings.Fields(s)
	if len(fields) > 0 {
		l.Command = fields[0]
		l.Params = fields[1:]
	}
	return l
}

func (l Line) text() string {
	if l.Trailing != "" {
		return l.Trailing
	}
	if len(l.Params) > 1 {
		return l.Params[len(l.Params)-1]
	}
	return ""
}

func (l Line) target() string {
	if len(l.Params) > 0 {
		return l.Params[0]
	}
	return ""
}
