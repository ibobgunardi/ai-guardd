package parser

import (
	"regexp"
	"strings"
)

// SyslogParser parses generic system logs
type SyslogParser struct {
	reSudo  *regexp.Regexp
	reMySQL *regexp.Regexp
}

func NewSyslogParser() *SyslogParser {
	return &SyslogParser{
		// sudo: pam_unix(sudo:auth): authentication failure; logname= user=root host= ...
		reSudo: regexp.MustCompile(`sudo:auth.*authentication failure;.*user=(\S+)`),
		// MySQL: Access denied for user 'root'@'1.2.3.4'
		reMySQL: regexp.MustCompile(`Access denied for user '(\S+)'@'(\S+)'`),
	}
}

func (p *SyslogParser) Parse(line string) *ParsedEvent {
	// MySQL Check
	if matches := p.reMySQL.FindStringSubmatch(line); len(matches) > 2 {
		return &ParsedEvent{
			Source: "mysql",
			Type:   "login_failed",
			User:   matches[1],
			IP:     matches[2],
			Raw:    line,
		}
	}

	// Sudo Check
	if strings.Contains(line, "sudo") {
		if matches := p.reSudo.FindStringSubmatch(line); len(matches) > 1 {
			return &ParsedEvent{
				Source: "syslog_sudo",
				Type:   "priv_escalation_fail",
				User:   matches[1],
				IP:     "local",
				Raw:    line,
			}
		}
	}

	return nil
}
