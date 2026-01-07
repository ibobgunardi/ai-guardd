package parser

import (
	"regexp"
	"strconv"
)

// HTTPParser parses Nginx/Apache Combined Log Format
// Format: 1.2.3.4 - user [01/Jan/2026:12:00:00 +0000] "GET /path HTTP/1.1" 200 123 "-" "UserAgent"
type HTTPParser struct {
	re     *regexp.Regexp
	source string
}

func NewHTTPParser(sourceLabel string) *HTTPParser {
	// Flexible regex for CLF/Combined
	// Matches: IP, User, Timestamp, Method, URL, Proto, Status, Size, Referer, UA
	if sourceLabel == "" {
		sourceLabel = "web_server"
	}
	return &HTTPParser{
		re:     regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"`),
		source: sourceLabel,
	}
}

func (p *HTTPParser) Parse(line string) *ParsedEvent {
	matches := p.re.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	// 1=IP, 2=User, 3=Time, 4=Method, 5=URL, 6=Proto, 7=Status, 8=Size, 9=Ref, 10=UA
	ip := matches[1]
	// user := matches[2] // often "-"
	method := matches[4]
	url := matches[5]
	statusStr := matches[7]
	ua := matches[10]

	statusCode, _ := strconv.Atoi(statusStr)

	return &ParsedEvent{
		Source:     p.source,
		Type:       "http_request",
		IP:         ip,
		Method:     method,
		URL:        url,
		StatusCode: statusCode,
		UserAgent:  ua,
		Raw:        line,
	}
}
