package parser

import "testing"

func TestHTTPParserParseCombinedLog(t *testing.T) {
	parser := NewHTTPParser("nginx")
	line := `198.51.100.10 - - [08/Jun/2026:03:14:15 +0000] "GET /health HTTP/1.1" 200 42 "-" "curl/8.0"`

	evt := parser.Parse(line)
	if evt == nil {
		t.Fatal("expected parsed event")
	}
	if evt.Source != "nginx" {
		t.Fatalf("Source = %q", evt.Source)
	}
	if evt.Type != "http_request" {
		t.Fatalf("Type = %q", evt.Type)
	}
	if evt.IP != "198.51.100.10" {
		t.Fatalf("IP = %q", evt.IP)
	}
	if evt.Method != "GET" {
		t.Fatalf("Method = %q", evt.Method)
	}
	if evt.URL != "/health" {
		t.Fatalf("URL = %q", evt.URL)
	}
	if evt.StatusCode != 200 {
		t.Fatalf("StatusCode = %d", evt.StatusCode)
	}
	if evt.UserAgent != "curl/8.0" {
		t.Fatalf("UserAgent = %q", evt.UserAgent)
	}
}

func TestHTTPParserParseDashResponseSize(t *testing.T) {
	parser := NewHTTPParser("")
	line := `203.0.113.25 - - [08/Jun/2026:03:15:00 +0000] "GET /.env HTTP/1.1" 404 - "-" "scanner"`

	evt := parser.Parse(line)
	if evt == nil {
		t.Fatal("expected dash-size log line to parse")
	}
	if evt.Source != "web_server" {
		t.Fatalf("Source = %q", evt.Source)
	}
	if evt.IP != "203.0.113.25" {
		t.Fatalf("IP = %q", evt.IP)
	}
	if evt.URL != "/.env" {
		t.Fatalf("URL = %q", evt.URL)
	}
	if evt.StatusCode != 404 {
		t.Fatalf("StatusCode = %d", evt.StatusCode)
	}
}

func TestHTTPParserParseCommonLog(t *testing.T) {
	parser := NewHTTPParser("apache")
	line := `192.0.2.55 - - [08/Jun/2026:03:16:00 +0000] "POST /login HTTP/1.1" 401 128`

	evt := parser.Parse(line)
	if evt == nil {
		t.Fatal("expected common log line to parse")
	}
	if evt.Source != "apache" {
		t.Fatalf("Source = %q", evt.Source)
	}
	if evt.IP != "192.0.2.55" {
		t.Fatalf("IP = %q", evt.IP)
	}
	if evt.Method != "POST" {
		t.Fatalf("Method = %q", evt.Method)
	}
	if evt.URL != "/login" {
		t.Fatalf("URL = %q", evt.URL)
	}
	if evt.StatusCode != 401 {
		t.Fatalf("StatusCode = %d", evt.StatusCode)
	}
	if evt.UserAgent != "" {
		t.Fatalf("UserAgent = %q", evt.UserAgent)
	}
}

func TestHTTPParserParseCommonLogDashResponseSize(t *testing.T) {
	parser := NewHTTPParser("nginx")
	line := `192.0.2.56 - - [08/Jun/2026:03:17:00 +0000] "GET /missing HTTP/2.0" 404 -`

	evt := parser.Parse(line)
	if evt == nil {
		t.Fatal("expected common log line with dash response size to parse")
	}
	if evt.IP != "192.0.2.56" {
		t.Fatalf("IP = %q", evt.IP)
	}
	if evt.URL != "/missing" {
		t.Fatalf("URL = %q", evt.URL)
	}
	if evt.StatusCode != 404 {
		t.Fatalf("StatusCode = %d", evt.StatusCode)
	}
}

func TestHTTPParserParseInvalidLine(t *testing.T) {
	parser := NewHTTPParser("apache")

	if evt := parser.Parse("not an access log entry"); evt != nil {
		t.Fatalf("expected invalid line to be ignored, got %#v", evt)
	}
}
