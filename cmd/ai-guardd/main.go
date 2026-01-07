package main

import (
	"ai-guardd/internal/action"
	"ai-guardd/internal/audit"
	"ai-guardd/internal/config"
	"ai-guardd/internal/detect"
	"ai-guardd/internal/explain"
	"ai-guardd/internal/ingest"
	"ai-guardd/internal/metrics"
	"ai-guardd/internal/parser"
	"ai-guardd/internal/state"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "run":
		runCommand(os.Args[2:])
	case "audit":
		auditCommand(os.Args[2:])
	case "status":
		statusCommand()
	case "executor":
		executorCommand(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: ai-guardd <command> [flags]")
	fmt.Println("Commands:")
	fmt.Println("  run       Start the agent (Analyzer)")
	fmt.Println("  status    Check agent status")
	fmt.Println("  executor  Start the privileged executor (Requires root)")
}

func runCommand(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "/etc/ai-guardd/config.yml", "Path to config file")
	fs.Parse(args)

	// Load Config
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Printf("Starting ai-guardd [Safe Mode]...\n")
	fmt.Printf("Monitoring: %s\n", cfg.Input.AuthLogPath)

	// Initialize Audit Logger
	auditLogger := audit.NewLogger(cfg.Output.AuditLogPath)

	// Initialize Components
	sshParser := parser.NewSSHParser()
	detector := detect.NewEngine(cfg.Detection.Rules)

	// Initialize State Store
	stateStore, err := state.NewStore("ai-guardd.db")
	if err != nil {
		log.Printf("[ERROR] Failed to initialize state store: %v", err)
	} else {
		defer stateStore.Close()
		vectors, err := stateStore.LoadAll()
		if err == nil {
			detector.LoadState(vectors)
			log.Printf("[STATE] Restored %d entities from database", len(vectors))
		}
	}
	// Initialize Ingest
	// 1. Auth Log Tailer
	tailer := ingest.NewFileTailer(cfg.Input.AuthLogPath)
	fileChan, err := tailer.Start()
	if err != nil {
		log.Fatalf("Failed to start auth tailer: %v", err)
	}

	// 1b. Syslog Tailer (MySQL/Sudo)
	var syslogChan <-chan ingest.LogLine
	if cfg.Input.SyslogPath != "" {
		syslogTailer := ingest.NewFileTailer(cfg.Input.SyslogPath)
		ch, err := syslogTailer.Start()
		if err != nil {
			log.Printf("Warning: Failed to start syslog tailer: %v", err)
		} else {
			syslogChan = ch
		}
	}

	// 1c. Web Log Tailer (Nginx/Apache)
	var webChan <-chan ingest.LogLine
	if cfg.Input.WebLogPath != "" {
		webTailer := ingest.NewFileTailer(cfg.Input.WebLogPath)
		ch, err := webTailer.Start()
		if err != nil {
			log.Printf("Warning: Failed to start web tailer: %v", err)
		} else {
			webChan = ch
		}
	}

	// 2. Journald (Optional)
	var journalChan <-chan ingest.LogLine
	if cfg.Input.EnableJournal {
		fmt.Println("Starting Journald Monitor...")
		j := ingest.NewJournalReader()
		ch, err := j.Start()
		if err != nil {
			log.Printf("Warning: Failed to start journald: %v", err)
		} else {
			journalChan = ch
		}
	}

	// Initialize Explainer
	var explainer explain.Explainer
	if cfg.Detection.EnableLocalLLM {
		fmt.Printf("Enabling Local LLM Integration (%s)...\n", cfg.Detection.LocalLLMModel)
		explainer = explain.NewLLMExplainer(cfg.Detection.LocalLLMUrl, cfg.Detection.LocalLLMModel)
	} else {
		explainer = explain.NewTemplateExplainer()
	}
	templateFallback := explain.NewTemplateExplainer() // Always have fallback

	// Initialize Action Broker
	broker := action.NewBroker(cfg.Detection.ActiveDefense, cfg.Detection.Allowlist, cfg.Notification.DiscordWebhook, cfg.Action.ExecutorSocket)

	// Start Prometheus metrics server
	go func() {
		log.Println("[METRICS] Starting on :9090")
		if err := metrics.StartServer(":9090"); err != nil {
			log.Printf("[METRICS] Failed to start: %v", err)
		}
	}()

	// Main Loop
	var wg sync.WaitGroup
	wg.Add(1)

	// Initialize Parsers
	syslogParser := parser.NewSyslogParser()
	httpParser := parser.NewHTTPParser("web_server") // Generic label, or could be "apache"/"nginx" if we knew

	go func() {
		defer wg.Done()

		// Aggregation Loop
		for {
			var msg ingest.LogLine
			var ok bool

			select {
			case msg, ok = <-fileChan:
				if !ok {
					fileChan = nil
				}
			case msg, ok = <-syslogChan:
				if !ok {
					syslogChan = nil
				}
			case msg, ok = <-webChan:
				if !ok {
					webChan = nil
				}
			case msg, ok = <-journalChan:
				if !ok {
					journalChan = nil
				}
			}

			if fileChan == nil && syslogChan == nil && webChan == nil && journalChan == nil {
				return
			}
			if !ok {
				continue
			}

			// Parse
			var parsedEvt *parser.ParsedEvent

			// Detect Source Type
			switch msg.Source {
			case cfg.Input.AuthLogPath:
				parsedEvt = sshParser.Parse(msg.Content)
			case cfg.Input.WebLogPath:
				parsedEvt = httpParser.Parse(msg.Content)
			case cfg.Input.SyslogPath:
				parsedEvt = syslogParser.Parse(msg.Content)
			default:
				// Fallback or Journald
				if cfg.Input.EnableJournal && (msg.Source == "sshd" || msg.Source == "ssh") {
					parsedEvt = sshParser.Parse(msg.Content)
				} else {
					// Assume SSH for unknown sources in MVP? Or ignore.
					// Let's safe ignore to avoid noise.
					// parsedEvt = sshParser.Parse(msg.Content)
				}
			}

			if parsedEvt != nil {
				// Increment events processed
				metrics.EventsProcessed.Inc()

				// Detect
				alert := detector.ProcessEvent(parsedEvt)
				if alert != nil {
					// Explain
					err := explainer.Explain(alert)
					if err != nil {
						templateFallback.Explain(alert)
					}

					// Track metrics
					metrics.AlertsGenerated.WithLabelValues(string(alert.Risk)).Inc()
					if alert.SuggestedAction != nil && alert.SuggestedAction.Type == "ban_ip" {
						metrics.IPsBanned.Inc()
					}

					// Act (NOW PASS POINTER TO EVENT)
					broker.Execute(alert)

					// Log
					if err := auditLogger.LogEvent(*alert); err != nil {
						log.Printf("Failed to write to audit log: %v", err)
					}

					// Print
					// Sanitize output to prevent terminal injection
					safeSummary := sanitize(alert.Summary)
					safeExplanation := sanitize(alert.Explanation)
					safeAction := sanitize(fmt.Sprintf("%s %s (%s)", alert.SuggestedAction.Type, alert.SuggestedAction.Target, alert.SuggestedAction.Duration))

					fmt.Printf("\n[ALERT] Risk: %s | %s\n", alert.Risk, safeSummary)
					fmt.Printf("Explain: %s\n", safeExplanation)
					fmt.Printf("Action: %s\n", safeAction)
				}
			}
		}
	}()

	// Signal Handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			log.Println("[CONFIG] SIGHUP received, reloading configuration...")
			newCfg, err := config.LoadConfig(*configPath)
			if err != nil {
				log.Printf("[ERROR] Failed to reload config: %v", err)
				continue
			}
			// Update components dynamically
			broker.UpdateConfig(newCfg.Detection.ActiveDefense, newCfg.Detection.Allowlist, newCfg.Notification.DiscordWebhook, newCfg.Action.ExecutorSocket)

			// Track config reload
			metrics.ConfigReloads.Inc()

			// Save state on reload too
			if stateStore != nil {
				stateStore.SaveAll(detector.GetState())
			}

			// Note: Updating log paths requires restarting tailers, which is more complex.
			// For now, we update the core detection and notification settings.
			cfg = newCfg
			log.Println("[CONFIG] Reload successful")
		} else {
			fmt.Println("\nShutting down...")
			if stateStore != nil {
				log.Println("[STATE] Saving state before exit...")
				stateStore.SaveAll(detector.GetState())
			}
			break
		}
	}

	tailer.Stop()
	wg.Wait()
	fmt.Println("Shutdown complete.")
}

// sanitize strips control characters (except newline) to prevent terminal injection
func sanitize(s string) string {
	var builder strings.Builder
	for _, r := range s {
		// Allow printable characters, newline, and tab
		if r >= 32 || r == '\n' || r == '\t' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func auditCommand(args []string) {
	// Simple implementation: tail the audit log
	// In production, this would read structured JSON and pretty-print
	fmt.Println("Reading audit log...")
	// TODO: Load config to find audit trail path or pass as flag
	content, err := os.ReadFile("audit.log")
	if err != nil {
		fmt.Printf("Error reading audit log: %v\n", err)
		return
	}
	fmt.Println(string(content))
}

func statusCommand() {
	// Check if process is running (requires PID file pattern)
	// For now, placeholder
	fmt.Println("Agent status: Unknown (PID file not implemented)")
}

func executorCommand(args []string) {
	fs := flag.NewFlagSet("executor", flag.ExitOnError)
	configPath := fs.String("config", "/etc/ai-guardd/config.yml", "Path to config file")
	fs.Parse(args)

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Action.ExecutorSocket == "" {
		fmt.Println("Error: action.executor_socket not defined in config")
		os.Exit(1)
	}

	fmt.Printf("Starting Privileged Executor on %s...\n", cfg.Action.ExecutorSocket)
	e := action.NewExecutor(cfg.Action.ExecutorSocket)
	if err := e.Start(); err != nil {
		log.Fatalf("Executor failed: %v", err)
	}
}
