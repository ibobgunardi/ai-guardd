# ai-guardd

> **Status**: Feature Complete (v1.0 Candidate)

**ai-guardd** is a Linux-native, privacy-first AI security agent designed for VPS and servers. It operates locally, analyzing system logs to detect suspicious behavior, explain risks, and suggest actions without ever sending data off-server by default.

## Core Principles

- **Local-Only**: No data leaves the server (unless Discord notifications are enabled).
- **Read-Only Advisor**: Suggests actions, never acts autonomously (unless Active Defense is enabled).
- **Explainable**: Specific reasons provided for every alert.
- **Lightweight**: Written in Go, consumes minimal resources.

## Features

- **Detection**:
    - **SSH Brute Force**: Detects repeated failures and "low-and-slow" attacks.
    - **Root Login**: Alerts on any successful root login.
    - **Web Scanning**: Detects 404 floods and probing on Apache/Nginx.
    - **Database Attacks**: Detects MySQL/MariaDB brute force attempts via Syslog.
- **Active Defense**: Optional `iptables` banning of malicious IPs.
- **Notifications**: Real-time alerts via Discord Webhooks.
- **Anti-Spoofing**: Verifies logs against Systemd Journal UID to prevent injection.

## Installation (Linux)

**ai-guardd** is designed to run as a systemd service on bare-metal Linux (Ubuntu/Debian).

1.  **Build**:
    ```bash
    go build -o ai-guardd ./cmd/ai-guardd
    ```
2.  **Install**:
    ```bash
    sudo mv ai-guardd /usr/local/bin/
    sudo mkdir -p /etc/ai-guardd
    sudo cp config/config.yml /etc/ai-guardd/
    ```
3.  **Configure**:
    Edit `/etc/ai-guardd/config.yml`:
    ```yaml
    input:
      auth_log_path: "/var/log/auth.log"
      web_log_path: "/var/log/apache2/access.log" # OR /var/log/nginx/access.log
      syslog_path: "/var/log/syslog"
    
    detection:
      active_defense: true # Set to false for Advisory Mode
    
    notification:
      discord_webhook: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
    ```
4.  **Run**:
    ```bash
    sudo cp systemd/ai-guardd.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now ai-guardd
    ```

## Apache vs Nginx Support

**ai-guardd** supports both Apache and Nginx out of the box because they both use the **Combined Log Format (CLF)**.

-   **Configuration**: You simply need to point `web_log_path` in `config.yml` to your server's access log.
    -   Apache: Usually `/var/log/apache2/access.log`
    -   Nginx: Usually `/var/log/nginx/access.log`
-   **Detection**: The agent automatically parses the logs regardless of the server type.

## Docker Support

**Do we use Docker?**
-   **For Development**: Yes. We use Docker (`docker-compose.dev.yml`) to *simulate* a Linux environment on Windows/Mac and run integration tests.
-   **For Production**: No (Default). The agent is designed to run natively on the host to access `iptables` and system logs directly. However, it *can* run in a container if given `--net=host` and `--privileged` flags, but native systemd execution is recommended for simplicity.

## Security

See [SECURITY.md](SECURITY.md).
