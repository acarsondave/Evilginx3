# Evilginx3 Repository Analysis

## 📋 Executive Summary

**Evilginx 3.3.1 - Private Dev Edition** is an advanced man-in-the-middle (MITM) attack framework designed for authorized penetration testing and red team engagements. This private development edition extends the standard Evilginx 3.3 with enterprise-grade evasion, detection, and operational features.

**Repository Type:** Security Tool / Penetration Testing Framework  
**Language:** Go (Golang)  
**Version:** 3.3.1 - Private Dev Edition  
**License:** BSD-3 Clause  
**Modified By:** AKaZA (Akz0fuku)  
**Original Author:** Kuba Gretzky

---

## 🏗️ Repository Structure

```
Evilginx3/
├── core/                    # Core functionality modules
│   ├── banner.go            # Application banner
│   ├── blacklist.go         # IP blacklisting
│   ├── botguard.go          # Bot protection
│   ├── c2_channel.go        # Command & control channel
│   ├── captcha_provider.go  # CAPTCHA integration
│   ├── certdb.go            # Certificate database
│   ├── cloudflare_worker_api.go  # Cloudflare API integration
│   ├── cloudflare_worker.go      # Cloudflare Worker support
│   ├── config.go            # Configuration management
│   ├── dns_provider.go      # DNS provider abstraction
│   ├── dns_providers/       # DNS provider implementations
│   │   └── cloudflare.go    # Cloudflare DNS provider
│   ├── domain_rotation.go   # Domain rotation logic
│   ├── feature_extractor.go # ML feature extraction
│   ├── gophish.go           # Gophish integration
│   ├── http_proxy.go        # HTTP proxy core
│   ├── http_server.go       # HTTP server
│   ├── ja3_fingerprint.go   # JA3/JA3S TLS fingerprinting
│   ├── ml_detector.go       # Machine learning bot detection
│   ├── nameserver.go        # DNS nameserver
│   ├── obfuscator.go        # Code obfuscation
│   ├── phishlet.go          # Phishlet management
│   ├── polymorphic_engine.go # Polymorphic JavaScript engine
│   ├── sandbox_detector.go  # Sandbox/VM detection
│   ├── session_formatter.go # Session data formatting
│   ├── session.go           # Session management
│   ├── shared.go            # Shared utilities
│   ├── table.go             # Table display utilities
│   ├── telegram_exporter.go # Telegram export functionality
│   ├── telegram.go          # Telegram integration
│   ├── terminal.go          # Interactive terminal
│   ├── tls_interceptor.go   # TLS interception
│   ├── traffic_shaper.go    # Traffic shaping/rate limiting
│   ├── utils.go             # Utility functions
│   └── whitelist.go         # IP whitelisting
├── database/                # Database layer
│   ├── database.go          # Database interface
│   └── db_session.go        # Session storage
├── log/                     # Logging system
│   └── log.go               # Logging implementation
├── parser/                  # Parsing utilities
│   └── parser.go            # General parser
├── phishlets/               # Phishlet templates (23 total)
│   ├── adobe.yaml
│   ├── amazon.yaml
│   ├── apple.yaml
│   ├── booking.yaml
│   ├── coinbase.yaml
│   ├── discord.yaml
│   ├── docusign.yaml
│   ├── dropbox.yaml
│   ├── example.yaml         # Template example
│   ├── facebook.yaml
│   ├── github.yaml
│   ├── google.yaml
│   ├── instagram.yaml
│   ├── linkedin.yaml
│   ├── netflix.yaml
│   ├── o365.yaml            # Office 365
│   ├── okta.yaml
│   ├── paypal.yaml
│   ├── salesforce.yaml
│   ├── slack.yaml
│   ├── spotify.yaml
│   ├── telegram.yaml
│   ├── twitter.yaml
│   └── zoom.yaml
├── redirectors/             # HTML redirector pages
│   ├── [service]_turnstile/ # Cloudflare Turnstile redirectors
│   └── download_example/    # Download redirector example
├── install.sh               # Linux one-click installer (970 lines)
├── install-windows.ps1      # Windows installer
├── main.go                  # Application entry point
├── go.mod                   # Go dependencies
├── go.sum                   # Dependency checksums
├── Makefile                 # Build automation
├── LICENSE                  # BSD-3 Clause license
└── README.md                # Comprehensive documentation
```

---

## 🎯 Core Features

### 1. **Basic MITM Proxy**
- HTTP/HTTPS interception and proxying
- Real-time request/response modification
- Session cookie capture
- 2FA bypass through session hijacking

### 2. **Phishlet System**
- 23 pre-built phishlets for popular services:
  - **Enterprise:** Office 365, Okta, Salesforce, DocuSign
  - **Social Media:** Facebook, Twitter, Instagram, LinkedIn, Discord
  - **Cloud Services:** Google, GitHub, Dropbox, Adobe
  - **E-commerce:** Amazon, PayPal, Coinbase
  - **Entertainment:** Netflix, Spotify
  - **Communication:** Slack, Telegram, Zoom
  - **Travel:** Booking.com
- YAML-based configuration
- Custom phishlet creation support
- Subdomain filtering and replacement

### 3. **Gophish Integration**
- Seamless integration with Gophish phishing framework
- Campaign management
- Email template support
- Click tracking

---

## 🛡️ Advanced Features (Private Dev Edition)

### 1. **Machine Learning Bot Detection** (`core/ml_detector.go`)

**Purpose:** AI-powered detection of automated bots and security scanners

**Capabilities:**
- **Feature Extraction:**
  - HTTP header analysis (count, order, presence)
  - User-Agent length and patterns
  - Timing patterns (request intervals, time on site)
  - Behavioral metrics (mouse movements, keystrokes, scroll depth)
  - Network fingerprinting (connection reuse, HTTP/2, TLS version)
  - JA3 hash integration
  - Header order analysis

- **ML Model:**
  - Pre-trained weights and bias
  - Feature scaling and normalization
  - Confidence-based scoring
  - Learning mode for adaptation

- **Performance:**
  - Caching system (30-minute default)
  - Thread-safe operations
  - Statistics tracking
  - Low-latency detection

**Configuration:**
```json
{
  "ml_detection": {
    "enabled": true,
    "threshold": 0.75,
    "learning_mode": true,
    "cache_duration": 30
  }
}
```

---

### 2. **JA3/JA3S TLS Fingerprinting** (`core/ja3_fingerprint.go`)

**Purpose:** Detect and block automated tools based on TLS handshake fingerprints

**Detected Tools:**
- Python requests library
- Golang HTTP clients
- curl variations (multiple versions)
- Scrapy framework
- Headless browsers (Puppeteer, Selenium)
- Security scanners (Burp Suite, OWASP ZAP, etc.)

**Features:**
- Real-time TLS handshake capture
- JA3 hash calculation (client fingerprint)
- JA3S hash calculation (server fingerprint)
- Known bot signature database (pre-loaded)
- Custom signature addition
- Confidence scoring
- Caching for performance

**Implementation:**
- Custom TLS listener wrapper
- ClientHelloInfo extraction
- MD5 hash generation
- Signature matching algorithm

---

### 3. **Sandbox Detection** (`core/sandbox_detector.go`)

**Purpose:** Multi-layer detection of VM environments and analysis tools

**Detection Methods:**

**Server-Side:**
- IP reputation checking
- Request pattern analysis
- Timing anomalies
- User-Agent analysis
- Header inconsistencies

**Client-Side (JavaScript):**
- VM environment detection (VMware, VirtualBox, QEMU, etc.)
- Debugger presence detection
- Automation tool detection (Selenium, Puppeteer)
- Hardware fingerprinting
- Timing-based detection
- Artifact checking

**Modes:**
- **Passive:** Silent detection, logging only
- **Active:** Challenge-response tests
- **Aggressive:** Multi-stage verification with honeypots

**Actions on Detection:**
- Block access
- Redirect to honeypot
- Serve fake content
- Log and alert

**Configuration:**
```json
{
  "sandbox_detection": {
    "enabled": true,
    "mode": "active",
    "action_on_detection": "redirect",
    "detection_threshold": 0.7
  }
}
```

---

### 4. **Polymorphic JavaScript Engine** (`core/polymorphic_engine.go`)

**Purpose:** Dynamic code mutation to evade signature-based detection

**Mutation Techniques:**
- Variable/function name randomization
- Code structure modification
- Dead code injection
- Control flow obfuscation
- String encoding (base64, hex, unicode)
- Expression rewriting
- Comment injection/removal

**Mutation Levels:**
- **Low:** Basic variable renaming
- **Medium:** Structure modification + renaming
- **High:** Advanced obfuscation + control flow changes
- **Extreme:** Maximum mutation with semantic preservation

**Features:**
- Template-based mutation
- Seed-based randomization
- Cache system for performance
- Statistics tracking
- Semantic preservation option

**Configuration:**
```json
{
  "polymorphic_engine": {
    "enabled": true,
    "mutation_level": "high",
    "seed_rotation": 15,
    "preserve_semantics": true
  }
}
```

---

### 5. **Domain Rotation** (`core/domain_rotation.go`)

**Purpose:** Automated domain management and rotation for evasion

**Strategies:**
- **Round-robin:** Sequential rotation through domains
- **Weighted:** Priority-based selection
- **Health-based:** Availability monitoring with failover
- **Random:** Unpredictable rotation

**Features:**
- Automatic domain generation
- DNS provider integration (Cloudflare)
- Health monitoring
- Automatic failover
- Certificate management
- Rotation interval configuration

**Use Cases:**
- Evading domain reputation systems
- Distributing load
- Maintaining availability
- Burner domain management

---

### 6. **Traffic Shaping** (`core/traffic_shaper.go`)

**Purpose:** Intelligent traffic management and DDoS protection

**Capabilities:**
- **Rate Limiting:**
  - Per-IP rate limiting
  - Global bandwidth controls
  - Burst size configuration
  - Queue management

- **Geographic Rules:**
  - Country-based filtering
  - IP range restrictions
  - ASN-based rules

- **DDoS Protection:**
  - SYN flood protection
  - Slowloris mitigation
  - Amplification attack detection
  - Automatic blacklisting

- **Adaptive Learning:**
  - Pattern recognition
  - Automatic threshold adjustment
  - Priority queuing

**Configuration:**
```json
{
  "traffic_shaping": {
    "enabled": true,
    "per_ip_rate_limit": 100,
    "ddos_protection": true,
    "burst_size": 200
  }
}
```

---

### 7. **C2 Channel** (`core/c2_channel.go`)

**Purpose:** Encrypted command and control infrastructure

**Features:**
- **Transport Protocols:**
  - HTTPS (primary)
  - DNS tunneling (fallback)
  - Proxy support

- **Security:**
  - AES-256 encryption
  - Perfect forward secrecy
  - HMAC message authentication
  - Anti-replay protection
  - Traffic obfuscation

- **Functionality:**
  - Command queue management
  - Compression support
  - Heartbeat mechanism
  - Automatic reconnection

**Use Cases:**
- Remote campaign control
- Secure data exfiltration
- Operational security
- Multi-stage operations

---

### 8. **Cloudflare Worker Integration** (`core/cloudflare_worker.go`, `core/cloudflare_worker_api.go`)

**Purpose:** Deploy phishing infrastructure behind Cloudflare Workers

**Benefits:**
- IP address protection (hides server IP)
- DDoS mitigation
- Global CDN distribution
- SSL/TLS termination
- Rate limiting
- Caching control
- WAF bypass capabilities

**Features:**
- Cloudflare API integration
- Worker script generation
- Automatic deployment
- Configuration management

---

### 9. **Enhanced Telegram Integration** (`core/telegram.go`, `core/telegram_exporter.go`)

**Purpose:** Real-time notifications and data exfiltration

**Features:**
- Captured credential alerts
- Session cookie export
- Screenshot delivery (if implemented)
- Campaign statistics
- Error notifications
- Remote control commands
- Formatted session data export

**Configuration:**
```json
{
  "telegram": {
    "enabled": true,
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID"
  }
}
```

---

### 10. **Advanced Obfuscation** (`core/obfuscator.go`)

**Purpose:** Multi-layer code and traffic obfuscation

**Techniques:**
- JavaScript obfuscation
- HTML structure randomization
- CSS class name mutation
- Network traffic padding
- Timing randomization
- String encoding
- Control flow flattening

---

### 11. **TLS Interception** (`core/tls_interceptor.go`)

**Purpose:** Advanced certificate management and TLS handling

**Features:**
- Automatic certificate generation (Let's Encrypt)
- Certificate database management
- SNI-based routing
- Custom certificate support
- Certificate rotation
- Developer mode (self-signed certs)

---

### 12. **DNS Provider Abstraction** (`core/dns_provider.go`, `core/dns_providers/cloudflare.go`)

**Purpose:** Automated DNS record management

**Supported Providers:**
- Cloudflare (implemented)
- Extensible architecture for other providers

**Features:**
- Automatic A record creation
- TXT record management (for ACME challenges)
- Record deletion
- Health checking

---

## 🔧 Installation & Deployment

### Linux Installation (`install.sh`)

**Automated One-Click Installer (970 lines):**

**What it does:**
1. ✅ System package updates
2. ✅ Dependency installation (Go 1.22, build tools, etc.)
3. ✅ Go installation and PATH configuration
4. ✅ Directory creation (`/opt/evilginx`, `/etc/evilginx`, `/var/log/evilginx`)
5. ✅ Stops conflicting services (Apache2, Nginx, systemd-resolved)
6. ✅ Disables systemd-resolved (frees port 53)
7. ✅ Builds Evilginx from source
8. ✅ Installs binary and phishlets
9. ✅ Configures UFW firewall (ports 22, 53, 80, 443)
10. ✅ Sets up Fail2Ban
11. ✅ Creates systemd service
12. ✅ Sets binary capabilities (CAP_NET_BIND_SERVICE)
13. ✅ Creates helper scripts (`evilginx-start`, `evilginx-stop`, etc.)

**Helper Scripts Created:**
- `evilginx-start` - Start service
- `evilginx-stop` - Stop service
- `evilginx-restart` - Restart service
- `evilginx-status` - Check status
- `evilginx-logs` - View logs
- `evilginx-console` - Interactive console

**Installation Paths:**
- Binary: `/opt/evilginx/evilginx.bin`
- Wrapper: `/usr/local/bin/evilginx`
- Phishlets: `/opt/evilginx/phishlets`
- Redirectors: `/opt/evilginx/redirectors`
- Config: `/etc/evilginx`
- Logs: `/var/log/evilginx`

### Windows Installation (`install-windows.ps1`)

**Features:**
- Go 1.22 installation
- Source compilation
- NSSM service installation
- Windows Firewall configuration
- Service auto-start
- Helper commands

---

## 📊 Technical Architecture

### Language & Dependencies

**Language:** Go 1.22+

**Key Dependencies:**
- `github.com/caddyserver/certmagic` - Automatic certificate management
- `github.com/elazarl/goproxy` - HTTP proxy functionality
- `github.com/miekg/dns` - DNS server implementation
- `github.com/go-acme/lego/v3` - Let's Encrypt ACME client
- `github.com/go-resty/resty/v2` - HTTP client
- `github.com/tidwall/buntdb` - Embedded database
- `go.uber.org/zap` - Structured logging
- `golang.org/x/crypto` - Cryptographic functions
- `golang.org/x/time` - Rate limiting

### Database

- **Type:** BuntDB (embedded key-value database)
- **Location:** `~/.evilginx/data.db`
- **Stores:**
  - Sessions
  - Lures
  - Configuration
  - Statistics

### Configuration System

- **Format:** JSON
- **Location:** `~/.evilginx/config.json`
- **Features:**
  - Hot-reloading
  - Validation
  - Default values
  - Environment variable support

### Logging System

- **Format:** Structured logging (zap)
- **Levels:** Debug, Info, Warning, Error
- **Outputs:**
  - Console (colored)
  - File (`~/.evilginx/logs/`)
  - Systemd journal (when running as service)

---

## 🎮 Usage Workflow

### Basic Campaign Setup

```bash
# 1. Start Evilginx
sudo evilginx

# 2. Configure domain and IP
config domain yourdomain.com
config ipv4 123.45.67.89
config autocert on

# 3. Enable phishlet
phishlets hostname o365 login.yourdomain.com
phishlets enable o365

# 4. Create lure
lures create o365
lures edit 0 redirect_url https://office.com
lures get-url 0
```

### Advanced Campaign with All Features

```bash
# Enable ML detection
config ml_detection on
config ml_threshold 0.8

# Enable JA3 fingerprinting
config ja3_detection on

# Enable sandbox detection
config sandbox_detection on
config sandbox_mode aggressive

# Enable polymorphic engine
config polymorphic on
config mutation_level extreme

# Enable traffic shaping
config traffic_shaping on
config rate_limit 50

# Setup Telegram notifications
config telegram_token YOUR_BOT_TOKEN
config telegram_chat YOUR_CHAT_ID
config telegram on
```

---

## 🔒 Security Features

### Operational Security

1. **Infrastructure Isolation**
   - Dedicated VPS per campaign
   - Separate C2 infrastructure
   - VPN/proxy chains
   - Infrastructure burning after engagement

2. **Domain Management**
   - Privacy protection
   - Multiple registrars
   - Domain aging
   - Realistic naming

3. **Traffic Management**
   - Rate limiting
   - Geographic restrictions
   - IP whitelisting
   - Security researcher monitoring

4. **Data Protection**
   - Encrypted credentials
   - Secure channels
   - Automatic data destruction
   - Retention policies

### Detection Evasion

1. **ML Bot Detection** - Identifies and blocks automated tools
2. **JA3 Fingerprinting** - Blocks known security scanners
3. **Sandbox Detection** - Detects analysis environments
4. **Polymorphic Engine** - Evades signature detection
5. **Traffic Shaping** - Mimics legitimate traffic patterns
6. **Domain Rotation** - Evades reputation systems

---

## 📈 Feature Comparison

| Feature | Standard 3.3 | Private Dev Edition |
|---------|--------------|---------------------|
| Basic MITM Proxy | ✅ | ✅ |
| 2FA Bypass | ✅ | ✅ |
| Phishlet System | ✅ | ✅ |
| Gophish Integration | ✅ | ✅ |
| **ML Bot Detection** | ❌ | ✅ |
| **JA3 Fingerprinting** | ❌ | ✅ |
| **Sandbox Detection** | ❌ | ✅ |
| **Polymorphic Engine** | ❌ | ✅ |
| **Domain Rotation** | ❌ | ✅ |
| **Traffic Shaping** | ❌ | ✅ |
| **C2 Channel** | ❌ | ✅ |
| **Advanced Obfuscation** | ❌ | ✅ |
| **Cloudflare Workers** | ❌ | ✅ |
| **Enhanced Telegram** | ❌ | ✅ |

---

## 🎯 Use Cases

### Authorized Penetration Testing

1. **Phishing Campaigns**
   - Credential harvesting
   - Session hijacking
   - 2FA bypass testing
   - Social engineering assessment

2. **Red Team Operations**
   - Initial access simulation
   - Multi-stage attack chains
   - Infrastructure testing
   - Detection evasion testing

3. **Security Awareness Training**
   - Realistic phishing scenarios
   - User training
   - Click tracking
   - Reporting and metrics

### Research & Development

1. **Security Research**
   - Detection evasion techniques
   - TLS fingerprinting analysis
   - Bot detection algorithms
   - Sandbox detection methods

2. **Tool Development**
   - Phishlet creation
   - Custom integrations
   - Feature extensions
   - Testing frameworks

---

## ⚠️ Legal & Ethical Considerations

### Legal Requirements

- ✅ Written authorization from target organization
- ✅ Defined scope of engagement
- ✅ Compliance with local laws
- ✅ Proper data handling and destruction

### Ethical Guidelines

1. **Authorization**
   - Always get written permission
   - Define clear scope
   - Document everything
   - Follow rules of engagement

2. **Data Handling**
   - Minimize data collection
   - Encrypt all data
   - Secure transmission
   - Proper destruction

3. **Reporting**
   - Detailed documentation
   - Clear methodology
   - Recommendations
   - Remediation guidance

---

## 📚 Documentation

### Included Documentation

- `README.md` - Comprehensive project documentation
- `DEPLOYMENT_GUIDE.md` - Complete deployment guide (referenced)
- `BEST_PRACTICES.md` - Operational best practices (referenced)
- `SESSION_FORMATTING_GUIDE.md` - Session data formatting (referenced)
- `LINUX_VPS_SETUP.md` - VPS setup guide (referenced)
- `TELEGRAM_NOTIFICATIONS.md` - Telegram setup (referenced)
- `NEW_PHISHLETS_GUIDE.md` - Phishlet creation guide (referenced)

### Code Documentation

- Inline comments in Go code
- Function documentation
- Configuration examples
- Usage examples

---

## 🔍 Code Quality & Architecture

### Strengths

1. **Modular Design**
   - Clear separation of concerns
   - Reusable components
   - Extensible architecture

2. **Error Handling**
   - Comprehensive error checking
   - Graceful degradation
   - Detailed logging

3. **Performance**
   - Caching systems
   - Thread-safe operations
   - Efficient algorithms

4. **Security**
   - Input validation
   - Secure defaults
   - Capability-based permissions

### Areas for Improvement

1. **Testing**
   - Unit tests (not visible in structure)
   - Integration tests
   - End-to-end tests

2. **Documentation**
   - API documentation
   - Architecture diagrams
   - Deployment guides (some referenced but may not exist)

3. **Configuration**
   - Configuration validation
   - Schema documentation
   - Migration tools

---

## 🚀 Future Enhancements

### Potential Additions

1. **Additional DNS Providers**
   - AWS Route53
   - Google Cloud DNS
   - Azure DNS

2. **Enhanced ML Models**
   - Deep learning integration
   - Online learning
   - Transfer learning

3. **Advanced Analytics**
   - Real-time dashboards
   - Campaign metrics
   - Success rate tracking

4. **Integration Expansion**
   - Slack integration
   - Discord webhooks
   - Custom webhooks

---

## 📝 Summary

**Evilginx 3.3.1 - Private Dev Edition** is a sophisticated, feature-rich MITM framework designed for authorized security testing. The private development edition adds significant advanced capabilities including:

- **10+ Advanced Features** not in standard release
- **23 Pre-built Phishlets** for popular services
- **One-Click Installation** for Linux and Windows
- **Enterprise-Grade Evasion** capabilities
- **Comprehensive Documentation**

The codebase is well-structured, modular, and follows Go best practices. The advanced features demonstrate sophisticated security research and implementation, making this a powerful tool for red team operations and authorized penetration testing.

**⚠️ Important:** This tool must only be used with explicit written authorization and in compliance with all applicable laws and regulations.

---

**Analysis Date:** 2024  
**Repository Version:** 3.3.1 - Private Dev Edition  
**Analysis Scope:** Complete repository structure, features, and capabilities




