# 🔐 DNS Lookup Tool with Digital Key System

A secure DNS auditing tool with enterprise-grade key management and access control.

## 🚀 Features

### 🔍 DNS Capabilities
- Multi-record DNS lookups (A, AAAA, MX, TXT, NS, SOA, CNAME)
- Comprehensive domain auditing
- WHOIS information retrieval
- JSON export functionality
- Customizable DNS servers

### 🔐 Security Features
- Digital key generation and validation
- Time-based key expiry
- Automatic system locking
- Encrypted key storage
- Access audit logging
- Brute-force protection

### 📊 Logging & Monitoring
- Detailed access logs
- Usage tracking
- Failed attempt monitoring
- JSON export capabilities

## 📋 Prerequisites

```bash
# Required tools
dig      # DNS lookup utility
openssl  # Encryption
whois    # Domain information (optional)

# Install on Ubuntu/Debian
sudo apt-get update
sudo apt-get install dnsutils openssl whois
