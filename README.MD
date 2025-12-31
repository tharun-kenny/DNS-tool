# 🔐 DNS Lookup Tool with Digital Key System

A secure DNS auditing tool with enterprise-grade key management and access control.

## 🚀 Features

### 🔍 DNS Capabilities
- Multi-record DNS lookups (A, AAAA, MX, TXT, NS, SOA, CNAME)
- Comprehensive domain auditing
- WHOIS information retrieval
- JSON export functionality
- Customizable DNS servers

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install dnsutils openssl whois
```

**macOS:**
```bash
brew install bind openssl whois
```

**CentOS/RHEL:**
```bash
sudo yum install bind-utils openssl whois
```


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

```python 
# git clone 
```

## 📋 Prerequisites
```bash
# Required tools
dig      # DNS lookup utility
openssl  # Encryption
whois    # Domain information (optional)

# Install on Ubuntu/Debian
sudo apt-get update
sudo apt-get install dnsutils openssl whois
