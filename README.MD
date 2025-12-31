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

## 🏁 Quick Start Tutorial
```bash
# Clone the Repository
git clone https://github.com/tharun-kenny/DNS-Lookup-Tool-with-Digital-Key-System/

# Navigate to Repository 
cd DNS-Lookup-Tool-with-Digital-Key-System/

# Make all script Executable 
chmod +x * 
```

## 📞 Need Help?

```bash
# Run Self-Diagnostic
./dns_tool.sh --help 
./key_manager.sh --help

#Check system status 
./key_manager.sh --status

#View Logs
tail -50 logs/access_*.log

# Create debug report
bash -x dns_tool.sh -d test.com 2>&1 | tee debug.log

```

## 🚨 Troubleshooting Common Issues
```bash 
# On Ubuntu/Debian
sudo apt install dnsutils

# Verify
which dig
dig google.com +short
```


