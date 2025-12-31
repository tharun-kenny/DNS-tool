#!/bin/bash

############################################################
# DNS Lookup Tool with Digital Key Security System
# GitHub Project: Secure DNS Auditor
# Author: Your Name
# License: MIT
############################################################

# Configuration
CONFIG_FILE="$(dirname "$0")/config.env"
LOG_DIR="$(dirname "$0")/logs"
KEY_MANAGER="$(dirname "$0")/key_manager.sh"
TODAY=$(date +%Y-%m-%d)
LOG_FILE="${LOG_DIR}/dns_audit_${TODAY}.log"
LOCK_FILE="/tmp/dns_tool.lock"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        echo -e "${RED}Configuration file not found. Creating default...${NC}"
        create_default_config
    fi
}

# Create default configuration
create_default_config() {
    cat > "$CONFIG_FILE" << 'EOF'
#!/bin/bash
# DNS Tool Configuration

# Security Settings
REQUIRE_KEY=true
MAX_ATTEMPTS=3
LOCKOUT_TIME=300 # 5 minutes in seconds

# DNS Settings
DEFAULT_DNS="8.8.8.8"
DNS_TYPES="A AAAA MX TXT NS SOA CNAME"
TIMEOUT=5

# Logging
LOG_LEVEL="INFO" # DEBUG, INFO, WARN, ERROR
LOG_RETENTION_DAYS=30

# Notification (optional)
EMAIL_NOTIFY=false
EMAIL_ADDRESS="admin@example.com"

# API Keys (for external DNS services)
IPINFO_TOKEN=""
SHODAN_KEY=""
EOF
    chmod 600 "$CONFIG_FILE"
    echo -e "${GREEN}Default configuration created.${NC}"
}

# Initialize directories
init_dirs() {
    mkdir -p "$LOG_DIR"
    mkdir -p "$(dirname "$0")/keys"
    mkdir -p "$(dirname "$0")/exports"
}

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Check log level
    case $LOG_LEVEL in
        DEBUG) [[ "$level" =~ ^(DEBUG|INFO|WARN|ERROR)$ ]] ;;
        INFO) [[ "$level" =~ ^(INFO|WARN|ERROR)$ ]] ;;
        WARN) [[ "$level" =~ ^(WARN|ERROR)$ ]] ;;
        ERROR) [[ "$level" =~ ^(ERROR)$ ]] ;;
        *) [[ "$level" =~ ^(INFO|WARN|ERROR)$ ]] ;;
    esac || return 0
    
    echo -e "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Also print to console based on level
    case $level in
        ERROR) echo -e "${RED}[ERROR]${NC} $message" ;;
        WARN) echo -e "${YELLOW}[WARN]${NC} $message" ;;
        INFO) echo -e "${GREEN}[INFO]${NC} $message" ;;
        DEBUG) echo -e "${BLUE}[DEBUG]${NC} $message" ;;
    esac
}

# Check if tool is locked
check_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local lock_time=$(stat -c %Y "$LOCK_FILE" 2>/dev/null || echo 0)
        local current_time=$(date +%s)
        local lockout_age=$((current_time - lock_time))
        
        if [ $lockout_age -lt $LOCKOUT_TIME ]; then
            local remaining=$((LOCKOUT_TIME - lockout_age))
            log_message "ERROR" "Tool is locked. Try again in ${remaining} seconds."
            exit 1
        else
            rm -f "$LOCK_FILE"
        fi
    fi
}

# Key verification
verify_key() {
    if [ "$REQUIRE_KEY" = true ]; then
        if [ ! -x "$KEY_MANAGER" ]; then
            log_message "ERROR" "Key manager not found or not executable"
            exit 1
        fi
        
        # Check if user has active key
        local user_key_status=$("$KEY_MANAGER" --check)
        
        if [ "$user_key_status" != "VALID" ]; then
            log_message "WARN" "No valid key found. Please unlock first."
            "$KEY_MANAGER" --unlock
            if [ $? -ne 0 ]; then
                log_message "ERROR" "Failed to unlock. Exiting."
                exit 1
            fi
        fi
        
        # Log key usage
        "$KEY_MANAGER" --log-usage "DNS Lookup"
    fi
}

# Perform DNS lookup
dns_lookup() {
    local domain="$1"
    local record_type="${2:-A}"
    
    log_message "INFO" "Starting DNS lookup for $domain ($record_type)"
    
    # Check if domain is valid
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        log_message "ERROR" "Invalid domain format: $domain"
        return 1
    fi
    
    # Perform dig lookup with timeout
    local result
    result=$(timeout $TIMEOUT dig @"$DEFAULT_DNS" "$domain" "$record_type" +short 2>&1)
    local exit_code=$?
    
    if [ $exit_code -eq 124 ]; then
        log_message "ERROR" "DNS lookup timed out for $domain"
        echo "TIMEOUT"
        return 1
    elif [ $exit_code -ne 0 ]; then
        log_message "ERROR" "DNS lookup failed for $domain: $result"
        echo "FAILED"
        return 1
    fi
    
    if [ -z "$result" ]; then
        echo "NO_RECORDS"
        log_message "INFO" "No $record_type records found for $domain"
    else
        echo "$result"
        log_message "INFO" "Found $record_type records for $domain"
    fi
}

# Comprehensive domain audit
domain_audit() {
    local domain="$1"
    
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${GREEN}DNS Audit Report for: $domain${NC}"
    echo -e "${BLUE}========================================${NC}\n"
    
    log_message "INFO" "Starting comprehensive audit for $domain"
    
    # Test each DNS record type
    for type in $DNS_TYPES; do
        echo -e "${YELLOW}[$type] Records:${NC}"
        local records=$(dns_lookup "$domain" "$type")
        
        if [ "$records" != "NO_RECORDS" ] && [ "$records" != "FAILED" ] && [ "$records" != "TIMEOUT" ]; then
            echo "$records"
            echo ""
        else
            echo "None found"
            echo ""
        fi
    done
    
    # Get WHOIS information (if available)
    echo -e "${YELLOW}[WHOIS] Information:${NC}"
    if command -v whois &> /dev/null; then
        timeout 10 whois "$domain" | head -20 2>/dev/null || echo "WHOIS lookup failed/limited"
    else
        echo "whois command not available"
    fi
    
    log_message "INFO" "Completed audit for $domain"
}

# Export results to JSON
export_json() {
    local domain="$1"
    local output_file="$(dirname "$0")/exports/${domain}_$(date +%Y%m%d_%H%M%S).json"
    
    log_message "INFO" "Exporting results to JSON: $output_file"
    
    cat > "$output_file" << EOF
{
  "domain": "$domain",
  "audit_date": "$(date -Iseconds)",
  "dns_records": {
EOF
    
    local first=true
    for type in $DNS_TYPES; do
        if [ "$first" != true ]; then
            echo "    }," >> "$output_file"
        fi
        first=false
        
        local records=$(dns_lookup "$domain" "$type" | tr '\n' ',' | sed 's/,$//')
        
        cat >> "$output_file" << EOF
    "$type": {
      "values": [$records]
EOF
    done
    
    cat >> "$output_file" << EOF
    }
  }
}
EOF
    
    echo -e "${GREEN}Results exported to: $output_file${NC}"
    log_message "INFO" "Export completed: $output_file"
}

# Show usage
usage() {
    echo -e "${BLUE}DNS Lookup Tool with Digital Key Security${NC}"
    echo "Usage: $0 [OPTIONS] <domain>"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -d, --domain DOMAIN  Domain to lookup (required)"
    echo "  -t, --type TYPE      DNS record type (default: A)"
    echo "  -a, --audit          Perform comprehensive domain audit"
    echo "  -j, --json           Export results as JSON"
    echo "  --unlock             Unlock with digital key"
    echo "  --lock               Lock the tool"
    echo "  --status             Show tool status"
    echo ""
    echo "Examples:"
    echo "  $0 -d example.com"
    echo "  $0 -d example.com -t MX"
    echo "  $0 -d example.com -a"
    echo "  $0 --unlock"
    echo ""
    echo "Available DNS types: $DNS_TYPES"
}

# Main function
main() {
    # Initialize
    load_config
    init_dirs
    check_lock
    
    # Parse arguments
    local domain=""
    local record_type="A"
    local do_audit=false
    local export_json=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            --unlock)
                "$KEY_MANAGER" --unlock
                exit $?
                ;;
            --lock)
                "$KEY_MANAGER" --lock
                exit $?
                ;;
            --status)
                "$KEY_MANAGER" --status
                exit $?
                ;;
            -d|--domain)
                domain="$2"
                shift 2
                ;;
            -t|--type)
                record_type="$2"
                shift 2
                ;;
            -a|--audit)
                do_audit=true
                shift
                ;;
            -j|--json)
                export_json=true
                shift
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                usage
                exit 1
                ;;
        esac
    done
    
    # Verify key if required
    verify_key
    
    # Check domain
    if [ -z "$domain" ] && [ $do_audit = false ]; then
        echo -e "${RED}Error: Domain is required${NC}"
        usage
        exit 1
    fi
    
    # Perform actions
    if [ $do_audit = true ]; then
        domain_audit "$domain"
    else
        echo -e "${GREEN}DNS Lookup Results for $domain ($record_type):${NC}"
        dns_lookup "$domain" "$record_type"
    fi
    
    # Export if requested
    if [ $export_json = true ]; then
        export_json "$domain"
    fi
    
    log_message "INFO" "Script execution completed"
}

# Handle script termination
cleanup() {
    log_message "DEBUG" "Cleaning up..."
    rm -f "$LOCK_FILE"
}

# Set trap for cleanup
trap cleanup EXIT

# Run main function
main "$@"
