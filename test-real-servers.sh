#!/bin/bash
#
# Test roughenough client against real-world Roughtime servers.
# Server list is read from test-servers.txt
#
# Usage: ./test-real-servers.sh [server-file]
#
# CI-friendly: always exits 0, prints protocol dump on failures for debugging.
#

# Cleanup child processes on exit to prevent zombies
cleanup() {
    # Kill any child processes in our process group
    pkill -P $$ 2>/dev/null || true
}
trap cleanup EXIT INT TERM

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_FILE="${1:-$SCRIPT_DIR/test-servers.txt}"

# Build the client if needed
if [ ! -f target/debug/roughenough_client ]; then
    echo "Building roughenough_client..."
    cargo build --bin roughenough_client
fi

CLIENT="target/debug/roughenough_client"

# Colors for output (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Test result counters
PASSED=0
FAILED=0
SKIPPED=0

# Store failed servers for verbose retry
declare -a FAILED_SERVERS

# Test a server and report results
test_server() {
    local name="$1"
    local host="$2"
    local port="$3"
    local protocol="$4"
    local pubkey="$5"

    printf "${BLUE}%-25s${NC} %-35s %-10s " "$name" "$host:$port" "draft-$protocol"

    # Build command
    local cmd="$CLIENT $host $port -P $protocol"
    if [ -n "$pubkey" ]; then
        cmd="$cmd -k $pubkey"
    fi

    # Run the test
    local output
    output=$($cmd 2>&1)
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        local time_str
        time_str=$(echo "$output" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}" | head -1)
        if [ -n "$time_str" ]; then
            printf "${GREEN}PASS${NC}  %s\n" "$time_str"
        else
            printf "${GREEN}PASS${NC}\n"
        fi
        PASSED=$((PASSED + 1))
    else
        if echo "$output" | grep -qi "timeout"; then
            printf "${YELLOW}TIMEOUT${NC}\n"
            SKIPPED=$((SKIPPED + 1))
        else
            local err_msg
            err_msg=$(echo "$output" | grep -i "error" | head -1)
            if [ -z "$err_msg" ]; then
                err_msg=$(echo "$output" | tail -1)
            fi
            printf "${RED}FAIL${NC}  %s\n" "$err_msg"
            FAILED=$((FAILED + 1))
            # Store for verbose retry
            FAILED_SERVERS+=("$name|$host|$port|$protocol|$pubkey")
        fi
    fi
}

# Retry failed server with protocol dump
dump_retry() {
    local name="$1"
    local host="$2"
    local port="$3"
    local protocol="$4"
    local pubkey="$5"

    echo ""
    echo "--- $name ($host:$port) ---"

    local cmd="$CLIENT $host $port -P $protocol --dump"
    if [ -n "$pubkey" ]; then
        cmd="$cmd -k $pubkey"
    fi

    $cmd 2>&1
}

echo ""
echo "=============================================================================="
echo "                    Roughenough Real-World Server Tests"
echo "=============================================================================="
echo ""
echo "Server list: $SERVER_FILE"
echo ""

if [ ! -f "$SERVER_FILE" ]; then
    echo "Error: Server file not found: $SERVER_FILE"
    exit 0  # Don't fail CI
fi

# Read servers from file
while IFS='|' read -r name host port protocol pubkey; do
    # Skip comments and empty lines
    [[ "$name" =~ ^#.*$ ]] && continue
    [[ -z "$name" ]] && continue

    test_server "$name" "$host" "$port" "$protocol" "$pubkey"
done < "$SERVER_FILE"

echo ""
echo "=============================================================================="
echo "                              Test Summary"
echo "=============================================================================="
echo ""
printf "  ${GREEN}Passed:${NC}  %d\n" $PASSED
printf "  ${RED}Failed:${NC}  %d\n" $FAILED
printf "  ${YELLOW}Skipped:${NC} %d (timeouts)\n" $SKIPPED
echo ""

# Show protocol dump for failures
if [ ${#FAILED_SERVERS[@]} -gt 0 ]; then
    echo "=============================================================================="
    echo "                         Failure details (protocol dump)"
    echo "=============================================================================="

    for server in "${FAILED_SERVERS[@]}"; do
        IFS='|' read -r name host port protocol pubkey <<< "$server"
        dump_retry "$name" "$host" "$port" "$protocol" "$pubkey"
    done

    echo ""
    echo "=============================================================================="
    echo ""
    echo "Failures may be due to:"
    echo "  - Network issues or firewalls"
    echo "  - Servers being temporarily unavailable"
    echo "  - Protocol incompatibilities"
    echo ""
fi

# Always exit 0 for CI - failures are informational
exit 0
