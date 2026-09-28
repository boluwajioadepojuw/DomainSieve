#!/bin/bash
# Quick sanity check for one generated rule URL (optional tooling)
# Usage: ./check-rule-url.sh <domain>
set -u
D="${1:-paypa1.com}"
curl -sI "https://$D" -o /dev/null -w "status %{http_code}\n" --max-time 10 || echo "unreachable (expected for parked domains)"
