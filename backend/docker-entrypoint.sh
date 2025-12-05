#!/bin/bash
# docker-entrypoint.sh - Dual-mode entrypoint for AI Security Scanner
#
# Usage:
#   docker run ai-scanner web              # Start web server (default)
#   docker run ai-scanner scan URL         # Run CLI scan
#   docker run ai-scanner https://app.com  # Auto-detect: run CLI scan
#   docker run ai-scanner version          # Show version
#   docker run ai-scanner --help           # Show CLI help

set -e

# Detect mode based on first argument
case "$1" in
    web|server|api)
        # Web server mode
        shift
        echo "[entrypoint] Starting web server on port ${PORT:-8000}..."
        exec uvicorn backend.app.main:app \
            --host 0.0.0.0 \
            --port "${PORT:-8000}" \
            --proxy-headers \
            --forwarded-allow-ips "*" \
            "$@"
        ;;

    scan|version|info|--help|-h)
        # CLI mode - pass all args to CLI
        echo "[entrypoint] Running CLI command: $*"
        exec python -m backend.app.cli "$@"
        ;;

    "")
        # No arguments - default to web server
        echo "[entrypoint] Starting web server on port ${PORT:-8000} (default mode)..."
        exec uvicorn backend.app.main:app \
            --host 0.0.0.0 \
            --port "${PORT:-8000}" \
            --proxy-headers \
            --forwarded-allow-ips "*"
        ;;

    *)
        # Auto-detect: if looks like a URL, run scan
        if [[ "$1" == http* ]]; then
            echo "[entrypoint] Auto-detected URL, running scan..."
            exec python -m backend.app.cli scan "$@"
        fi

        # Otherwise, run whatever command was given (for debugging)
        exec "$@"
        ;;
esac
