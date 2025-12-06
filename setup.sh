#!/usr/bin/env bash
#
# setup.sh - Local development setup script
#   - Copies .env.example to .env (if exists)
#   - Sets up Python venv with dependencies (using uv or poetry)
#   - Installs Node.js dependencies
#
# Usage:
#   ./setup.sh
#

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="${PROJECT_ROOT}/frontend"

echo -e "${BOLD}======================================================${NC}"
echo -e "${BOLD}       AI Security Scanner - Development Setup        ${NC}"
echo -e "${BOLD}======================================================${NC}"

# Check requirements
check_requirements() {
  echo -e "\n${BOLD}Checking requirements...${NC}"
  local missing=0

  for cmd in npm docker; do
    if ! command -v "$cmd" &>/dev/null; then
      echo -e "${RED}✗ $cmd is not installed${NC}"
      missing=1
    else
      echo -e "${GREEN}✓ $cmd${NC}"
    fi
  done

  # Check for uv (preferred), poetry, or python3
  if command -v uv &>/dev/null; then
    echo -e "${GREEN}✓ uv${NC}"
    USE_UV=true
    USE_POETRY=false
  elif command -v poetry &>/dev/null; then
    echo -e "${GREEN}✓ poetry${NC}"
    USE_UV=false
    USE_POETRY=true
  elif command -v python3 &>/dev/null; then
    echo -e "${YELLOW}✓ python3 (uv or poetry recommended for faster setup)${NC}"
    USE_UV=false
    USE_POETRY=false
  else
    echo -e "${RED}✗ No Python tool found (uv, poetry, or python3)${NC}"
    missing=1
  fi

  if [ $missing -eq 1 ]; then
    echo -e "\n${RED}Please install missing tools:${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
      echo -e "  brew install node uv"
      echo -e "  Install Docker Desktop from https://docker.com"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
      echo -e "  sudo apt install nodejs npm docker.io"
      echo -e "  curl -LsSf https://astral.sh/uv/install.sh | sh"
    fi
    exit 1
  fi

  echo -e "${GREEN}All requirements satisfied.${NC}"
}

# Setup environment file
setup_env() {
  echo -e "\n${BOLD}Setting up environment...${NC}"
  if [ -f "${PROJECT_ROOT}/.env.example" ] && [ ! -f "${PROJECT_ROOT}/.env" ]; then
    cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
    echo -e "${GREEN}Created .env from .env.example${NC}"
  elif [ -f "${PROJECT_ROOT}/.env" ]; then
    echo -e "${YELLOW}.env already exists, skipping...${NC}"
  else
    echo -e "${YELLOW}No .env.example found, skipping...${NC}"
  fi
}

# Check if venv is valid (exists and Python works)
is_venv_valid() {
  [ -f ".venv/bin/python" ] && .venv/bin/python -c "import sys" 2>/dev/null
}

# Setup backend with uv, poetry, or fallback to python3
setup_backend() {
  echo -e "\n${BOLD}Setting up backend...${NC}"
  cd "$PROJECT_ROOT"

  if [ "$USE_UV" = true ]; then
    # Use uv (fastest, most reliable)
    if ! is_venv_valid; then
      echo "Creating Python virtual environment with uv..."
      rm -rf .venv  # Remove broken venv if exists
      uv venv .venv
    fi
    echo "Installing Python dependencies..."
    uv pip install --python .venv/bin/python -r backend/requirements.txt
  elif [ "$USE_POETRY" = true ]; then
    echo "Installing Python dependencies with poetry..."
    poetry install
  else
    # Fallback to standard python3 venv
    if ! is_venv_valid; then
      echo "Creating Python virtual environment..."
      rm -rf .venv  # Remove broken venv if exists
      python3 -m venv .venv --without-pip
      # Install pip manually to avoid ensurepip issues
      curl -sS https://bootstrap.pypa.io/get-pip.py | .venv/bin/python
    fi
    echo "Installing Python dependencies..."
    .venv/bin/pip install --upgrade pip -q
    .venv/bin/pip install -r backend/requirements.txt -q
  fi

  # macOS: Check WeasyPrint dependencies for PDF generation
  if [[ "$OSTYPE" == "darwin"* ]]; then
    if ! brew list glib &>/dev/null 2>&1; then
      echo -e "${YELLOW}Note: PDF generation requires: brew install glib pango gdk-pixbuf libffi${NC}"
    fi
  fi

  echo -e "${GREEN}✓ Backend setup complete${NC}"
}

# Setup frontend
setup_frontend() {
  echo -e "\n${BOLD}Setting up frontend...${NC}"
  cd "$FRONTEND_DIR"

  if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
  else
    echo -e "${YELLOW}node_modules exists, running npm install anyway...${NC}"
    npm install
  fi

  # Generate runtime env for local development
  echo "Generating runtime environment..."
  npm run gen:env 2>/dev/null || true

  cd "$PROJECT_ROOT"
  echo -e "${GREEN}✓ Frontend setup complete${NC}"
}

# Main
main() {
  check_requirements
  setup_env
  setup_backend
  setup_frontend

  echo -e "\n${GREEN}======================================================${NC}"
  echo -e "${GREEN}Setup complete!${NC}"
  echo -e "${GREEN}======================================================${NC}"
  echo -e "\n${YELLOW}Next steps:${NC}"
  echo -e "1. Run ${BOLD}docker compose up${NC} to start the development environment"
  echo -e "   Or run locally:"
  echo -e "   - Backend:  ${BOLD}poetry run uvicorn backend.app.main:app --reload${NC}"
  echo -e "   - Frontend: ${BOLD}cd frontend && npm run dev${NC}"
  echo -e "\n${BOLD}CLI Usage:${NC}"
  echo -e "  ${BOLD}poetry run scanner scan https://your-app.com${NC}"
  echo -e "\n${BOLD}URLs:${NC}"
  echo -e "  Backend:  http://localhost:8000"
  echo -e "  Frontend: http://localhost:3000"
  echo -e "  API Docs: http://localhost:8000/docs"
}

main "$@"
