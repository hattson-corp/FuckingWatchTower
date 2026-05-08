#!/bin/bash

# Quick Start Script for Sentinel Watchtower

echo "🛡️  Sentinel Watchtower - Quick Start"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found!"
    echo "Please create a .env file with your Telegram credentials:"
    echo ""
    echo "TELEGRAM_BOT_TOKEN='your_bot_token'"
    echo "TELEGRAM_ADMIN_ID='your_telegram_id'"
    echo ""
    echo "Or copy .env.example and edit it:"
    echo "cp .env.example .env"
    echo ""
    exit 1
fi

# Load environment variables
export $(grep -v '^#' .env | xargs)

# Check if required variables are set
if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ "$TELEGRAM_BOT_TOKEN" = "your_bot_token_here" ]; then
    echo "❌ TELEGRAM_BOT_TOKEN is not set or still has default value"
    exit 1
fi

if [ -z "$TELEGRAM_ADMIN_ID" ] || [ "$TELEGRAM_ADMIN_ID" = "your_telegram_id_here" ]; then
    echo "❌ TELEGRAM_ADMIN_ID is not set or still has default value"
    exit 1
fi

# Check if Python dependencies are installed
if ! python3 -c "import telegram" 2>/dev/null; then
    echo "📦 Installing Python dependencies..."
    pip install -r requirements.txt
fi

# Check if tools are available
echo "🔍 Checking for required tools..."
missing_tools=()

for tool in subfinder dnsx httpx nuclei; do
    if ! command -v $tool &> /dev/null && ! command -v $GOPATH/bin/$tool &> /dev/null; then
        missing_tools+=($tool)
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "⚠️  Missing tools: ${missing_tools[*]}"
    echo "Run ./install.sh to install all required tools"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "✅ All checks passed!"
echo "🚀 Starting Sentinel Watchtower..."
echo ""
echo "In Telegram, use these commands:"
echo "  /start - Welcome message"
echo "  /add example.com - Add a target"
echo "  /targets - List targets"
echo "  /stats - View statistics"
echo "  /findings - Recent findings"
echo ""

# Run the watchtower
python3 sentinel.py
