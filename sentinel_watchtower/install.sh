#!/bin/bash

# Sentinel Watchtower Installation Script
# This script installs all required tools and dependencies

set -e

echo "🛡️  Installing Sentinel Watchtower..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    exit 1
fi

echo "✅ Go found: $(go version)"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Install ProjectDiscovery tools
echo "🔧 Installing ProjectDiscovery tools..."

echo "  • Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "  • Installing dnsx..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo "  • Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "  • Installing naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo "  • Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "  • Installing katana..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Install other tools
echo "  • Installing assetfinder..."
go install -v github.com/tomnomnom/assetfinder@latest

echo "  • Installing dalfox..."
go install -v github.com/hahwul/dalfox/v2@latest

echo "  • Installing gau..."
go install -v github.com/lc/gau/v2/cmd/gau@latest

echo "  • Installing waybackurls..."
go install -v github.com/tomnomnom/waybackurls@latest

# Add Go bin to PATH (temporary for this session)
export PATH=$PATH:$(go env GOPATH)/bin

# Verify installations
echo ""
echo "🔍 Verifying installations..."

tools=("subfinder" "dnsx" "httpx" "nuclei" "katana" "dalfox" "gau" "waybackurls")

for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "  ✅ $tool installed"
    else
        echo "  ⚠️  $tool not found in PATH"
    fi
done

echo ""
echo "📝 Next steps:"
echo "1. Add Go bin to your PATH permanently:"
echo "   echo 'export PATH=\$PATH:\$(go env GOPATH)/bin' >> ~/.bashrc"
echo "   source ~/.bashrc"
echo ""
echo "2. Set up Telegram bot:"
echo "   - Message @BotFather on Telegram to create a bot"
echo "   - Get your bot token"
echo "   - Message @userinfobot to get your Telegram ID"
echo ""
echo "3. Set environment variables:"
echo "   export TELEGRAM_BOT_TOKEN='your_bot_token'"
echo "   export TELEGRAM_ADMIN_ID='your_telegram_id'"
echo ""
echo "4. Run the watchtower:"
echo "   python3 sentinel.py"
echo ""
echo "🎉 Installation complete!"
