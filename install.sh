#!/bin/bash
# ThreatMapper Pro Installation Script

echo "🛡️  Installing ThreatMapper Pro..."

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required but not installed"
    exit 1
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "❌ Nmap is required but not installed"
    echo "Please install nmap first:"
    echo "  Ubuntu/Debian: sudo apt install nmap"
    echo "  CentOS/RHEL: sudo yum install nmap"
    echo "  macOS: brew install nmap"
    exit 1
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Make script executable
chmod +x threatmapper_pro.py

# Copy example configuration
if [ ! -f "threatmapper_config.json" ]; then
    echo "⚙️  Creating default configuration..."
    cp threatmapper_config_example.json threatmapper_config.json
fi

# Create reports directory
mkdir -p reports

echo "✅ Installation completed successfully!"
echo ""
echo "🚀 Quick start:"
echo "  ./threatmapper_pro.py -t 127.0.0.1"
echo ""
echo "📖 For more examples, see the README.md file"
