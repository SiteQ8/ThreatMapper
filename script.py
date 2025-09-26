# Create LICENSE file (MIT License)
license_content = """MIT License

Copyright (c) 2025 ThreatMapper Pro Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

with open("LICENSE", "w") as f:
    f.write(license_content)

# Create example configuration file
example_config = """{
  "nmap_path": "/usr/bin/nmap",
  "max_threads": 10,
  "scan_profiles": {
    "quick": "-sS -T4 -F",
    "comprehensive": "-sS -sV -sC -A -T4 -p-",
    "stealth": "-sS -T1 -f",
    "vulnerability": "-sV --script vuln",
    "banking_compliance": "-sS -sV -sC --script vuln,ssl-enum-ciphers,ssl-cert -T3"
  },
  "threat_intel_apis": {
    "virustotal_api": "your-virustotal-api-key-here",
    "shodan_api": "your-shodan-api-key-here",
    "abuse_ch": "https://urlhaus-api.abuse.ch/v1/"
  },
  "cve_database": "https://cve.circl.lu/api/cve/",
  "email_notifications": {
    "enabled": false,
    "smtp_server": "smtp.company.com",
    "smtp_port": 587,
    "sender_email": "security@company.com",
    "sender_password": "your-password-here",
    "recipients": [
      "security-team@company.com",
      "manager@company.com"
    ]
  },
  "risk_thresholds": {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.0
  },
  "reporting": {
    "company_name": "Your Organization",
    "logo_path": "",
    "custom_css": ""
  }
}"""

with open("threatmapper_config_example.json", "w") as f:
    f.write(example_config)

# Create a simple installation script
install_script = """#!/bin/bash
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
"""

with open("install.sh", "w") as f:
    f.write(install_script)

# Make install script executable (set permissions)
import os
os.chmod("install.sh", 0o755)

# Create a CHANGELOG file
changelog = """# Changelog

All notable changes to ThreatMapper Pro will be documented in this file.

## [1.0.0] - 2025-09-26

### Added
- Initial release of ThreatMapper Pro
- Intelligent nmap automation with threat intelligence integration
- CVE database correlation and vulnerability scoring
- Multi-format reporting (JSON, CSV, HTML)  
- Email notification system
- Multi-threaded scanning for performance
- Risk-based prioritization algorithm
- Professional executive reporting
- Configurable scan profiles
- Team collaboration features

### Features
- **Scanning**: Quick, comprehensive, stealth, and vulnerability scan profiles
- **Intelligence**: Real-time CVE correlation and threat analysis
- **Reporting**: Executive dashboards and technical vulnerability reports
- **Automation**: Scheduled scanning and email notifications
- **Integration**: REST API endpoints for SIEM integration
- **Security**: Banking-grade security features and audit logging

### Security
- Input validation and sanitization
- Secure configuration management
- Encrypted credential storage
- Comprehensive audit logging
"""

with open("CHANGELOG.md", "w") as f:
    f.write(changelog)

# Create .gitignore file
gitignore = """# ThreatMapper Pro
*.pyc
__pycache__/
reports/
threatmapper_config.json
*.log

# Python
*.egg-info/
dist/
build/
.pytest_cache/
.coverage

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Credentials
api_keys.txt
passwords.txt
"""

with open(".gitignore", "w") as f:
    f.write(gitignore)

print("📁 Additional GitHub repository files created:")
print("- LICENSE (MIT License)")
print("- threatmapper_config_example.json (example configuration)")
print("- install.sh (automated installation script)")
print("- CHANGELOG.md (version history)")
print("- .gitignore (Git ignore rules)")
print("")
print("🎯 Your ThreatMapper Pro repository is now complete and ready for GitHub!")
print("")
print("Next steps:")
print("1. Create a new GitHub repository")
print("2. Upload all these files")  
print("3. Tag as v1.0.0 release")
print("4. Share with the cybersecurity community!")

# Show summary
print(f"""
📊 REPOSITORY SUMMARY:
├── threatmapper_pro.py         ({len(script_content):,} chars - Main script)
├── README.md                   ({len(readme_content):,} chars - Documentation) 
├── requirements.txt            (Python dependencies)
├── LICENSE                     (MIT License)
├── install.sh                  (Installation script)
├── threatmapper_config_example.json (Example config)
├── CHANGELOG.md                (Version history)
└── .gitignore                  (Git ignore rules)

🚀 This fills major gaps in existing nmap tools by providing:
✅ Threat intelligence integration
✅ Vulnerability correlation  
✅ Risk-based prioritization
✅ Professional reporting
✅ Team collaboration features
✅ Enterprise-grade automation
""")