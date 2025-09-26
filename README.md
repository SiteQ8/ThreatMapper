# ThreatMapper Pro 🛡️

**Intelligent Network Security Scanner with Threat Intelligence Integration**

ThreatMapper Pro is an advanced nmap automation script that transforms traditional network scanning into intelligent threat analysis. Built for cybersecurity teams who need more than basic port scanning - it provides vulnerability correlation, risk prioritization, and collaborative security workflows.

## 🚀 Why ThreatMapper Pro?

Traditional nmap tools leave you with raw data. ThreatMapper Pro gives you **actionable intelligence**:

- **🧠 Intelligent Analysis**: Automatic vulnerability correlation with CVE databases
- **🎯 Risk Prioritization**: Smart risk scoring based on threat landscape
- **📊 Executive Reporting**: Professional reports in JSON, CSV, and HTML formats
- **📧 Team Collaboration**: Email notifications and shared reporting
- **⚡ Performance**: Multi-threaded scanning for enterprise networks
- **🔒 Banking-Grade Security**: Built with enterprise security requirements in mind

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/SiteQ8/ThreatMapper.git
cd ThreatMapper

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x threatmapper_pro.py
```

## 📖 Quick Start

### Basic Network Scan
```bash
# Quick scan of internal network
./threatmapper_pro.py -t 192.168.1.0/24

# Comprehensive scan with HTML report
./threatmapper_pro.py -t example.com --scan-type comprehensive --format html

# Multi-target scan with notifications
./threatmapper_pro.py -t 10.0.0.1 10.0.0.2 10.0.0.3 --notify
```

### Available Scan Types
- **quick**: Fast SYN scan of common ports
- **comprehensive**: Full port range with service/OS detection  
- **stealth**: Low-intensity scan to avoid detection
- **vulnerability**: Focused vulnerability assessment

## 🎯 Key Features

### 🔍 Intelligent Scanning
- Multi-threaded execution for faster results
- Configurable scan profiles for different use cases
- Automatic service version detection and OS fingerprinting

### 🛡️ Threat Intelligence Integration
- Real-time CVE database correlation
- Risk scoring based on vulnerability severity
- Threat campaign attribution and tracking

### 📈 Advanced Reporting
- **Executive Dashboards**: High-level security metrics
- **Technical Reports**: Detailed vulnerability analysis
- **Compliance Ready**: Structured data for audit requirements

### 👥 Team Collaboration
- Email notifications for critical findings
- Shared configuration management
- Audit logging for security operations

## ⚙️ Configuration

ThreatMapper Pro uses a JSON configuration file (`threatmapper_config.json`) that's automatically created on first run:

```json
{
  "scan_profiles": {
    "quick": "-sS -T4 -F",
    "comprehensive": "-sS -sV -sC -A -T4 -p-",
    "stealth": "-sS -T1 -f",
    "vulnerability": "-sV --script vuln"
  },
  "threat_intel_apis": {
    "virustotal_api": "your-api-key",
    "shodan_api": "your-api-key"
  },
  "email_notifications": {
    "enabled": true,
    "smtp_server": "smtp.company.com",
    "recipients": ["security-team@company.com"]
  }
}
```

## 📊 Sample Output

### JSON Report Structure
```json
{
  "hosts": {
    "192.168.1.100": {
      "hostname": "web-server.local",
      "status": "up",
      "risk_level": "HIGH",
      "risk_score": 8.5,
      "vulnerabilities": [
        {
          "cve_id": "CVE-2023-44487",
          "cvss_score": 9.8,
          "description": "HTTP/2 Rapid Reset Attack",
          "port": "80",
          "service": "http"
        }
      ]
    }
  }
}
```

### Executive Summary (HTML)
- Total Hosts Scanned: 50
- Hosts Online: 45
- Critical Risk Hosts: 3
- High Risk Hosts: 7
- Total Vulnerabilities Found: 23

## 🎪 Use Cases

### 🏦 Banking & Financial Services
- **Regulatory Compliance**: PCI DSS, SOX compliance scanning
- **Risk Assessment**: Quantified risk scoring for audit reports
- **Threat Monitoring**: Continuous security posture assessment

### 🏢 Enterprise Networks
- **Asset Discovery**: Complete network inventory management
- **Vulnerability Management**: Prioritized patch management workflows
- **Security Operations**: Integration with SIEM and ticketing systems

### 🔒 Penetration Testing
- **Reconnaissance**: Enhanced target profiling with threat intelligence
- **Vulnerability Assessment**: Comprehensive security gap analysis
- **Reporting**: Professional client-ready security reports

## 🚨 Advanced Features

### Risk Scoring Algorithm
ThreatMapper Pro uses a sophisticated risk scoring system:
- **Port Analysis**: Open ports and service exposure
- **Vulnerability Correlation**: CVE severity and exploitability
- **Threat Intelligence**: Active campaign and exploitation data
- **Business Context**: Asset criticality and network position

### Multi-Format Reporting
- **JSON**: Machine-readable for automation and integration
- **CSV**: Spreadsheet-compatible for analysis and tracking  
- **HTML**: Executive-friendly dashboards and visualizations

## 🔧 Command Line Reference

```bash
# Basic usage
./threatmapper_pro.py -t <targets> [options]

# Options
-t, --targets          Target IPs, hostnames, or CIDR ranges
--scan-type           Scan profile: quick|comprehensive|stealth|vulnerability
--format              Report format: json|csv|html
--notify              Send email notification
--config              Custom configuration file
--list-profiles       Show available scan profiles
```

## 🤝 Contributing

We welcome contributions from the cybersecurity community! 

### Development Setup
```bash
git clone https://github.com/yourusername/threatmapper-pro.git
cd threatmapper-pro
pip3 install -r requirements-dev.txt
```

### Contribution Areas
- **🌐 Threat Intelligence**: Additional API integrations
- **📊 Reporting**: New visualization and export formats
- **🔌 Integrations**: SIEM, ticketing, and workflow connectors
- **🧪 Testing**: Security testing and validation frameworks

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## ⚠️ Legal Notice

This tool is for authorized security testing only. Users are responsible for compliance with applicable laws and regulations. Always obtain proper authorization before scanning networks you don't own.

## 🆘 Support

- **📖 Documentation**: [Wiki](https://github.com/yourusername/threatmapper-pro/wiki)
- **🐛 Issues**: [GitHub Issues](https://github.com/yourusername/threatmapper-pro/issues)
- **💬 Community**: [Discussions](https://github.com/yourusername/threatmapper-pro/discussions)

## 🏆 Credits

Built by cybersecurity professionals for the cybersecurity community. Special thanks to:
- The nmap development team for the foundational scanning engine
- CVE/MITRE for vulnerability intelligence
- The open source security community

---

**ThreatMapper Pro v1.0.0** - Transforming Network Security, One Scan at a Time 🛡️
