#!/usr/bin/env python3
"""
ThreatMapper Pro - Intelligent Network Security Scanner
Author: Cybersecurity Community
Version: 1.0.0
License: MIT

A comprehensive nmap automation script that integrates threat intelligence,
vulnerability correlation, and collaborative security workflows.
"""

import subprocess
import json
import csv
import xml.etree.ElementTree as ET
import argparse
import sys
import os
import time
import re
import requests
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class ThreatMapper:
    """
    Advanced nmap automation with threat intelligence integration
    """

    def __init__(self, config_file: str = "threatmapper_config.json"):
        self.version = "1.0.0"
        self.config_file = config_file
        self.config = self.load_config()
        self.scan_results = {}
        self.vulnerabilities = {}
        self.threat_intel = {}
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)

    def load_config(self) -> Dict:
        """Load configuration from file or create default"""
        default_config = {
            "nmap_path": "/usr/bin/nmap",
            "max_threads": 10,
            "scan_profiles": {
                "quick": "-sS -T4 -F",
                "comprehensive": "-sS -sV -sC -A -T4 -p-",
                "stealth": "-sS -T1 -f",
                "vulnerability": "-sV --script vuln"
            },
            "threat_intel_apis": {
                "virustotal_api": "",
                "shodan_api": "",
                "abuse_ch": "https://urlhaus-api.abuse.ch/v1/"
            },
            "cve_database": "https://cve.circl.lu/api/cve/",
            "email_notifications": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "sender_email": "",
                "sender_password": "",
                "recipients": []
            },
            "risk_thresholds": {
                "critical": 9.0,
                "high": 7.0,
                "medium": 4.0,
                "low": 0.0
            }
        }

        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            # Merge with defaults for missing keys
            for key, value in default_config.items():
                if key not in config:
                    config[key] = value
        except FileNotFoundError:
            config = default_config
            self.save_config(config)

        return config

    def save_config(self, config: Dict):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)

    def validate_target(self, target: str) -> bool:
        """Validate scan target"""
        try:
            socket.inet_aton(target.split('/')[0])
            return True
        except socket.error:
            try:
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                return False

    def run_nmap_scan(self, target: str, scan_type: str = "quick", 
                     custom_args: str = "") -> Dict:
        """Execute nmap scan with specified parameters"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")

        # Build nmap command
        nmap_cmd = [self.config["nmap_path"]]

        if custom_args:
            nmap_cmd.extend(custom_args.split())
        elif scan_type in self.config["scan_profiles"]:
            nmap_cmd.extend(self.config["scan_profiles"][scan_type].split())
        else:
            nmap_cmd.extend(self.config["scan_profiles"]["quick"].split())

        # Add output format and target
        nmap_cmd.extend(["-oX", "-", target])

        print(f"[+] Running scan: {' '.join(nmap_cmd)}")

        try:
            result = subprocess.run(nmap_cmd, capture_output=True, 
                                  text=True, timeout=3600)
            if result.returncode != 0:
                raise RuntimeError(f"Nmap scan failed: {result.stderr}")

            return self.parse_nmap_xml(result.stdout)

        except subprocess.TimeoutExpired:
            raise RuntimeError("Nmap scan timed out")
        except FileNotFoundError:
            raise RuntimeError(f"Nmap not found at {self.config['nmap_path']}")

    def parse_nmap_xml(self, xml_data: str) -> Dict:
        """Parse nmap XML output"""
        root = ET.fromstring(xml_data)
        scan_data = {
            "scan_info": {},
            "hosts": {},
            "runtime": {}
        }

        # Parse scan info
        scaninfo = root.find('scaninfo')
        if scaninfo is not None:
            scan_data["scan_info"] = scaninfo.attrib

        # Parse runtime info
        runstats = root.find('runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            if finished is not None:
                scan_data["runtime"] = finished.attrib

        # Parse hosts
        for host in root.findall('host'):
            host_data = self.parse_host(host)
            if host_data:
                scan_data["hosts"][host_data["ip"]] = host_data

        return scan_data

    def parse_host(self, host_element) -> Dict:
        """Parse individual host from nmap XML"""
        host_data = {
            "ip": "",
            "hostname": "",
            "status": "",
            "ports": {},
            "os": {},
            "scripts": {}
        }

        # Get IP address
        address = host_element.find('address')
        if address is not None:
            host_data["ip"] = address.get('addr', '')

        # Get hostname
        hostnames = host_element.find('hostnames')
        if hostnames is not None:
            hostname = hostnames.find('hostname')
            if hostname is not None:
                host_data["hostname"] = hostname.get('name', '')

        # Get status
        status = host_element.find('status')
        if status is not None:
            host_data["status"] = status.get('state', '')

        # Parse ports
        ports = host_element.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_data = self.parse_port(port)
                host_data["ports"][port_data["port"]] = port_data

        # Parse OS detection
        os_element = host_element.find('os')
        if os_element is not None:
            host_data["os"] = self.parse_os(os_element)

        # Parse script results
        hostscript = host_element.find('hostscript')
        if hostscript is not None:
            for script in hostscript.findall('script'):
                script_id = script.get('id', '')
                script_output = script.get('output', '')
                host_data["scripts"][script_id] = script_output

        return host_data

    def parse_port(self, port_element) -> Dict:
        """Parse port information from nmap XML"""
        port_data = {
            "port": "",
            "protocol": "",
            "state": "",
            "service": "",
            "version": "",
            "scripts": {}
        }

        port_data["port"] = port_element.get('portid', '')
        port_data["protocol"] = port_element.get('protocol', '')

        state = port_element.find('state')
        if state is not None:
            port_data["state"] = state.get('state', '')

        service = port_element.find('service')
        if service is not None:
            port_data["service"] = service.get('name', '')
            port_data["version"] = service.get('version', '')

        # Parse scripts
        for script in port_element.findall('script'):
            script_id = script.get('id', '')
            script_output = script.get('output', '')
            port_data["scripts"][script_id] = script_output

        return port_data

    def parse_os(self, os_element) -> Dict:
        """Parse OS detection information"""
        os_data = {
            "matches": [],
            "fingerprint": ""
        }

        for osmatch in os_element.findall('osmatch'):
            match_data = {
                "name": osmatch.get('name', ''),
                "accuracy": osmatch.get('accuracy', ''),
                "line": osmatch.get('line', '')
            }
            os_data["matches"].append(match_data)

        fingerprint = os_element.find('osfingerprint')
        if fingerprint is not None:
            os_data["fingerprint"] = fingerprint.get('fingerprint', '')

        return os_data

    def query_cve_database(self, service: str, version: str) -> List[Dict]:
        """Query CVE database for known vulnerabilities"""
        if not service or not version:
            return []

        try:
            # Build search query
            search_term = f"{service} {version}".replace(' ', '%20')
            url = f"{self.config['cve_database']}/search/{search_term}"

            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                cve_data = response.json()
                return cve_data.get('results', [])
        except Exception as e:
            print(f"[!] CVE database query failed: {e}")

        return []

    def calculate_risk_score(self, host_data: Dict) -> Tuple[float, str]:
        """Calculate risk score for a host"""
        base_score = 0.0
        risk_factors = []

        # Check for open ports
        open_ports = len([p for p in host_data["ports"].values() 
                         if p["state"] == "open"])
        if open_ports > 10:
            base_score += 2.0
            risk_factors.append(f"{open_ports} open ports")
        elif open_ports > 5:
            base_score += 1.0
            risk_factors.append(f"{open_ports} open ports")

        # Check for high-risk services
        high_risk_services = ["ftp", "telnet", "rlogin", "rsh", "vnc", "rdp"]
        for port_data in host_data["ports"].values():
            if port_data["service"].lower() in high_risk_services:
                base_score += 3.0
                risk_factors.append(f"High-risk service: {port_data['service']}")

        # Check for vulnerabilities in script results
        vuln_scripts = ["vuln", "exploit", "dos"]
        for port_data in host_data["ports"].values():
            for script_name, script_output in port_data["scripts"].items():
                if any(vs in script_name.lower() for vs in vuln_scripts):
                    if "VULNERABLE" in script_output.upper():
                        base_score += 5.0
                        risk_factors.append(f"Vulnerability detected: {script_name}")

        # Determine risk level
        thresholds = self.config["risk_thresholds"]
        if base_score >= thresholds["critical"]:
            risk_level = "CRITICAL"
        elif base_score >= thresholds["high"]:
            risk_level = "HIGH"
        elif base_score >= thresholds["medium"]:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return base_score, risk_level

    def generate_report(self, scan_data: Dict, output_format: str = "json") -> str:
        """Generate comprehensive scan report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Enhance scan data with threat intelligence
        enhanced_data = self.enhance_with_threat_intel(scan_data)

        if output_format == "json":
            filename = f"threatmapper_report_{timestamp}.json"
            filepath = self.reports_dir / filename
            with open(filepath, 'w') as f:
                json.dump(enhanced_data, f, indent=2)

        elif output_format == "csv":
            filename = f"threatmapper_report_{timestamp}.csv"
            filepath = self.reports_dir / filename
            self.generate_csv_report(enhanced_data, filepath)

        elif output_format == "html":
            filename = f"threatmapper_report_{timestamp}.html"
            filepath = self.reports_dir / filename
            self.generate_html_report(enhanced_data, filepath)

        return str(filepath)

    def enhance_with_threat_intel(self, scan_data: Dict) -> Dict:
        """Enhance scan data with threat intelligence"""
        enhanced_data = scan_data.copy()
        enhanced_data["threat_analysis"] = {}

        for ip, host_data in scan_data["hosts"].items():
            risk_score, risk_level = self.calculate_risk_score(host_data)

            enhanced_data["hosts"][ip]["risk_score"] = risk_score
            enhanced_data["hosts"][ip]["risk_level"] = risk_level
            enhanced_data["hosts"][ip]["vulnerabilities"] = []

            # Query vulnerabilities for each service
            for port, port_data in host_data["ports"].items():
                if port_data["state"] == "open" and port_data["service"]:
                    cve_results = self.query_cve_database(
                        port_data["service"], port_data["version"])

                    for cve in cve_results[:5]:  # Limit to top 5 CVEs
                        vuln_data = {
                            "cve_id": cve.get("id", ""),
                            "description": cve.get("summary", ""),
                            "cvss_score": cve.get("cvss", 0),
                            "port": port,
                            "service": port_data["service"],
                            "version": port_data["version"]
                        }
                        enhanced_data["hosts"][ip]["vulnerabilities"].append(vuln_data)

        return enhanced_data

    def generate_csv_report(self, data: Dict, filepath: Path):
        """Generate CSV report"""
        with open(filepath, 'w', newline='') as csvfile:
            fieldnames = ['ip', 'hostname', 'port', 'service', 'version', 
                         'state', 'risk_level', 'vulnerabilities']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for ip, host_data in data["hosts"].items():
                for port, port_data in host_data["ports"].items():
                    vuln_count = len(host_data.get("vulnerabilities", []))
                    writer.writerow({
                        'ip': ip,
                        'hostname': host_data.get("hostname", ""),
                        'port': port,
                        'service': port_data.get("service", ""),
                        'version': port_data.get("version", ""),
                        'state': port_data.get("state", ""),
                        'risk_level': host_data.get("risk_level", ""),
                        'vulnerabilities': vuln_count
                    })

    def generate_html_report(self, data: Dict, filepath: Path):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>ThreatMapper Pro Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; }
                .host { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
                .critical { border-left: 5px solid #e74c3c; }
                .high { border-left: 5px solid #f39c12; }
                .medium { border-left: 5px solid #f1c40f; }
                .low { border-left: 5px solid #27ae60; }
                .port-table { width: 100%; border-collapse: collapse; }
                .port-table th, .port-table td { 
                    border: 1px solid #ddd; padding: 8px; text-align: left; 
                }
                .port-table th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>ThreatMapper Pro Security Report</h1>
                <p>Generated: {timestamp}</p>
            </div>

            <div class="summary">
                <h2>Executive Summary</h2>
                <ul>
                    <li>Total Hosts Scanned: {total_hosts}</li>
                    <li>Hosts Online: {hosts_online}</li>
                    <li>Critical Risk Hosts: {critical_hosts}</li>
                    <li>High Risk Hosts: {high_hosts}</li>
                    <li>Total Vulnerabilities: {total_vulns}</li>
                </ul>
            </div>

            {host_details}
        </body>
        </html>
        """

        # Calculate summary statistics
        total_hosts = len(data["hosts"])
        hosts_online = len([h for h in data["hosts"].values() 
                           if h["status"] == "up"])
        critical_hosts = len([h for h in data["hosts"].values() 
                             if h.get("risk_level") == "CRITICAL"])
        high_hosts = len([h for h in data["hosts"].values() 
                         if h.get("risk_level") == "HIGH"])
        total_vulns = sum(len(h.get("vulnerabilities", [])) 
                         for h in data["hosts"].values())

        # Generate host details
        host_details = ""
        for ip, host_data in data["hosts"].items():
            risk_level = host_data.get("risk_level", "LOW").lower()
            host_details += f"""
            <div class="host {risk_level}">
                <h3>{ip} ({host_data.get('hostname', 'Unknown')})</h3>
                <p><strong>Status:</strong> {host_data['status']}</p>
                <p><strong>Risk Level:</strong> {host_data.get('risk_level', 'LOW')}</p>
                <p><strong>Risk Score:</strong> {host_data.get('risk_score', 0)}</p>

                <h4>Open Ports</h4>
                <table class="port-table">
                    <tr><th>Port</th><th>Service</th><th>Version</th><th>State</th></tr>
            """

            for port, port_data in host_data["ports"].items():
                if port_data["state"] == "open":
                    host_details += f"""
                    <tr>
                        <td>{port}</td>
                        <td>{port_data.get('service', '')}</td>
                        <td>{port_data.get('version', '')}</td>
                        <td>{port_data['state']}</td>
                    </tr>
                    """

            host_details += "</table>"

            # Add vulnerabilities if any
            vulns = host_data.get("vulnerabilities", [])
            if vulns:
                host_details += "<h4>Vulnerabilities</h4><ul>"
                for vuln in vulns[:10]:  # Limit display
                    host_details += f"""
                    <li><strong>{vuln['cve_id']}</strong> 
                        (CVSS: {vuln['cvss_score']}) - {vuln['description'][:100]}...</li>
                    """
                host_details += "</ul>"

            host_details += "</div>"

        # Write HTML file
        html_content = html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_hosts=total_hosts,
            hosts_online=hosts_online,
            critical_hosts=critical_hosts,
            high_hosts=high_hosts,
            total_vulns=total_vulns,
            host_details=host_details
        )

        with open(filepath, 'w') as f:
            f.write(html_content)

    def send_notification(self, report_path: str, scan_summary: Dict):
        """Send email notification with scan results"""
        if not self.config["email_notifications"]["enabled"]:
            return

        try:
            smtp_config = self.config["email_notifications"]

            msg = MIMEMultipart()
            msg['From'] = smtp_config["sender_email"]
            msg['To'] = ", ".join(smtp_config["recipients"])
            msg['Subject'] = "ThreatMapper Pro - Security Scan Completed"

            body = f"""
            Security scan completed successfully.

            Summary:
            - Hosts scanned: {scan_summary.get('total_hosts', 0)}
            - Critical risks: {scan_summary.get('critical_hosts', 0)}
            - High risks: {scan_summary.get('high_hosts', 0)}
            - Total vulnerabilities: {scan_summary.get('total_vulns', 0)}

            Report generated: {report_path}

            ThreatMapper Pro v{self.version}
            """

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(smtp_config["smtp_server"], 
                                 smtp_config["smtp_port"])
            server.starttls()
            server.login(smtp_config["sender_email"], 
                        smtp_config["sender_password"])

            server.send_message(msg)
            server.quit()

            print("[+] Email notification sent successfully")

        except Exception as e:
            print(f"[!] Failed to send notification: {e}")

    def run_scan(self, targets: List[str], scan_type: str = "quick",
                output_format: str = "json", notify: bool = False) -> str:
        """Main scan execution method"""
        print(f"[+] ThreatMapper Pro v{self.version}")
        print(f"[+] Starting scan of {len(targets)} target(s)")

        all_results = {"hosts": {}, "scan_info": {}, "runtime": {}}

        with ThreadPoolExecutor(max_workers=self.config["max_threads"]) as executor:
            future_to_target = {
                executor.submit(self.run_nmap_scan, target, scan_type): target
                for target in targets
            }

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    all_results["hosts"].update(result["hosts"])
                    print(f"[+] Completed scan of {target}")
                except Exception as e:
                    print(f"[!] Scan failed for {target}: {e}")

        print("[+] Generating threat intelligence report...")
        report_path = self.generate_report(all_results, output_format)

        # Calculate summary for notifications
        scan_summary = {
            'total_hosts': len(all_results["hosts"]),
            'critical_hosts': len([h for h in all_results["hosts"].values() 
                                  if h.get("risk_level") == "CRITICAL"]),
            'high_hosts': len([h for h in all_results["hosts"].values() 
                              if h.get("risk_level") == "HIGH"]),
            'total_vulns': sum(len(h.get("vulnerabilities", [])) 
                              for h in all_results["hosts"].values())
        }

        print(f"[+] Report generated: {report_path}")
        print(f"[+] Scan completed. {scan_summary['total_hosts']} hosts analyzed.")
        print(f"[+] Found {scan_summary['critical_hosts']} critical and "
              f"{scan_summary['high_hosts']} high-risk hosts")

        if notify:
            self.send_notification(report_path, scan_summary)

        return report_path


def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(
        description="ThreatMapper Pro - Intelligent Network Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.0/24 --scan-type quick
  %(prog)s -t example.com --scan-type comprehensive --format html
  %(prog)s -t 10.0.0.1 10.0.0.2 --notify
  %(prog)s --list-profiles
        """
    )

    parser.add_argument('-t', '--targets', nargs='+', required=True,
                       help='Target IP addresses, hostnames, or CIDR ranges')
    parser.add_argument('--scan-type', choices=['quick', 'comprehensive', 
                       'stealth', 'vulnerability'], default='quick',
                       help='Scan profile type (default: quick)')
    parser.add_argument('--format', choices=['json', 'csv', 'html'], 
                       default='json', help='Report format (default: json)')
    parser.add_argument('--notify', action='store_true',
                       help='Send email notification when scan completes')
    parser.add_argument('--config', default='threatmapper_config.json',
                       help='Configuration file path')
    parser.add_argument('--list-profiles', action='store_true',
                       help='List available scan profiles')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')

    args = parser.parse_args()

    try:
        scanner = ThreatMapper(args.config)

        if args.list_profiles:
            print("Available scan profiles:")
            for profile, command in scanner.config["scan_profiles"].items():
                print(f"  {profile}: {command}")
            return

        report_path = scanner.run_scan(
            targets=args.targets,
            scan_type=args.scan_type,
            output_format=args.format,
            notify=args.notify
        )

        print(f"\n[+] Scan completed successfully!")
        print(f"[+] Report saved to: {report_path}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
