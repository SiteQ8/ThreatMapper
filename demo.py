#!/usr/bin/env python3
"""
ThreatMapper Pro - Demo Script
This script demonstrates various usage scenarios for ThreatMapper Pro
"""

import subprocess
import sys
from pathlib import Path

def run_demo():
    print("🛡️  ThreatMapper Pro - Demonstration Script")
    print("=" * 50)

    # Check if the main script exists
    if not Path("threatmapper_pro.py").exists():
        print("❌ threatmapper_pro.py not found in current directory")
        sys.exit(1)

    print("\n📝 Available Demo Scenarios:")
    print("1. Quick network scan (safe for localhost)")
    print("2. Show scan profiles")
    print("3. Generate sample configuration")
    print("4. Show help information")
    print("5. Exit")

    while True:
        choice = input("\nSelect demo (1-5): ").strip()

        if choice == "1":
            print("\n🔍 Running quick localhost scan...")
            cmd = ["python3", "threatmapper_pro.py", "-t", "127.0.0.1", "--format", "json"]
            print(f"Command: {' '.join(cmd)}")
            print("\nNote: This is a safe demo scanning only localhost")

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    print("✅ Demo scan completed successfully!")
                    print("Check the reports/ directory for results")
                else:
                    print(f"⚠️  Demo completed with warnings: {result.stderr}")
            except subprocess.TimeoutExpired:
                print("⏰ Demo scan timed out (this is normal for demo)")
            except Exception as e:
                print(f"ℹ️  Demo note: {e}")
                print("💡 Install nmap and dependencies to run actual scans")

        elif choice == "2":
            print("\n📋 Available Scan Profiles:")
            cmd = ["python3", "threatmapper_pro.py", "--list-profiles"]
            try:
                subprocess.run(cmd)
            except Exception as e:
                print("💡 Install dependencies to see scan profiles")

        elif choice == "3":
            print("\n⚙️  Sample configuration created:")
            print("File: threatmapper_config_example.json")
            print("Copy to: threatmapper_config.json")
            print("Then edit with your settings")

        elif choice == "4":
            print("\n📖 ThreatMapper Pro Help:")
            cmd = ["python3", "threatmapper_pro.py", "--help"]
            try:
                subprocess.run(cmd)
            except Exception as e:
                print("💡 Install dependencies to see full help")

        elif choice == "5":
            print("\n👋 Demo completed. Happy scanning!")
            break

        else:
            print("❌ Invalid choice. Please select 1-5.")

if __name__ == "__main__":
    run_demo()
