"""
Test Suite for IDS Cybersecurity Platform
Test 1: Network Connectivity Validation

This script tests if all VMs can communicate with each other
and have proper network configuration.

Usage:
    python tests/test_connectivity.py

Expected: All pings should succeed
"""

import subprocess
import sys
import platform
from datetime import datetime


class NetworkConnectivityTest:
    """Test network connectivity between all components"""
    
    def __init__(self):
        self.test_name = "Network Connectivity Test"
        self.passed = 0
        self.failed = 0
        self.results = []
    
    def print_header(self):
        """Print test header"""
        print("\n" + "=" * 70)
        print(f"🧪 {self.test_name}")
        print("=" * 70)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70 + "\n")
    
    def ping_host(self, ip, name):
        """
        Ping a host and check if it's reachable
        
        Args:
            ip (str): IP address to ping
            name (str): Friendly name for the host
        
        Returns:
            bool: True if ping successful, False otherwise
        """
        print(f"Testing: {name} ({ip})...", end=" ")
        
        # Different ping command for Windows vs Linux/Mac
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        
        try:
            # Run ping command (1 packet, 2 second timeout)
            result = subprocess.run(
                ['ping', param, '1', '-w', '2000' if platform.system().lower() == 'windows' else '-W', '2', ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            
            if result.returncode == 0:
                print("✅ SUCCESS")
                self.passed += 1
                self.results.append({'test': name, 'status': 'PASS', 'ip': ip})
                return True
            else:
                print("❌ FAILED")
                self.failed += 1
                self.results.append({'test': name, 'status': 'FAIL', 'ip': ip})
                return False
        
        except subprocess.TimeoutExpired:
            print("❌ TIMEOUT")
            self.failed += 1
            self.results.append({'test': name, 'status': 'TIMEOUT', 'ip': ip})
            return False
        except Exception as e:
            print(f"❌ ERROR: {e}")
            self.failed += 1
            self.results.append({'test': name, 'status': 'ERROR', 'ip': ip, 'error': str(e)})
            return False
    
    def test_local_network(self):
        """Test connectivity to local network components"""
        print("\n📡 Testing Local Network Connectivity\n")
        
        # Modify these IPs based on your actual network configuration
        # These are examples - you should update them!
        hosts = [
            ('192.168.189.10', 'Kali Linux (Attacker)'),
            ('192.168.189.20', 'Ubuntu Victim'),
            ('192.168.189.30', 'Ubuntu Defender (IDS)'),
            ('192.168.189.2', 'VMware Gateway'),
        ]
        
        for ip, name in hosts:
            self.ping_host(ip, name)
    
    def test_internet_connectivity(self):
        """Test internet connectivity"""
        print("\n🌍 Testing Internet Connectivity\n")
        
        hosts = [
            ('8.8.8.8', 'Google DNS'),
            ('1.1.1.1', 'Cloudflare DNS'),
        ]
        
        for ip, name in hosts:
            self.ping_host(ip, name)
    
    def print_summary(self):
        """Print test summary"""
        total = self.passed + self.failed
        pass_rate = (self.passed / total * 100) if total > 0 else 0
        
        print("\n" + "=" * 70)
        print("📊 Test Summary")
        print("=" * 70)
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"Pass Rate: {pass_rate:.1f}%")
        print("=" * 70)
        
        if self.failed > 0:
            print("\n⚠️  Failed Tests:")
            for result in self.results:
                if result['status'] != 'PASS':
                    print(f"   - {result['test']} ({result['ip']}): {result['status']}")
        
        print(f"\nFinished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70 + "\n")
        
        return self.failed == 0
    
    def run(self):
        """Run all connectivity tests"""
        self.print_header()
        self.test_local_network()
        self.test_internet_connectivity()
        success = self.print_summary()
        return success


def main():
    """Main function"""
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║  IDS Platform - Network Connectivity Test Suite               ║
    ║                                                                ║
    ║  This test verifies that all VMs can communicate properly      ║
    ╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Important notice
    print("⚠️  IMPORTANT: Update the IP addresses in this script to match your network!")
    print("   Edit tests/test_connectivity.py and change the IPs in test_local_network()\n")
    
    # Run tests
    test = NetworkConnectivityTest()
    success = test.run()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
