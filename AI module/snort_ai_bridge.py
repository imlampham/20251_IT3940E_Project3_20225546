import os
import sys
import time
import logging
import threading
import subprocess
from datetime import datetime
from scapy.all import *

sys.path.insert(0, '/usr/local/bin')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from webshell_ai_detector import detector, analyze_http_payload
except ImportError:
    print("ERROR: Không thể import webshell_ai_detector")
    sys.exit(1)


BRIDGE_IFACE_IN = "ens33"  
BRIDGE_IFACE_OUT = "ens38"  

LOG_DIR = "/var/log/snort"
LOG_FILE = f"{LOG_DIR}/ai_analysis_bridge.log"
ALERT_FILE = f"{LOG_DIR}/alerts_bridge.txt"
BLOCK_LIST_FILE = f"{LOG_DIR}/blocked_ips.txt"

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SnortAI-Bridge')


class BridgePacketAnalyzer:
    
    def __init__(self):
        self.packet_count = 0
        self.alert_count = 0
        self.blocked_ips = set()
        self.alert_by_ip = {}
        self.start_time = time.time()
        self.ml_errors = 0
        self.signature_detections = 0
        
        self.load_blocked_ips()
        
        # Load AI model with error handling
        logger.info("Loading AI model...")
        try:
            if detector.load_model():
                logger.info(f" AI model loaded successfully")
                self.ml_available = True
            else:
                logger.warning(f" No pre-trained model found")
                logger.warning(f"  Using signature detection only")
                logger.warning(f"  Run: python3 train_model.py to train the model")
                self.ml_available = False
        except Exception as e:
            logger.error(f" Error loading model: {e}")
            logger.warning(f"  Falling back to signature detection only")
            self.ml_available = False
    
    def load_blocked_ips(self):
        """Load blocked IPs from file"""
        try:
            if os.path.exists(BLOCK_LIST_FILE):
                with open(BLOCK_LIST_FILE, 'r') as f:
                    self.blocked_ips = set(line.strip() for line in f if line.strip())
                logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs")
        except Exception as e:
            logger.error(f"Error loading blocked IPs: {e}")
    
    def save_blocked_ip(self, ip):
        """Save blocked IP to file"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            try:
                os.makedirs(os.path.dirname(BLOCK_LIST_FILE), exist_ok=True)
                with open(BLOCK_LIST_FILE, 'a') as f:
                    f.write(f"{ip}\n")
                logger.info(f"Added {ip} to blocklist file")
            except Exception as e:
                logger.error(f"Error saving blocked IP: {e}")
    
    def verify_ip_blocked(self, ip):
        try:
        # Check INPUT chain
            result = subprocess.run(
                ['iptables', '-L', 'INPUT', '-n', '-v'],
                capture_output=True,
                text=True,
                timeout=5
            )
        
            if ip in result.stdout:
                logger.debug(f"✓ Found {ip} in INPUT chain")
                return True
        
        # Check FORWARD chain (MOST IMPORTANT for bridge)
            result = subprocess.run(
                ['iptables', '-L', 'FORWARD', '-n', '-v'],
                capture_output=True,
                text=True,
                timeout=5
            )
        
            if ip in result.stdout:
                logger.debug(f"✓ Found {ip} in FORWARD chain")
            
            # Count how many rules (should be at least 4 for bidirectional)
                rule_count = result.stdout.count(ip)
                logger.debug(f"✓ Found {rule_count} FORWARD rules for {ip}")
            
                if rule_count >= 2:  # At least 2 rules (source + destination)
                    return True
        
        # Check OUTPUT chain
            result = subprocess.run(
                ['iptables', '-L', 'OUTPUT', '-n', '-v'],
                capture_output=True,
                text=True,
                timeout=5
            )
        
            return ip in result.stdout
        
        except Exception as e:
            logger.error(f"Error verifying block: {e}")
            return False
    
    def block_ip_with_iptables(self, ip, reason="Malicious activity detected"):
        try:
            if ip in self.blocked_ips:
                logger.info(f"IP {ip} already in blocked list")
                return True
        
            logger.info(f"\n{'='*70}")
            logger.info(f"BLOCKING IP: {ip}")
            logger.info(f"Reason: {reason}")
            logger.info(f"{'='*70}")
        
            rules_added = 0
            failed_rules = 0
        
            for iface in [BRIDGE_IFACE_IN, BRIDGE_IFACE_OUT]:
            
            # ========================================
            # 1. Block packets FROM this IP (source)
            # ========================================
            
            # INPUT chain (packets to local system)
                cmd1 = ['iptables', '-I', 'INPUT', '-i', iface, '-s', ip, '-j', 'DROP']
                result1 = subprocess.run(cmd1, capture_output=True)
                if result1.returncode == 0:
                    rules_added += 1
                    logger.info(f"  ✓ INPUT -s {ip} on {iface}")
                else:
                    failed_rules += 1
                    logger.error(f"  ✗ INPUT -s {ip} on {iface} FAILED")
            
            # FORWARD chain (packets being routed through - MOST IMPORTANT!)
                cmd2 = ['iptables', '-I', 'FORWARD', '-i', iface, '-s', ip, '-j', 'DROP']
                result2 = subprocess.run(cmd2, capture_output=True)
                if result2.returncode == 0:
                    rules_added += 1
                    logger.info(f"  ✓ FORWARD -s {ip} on {iface}")
                else:
                    failed_rules += 1
                    logger.error(f"  ✗ FORWARD -s {ip} on {iface} FAILED")
            
            # ========================================
            # 2. Block packets TO this IP (destination) ← ✅ CRITICAL!
            # ========================================
            
            # FORWARD chain (outgoing direction)
                cmd3 = ['iptables', '-I', 'FORWARD', '-o', iface, '-d', ip, '-j', 'DROP']
                result3 = subprocess.run(cmd3, capture_output=True)
                if result3.returncode == 0:
                    rules_added += 1
                    logger.info(f"  ✓ FORWARD -d {ip} on {iface}")
                else:
                    failed_rules += 1
                    logger.error(f"  ✗ FORWARD -d {ip} on {iface} FAILED")
            
                # OUTPUT chain (packets from local system)
                cmd4 = ['iptables', '-I', 'OUTPUT', '-o', iface, '-d', ip, '-j', 'DROP']
                result4 = subprocess.run(cmd4, capture_output=True)
                if result4.returncode == 0:
                    rules_added += 1
                    logger.info(f"  ✓ OUTPUT -d {ip} on {iface}")
                else:
                    failed_rules += 1
                    logger.error(f"  ✗ OUTPUT -d {ip} on {iface} FAILED")
        
        # ========================================
        # 3. Additional REJECT rules (for feedback)
        # ========================================
        
        # Global INPUT REJECT (any interface)
            cmd5 = ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'REJECT', '--reject-with', 'icmp-port-unreachable']
            result5 = subprocess.run(cmd5, capture_output=True)
            if result5.returncode == 0:
                rules_added += 1
                logger.info(f"  ✓ INPUT REJECT (global)")
        
        # Global FORWARD REJECT (any interface)
            cmd6 = ['iptables', '-I', 'FORWARD', '-s', ip, '-j', 'REJECT', '--reject-with', 'icmp-port-unreachable']
            result6 = subprocess.run(cmd6, capture_output=True)
            if result6.returncode == 0:
                rules_added += 1
                logger.info(f"  ✓ FORWARD REJECT (global)")
        
            logger.info(f"\n  Rules added: {rules_added}")
            logger.info(f"  Failed rules: {failed_rules}")
        
        # ========================================
        # 4. Verify blocking
        # ========================================
        
            time.sleep(0.5)  # Let iptables apply
            is_blocked = self.verify_ip_blocked(ip)
        
            if is_blocked:
            # Success!
                self.save_blocked_ip(ip)
            
                logger.critical(f"\n{GREEN}✓ BLOCKED & VERIFIED{RESET}")
                logger.critical(f"  IP: {ip}")
                logger.critical(f"  Reason: {reason}")
                logger.critical(f"  Rules: {rules_added}/{rules_added + failed_rules}")
            
            # Write to alert file
                with open(ALERT_FILE, 'a') as f:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"[BLOCKED & VERIFIED] {datetime.now()}\n")
                    f.write(f"IP: {ip}\n")
                    f.write(f"Reason: {reason}\n")
                    f.write(f"Rules Added: {rules_added}\n")
                    f.write(f"Failed Rules: {failed_rules}\n")
                    f.write(f"Verification: SUCCESS\n")
                    f.write(f"{'='*80}\n")
            
            # Console box
                print(f"\n{RED}╔{'═'*78}╗{RESET}")
                print(f"{RED}║{GREEN} {'BLOCKED & VERIFIED':^76} {RED}║{RESET}")
                print(f"{RED}║{RESET} IP: {ip:^72} {RED}║{RESET}")
                print(f"{RED}║{RESET} Reason: {reason[:68]:^72} {RED}║{RESET}")
                print(f"{RED}║{RESET} Rules: {f'{rules_added}/{rules_added+failed_rules}':^72} {RED}║{RESET}")
                print(f"{RED}╚{'═'*78}╝{RESET}\n")
            
                return True
            else:
            # Failed verification
                logger.error(f"\n{RED}✗ BLOCKING FAILED{RESET}")
                logger.error(f"  IP: {ip}")
                logger.error(f"  Rules added: {rules_added}, but not verified in iptables")
                logger.error(f"\nManual fix:")
                logger.error(f"  sudo iptables -I FORWARD -s {ip} -j DROP")
                logger.error(f"  sudo iptables -I FORWARD -d {ip} -j DROP")
            
                return False
        
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False
    
    def analyze_packet(self, packet):
        """Main packet analysis function"""
        self.packet_count += 1
        
        # Debug output for first 10 packets
        if self.packet_count <= 10:
            print(f"[DEBUG] Packet #{self.packet_count}: {packet.summary()}")
        
        # Progress logging
        if self.packet_count % 100 == 0:
            elapsed = time.time() - self.start_time
            rate = self.packet_count / elapsed if elapsed > 0 else 0
            logger.info(
                f"Processed {self.packet_count} packets | "
                f"Rate: {rate:.1f} pkt/s | "
                f"Alerts: {self.alert_count} | "
                f"Blocked: {len(self.blocked_ips)} | "
                f"ML errors: {self.ml_errors} | "
                f"Signature hits: {self.signature_detections}"
            )
        
        try:
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Skip if already blocked
            if src_ip in self.blocked_ips:
                return
            
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                
                # Get payload
                payload = None
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                
                if not payload:
                    return
                
                # Convert payload to string
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                except:
                    payload_str = str(payload)
                
                # Check if suspicious
                if self.is_suspicious(payload_str):
                    self.analyze_suspicious_payload(src_ip, dst_ip, dst_port, payload_str, packet)
        
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}", exc_info=True)
    
    def is_suspicious(self, payload):
        """Quick signature-based check for suspicious content"""
        suspicious_keywords = [
            'system', 'eval', 'exec', 'shell_exec', 'passthru', 'assert',
            'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13',
            '$_GET', '$_POST', '$_REQUEST', '$_FILES', '$_COOKIE',
            '/bin/bash', '/bin/sh', 'cmd.exe', 'powershell',
            'bash -i', 'nc -e', 'fsockopen', 'socket',
            'move_uploaded_file', 'file_put_contents', 'fwrite',
            'create_function', 'preg_replace', 'chr(', '\\x'
        ]
        
        payload_lower = payload.lower()
        for keyword in suspicious_keywords:
            if keyword in payload_lower:
                return True
        
        return False
    
    def analyze_suspicious_payload(self, src_ip, dst_ip, dst_port, payload, packet):
        """Deep analysis of suspicious payload"""
        try:
            # Try AI analysis first
            result = None
            if self.ml_available:
                try:
                    result = analyze_http_payload(payload, src_ip, dst_ip, dst_port)
                except Exception as e:
                    self.ml_errors += 1
                    logger.warning(f"ML prediction error: {e}")
                    logger.warning("Falling back to signature detection")
                    result = None
            
            # If ML failed or not available, use signature detection only
            if result is None:
                result = {
                    'alert_level': 'CRITICAL',
                    'webshell_detection': {
                        'is_malicious': True,
                        'confidence': 0.85,  # Signature-based confidence
                        'detection_method': ['Signature_Only']
                    },
                    'revshell_detection': {
                        'is_reverse_shell': False,
                        'confidence_score': 0
                    }
                }
                self.signature_detections += 1
            
            # Check if critical
            if result['alert_level'] == 'CRITICAL':
                self.alert_count += 1
                self.alert_by_ip[src_ip] = self.alert_by_ip.get(src_ip, 0) + 1
                
                methods = result['webshell_detection']['detection_method']
                confidence = result['webshell_detection']['confidence']
                
                # Alert message
                alert_msg = f"""
                {'='*80}
                [ALERT #{self.alert_count}] Detected at {datetime.now()}
                Source: {src_ip} → Destination: {dst_ip}:{dst_port}
                Alerts from this IP: {self.alert_by_ip[src_ip]}

                Web Shell Detection:
                    Malicious: YES
                    Confidence: {confidence:.1%}
                    Detection Methods: {', '.join(methods)}

                Reverse Shell Detection:
                    Detected: {'YES' if result['revshell_detection']['is_reverse_shell'] else 'NO'}
                    Score: {result['revshell_detection']['confidence_score']}

                Payload Preview:
                    {payload[:300]}...
                    {'='*80}
                """
                
                # Log and print
                print(alert_msg)
                logger.critical(alert_msg)
                
                # Write to file
                with open(ALERT_FILE, 'a') as f:
                    f.write(alert_msg + '\n')
                
                # Console summary
                print(f"\n[ALERT #{self.alert_count}] {methods[0] if methods else 'DETECTED'}")
                print(f"  From: {src_ip} → To: {dst_ip}:{dst_port}")
                print(f"  Confidence: {confidence:.1%}")
                print(f"  Total alerts from this IP: {self.alert_by_ip[src_ip]}")
                
                # Auto-blocking logic
                should_block = False
                block_reason = ""
                
                if self.alert_by_ip[src_ip] >= 3:
                    should_block = True
                    block_reason = f"Multiple threats ({self.alert_by_ip[src_ip]} alerts): {', '.join(methods[:3])}"
                elif confidence >= 0.95 and 'Signature_WebShell' in methods:
                    should_block = True
                    block_reason = f"High confidence web shell ({confidence:.1%})"
                elif result['revshell_detection']['is_reverse_shell']:
                    should_block = True
                    block_reason = "Reverse shell detected"
                
                if should_block:
                    print(f"\n[AUTO-BLOCK TRIGGERED]")
                    print(f"  Reason: {block_reason}")
                    attacker_ip = self.track_attacker(src_ip, dst_ip, methods)
                    self.block_ip_with_iptables(attacker_ip, block_reason)
        
        except Exception as e:
            logger.error(f"Error in suspicious payload analysis: {e}", exc_info=True)


def check_bridge_interfaces():
    """Check if bridge interfaces exist and are UP"""
    print(f"\n{BLUE}Checking bridge interfaces...")
    
    interfaces = get_if_list()
    
    if BRIDGE_IFACE_IN in interfaces:
        print(f" {BRIDGE_IFACE_IN} found")
    else:
        print(f" {BRIDGE_IFACE_IN} not found!")
        return False
    
    if BRIDGE_IFACE_OUT in interfaces:
        print(f" {BRIDGE_IFACE_OUT} found")
    else:
        print(f" {BRIDGE_IFACE_OUT} not found!")
        return False
    
    # Check interface status
    for iface in [BRIDGE_IFACE_IN, BRIDGE_IFACE_OUT]:
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', iface], 
                capture_output=True,
                text=True,
                timeout=5
            )
            if 'state UP' in result.stdout:
                print(f" {iface} is UP")
            else:
                print(f" {iface} is DOWN - bringing up...")
                os.system(f"ip link set {iface} up")
        except Exception as e:
            logger.warning(f"Could not check {iface} status: {e}")
    
    return True


def test_bridge_traffic():
    """Test if there's traffic on bridge interfaces"""
    print(f"\n{BLUE}Testing bridge traffic (10 seconds)...")
    print(f"Sniffing on both {BRIDGE_IFACE_IN} and {BRIDGE_IFACE_OUT}")
    
    try:
        packets_in = sniff(iface=BRIDGE_IFACE_IN, count=5, timeout=5)
        packets_out = sniff(iface=BRIDGE_IFACE_OUT, count=5, timeout=5)
        
        print(f"\nResults:")
        print(f"  {BRIDGE_IFACE_IN}: {len(packets_in)} packets")
        print(f"  {BRIDGE_IFACE_OUT}: {len(packets_out)} packets")
        
        if len(packets_in) > 0 or len(packets_out) > 0:
            print(f" Bridge has traffic")
            return True
        else:
            print(f" No traffic detected on bridge")
            print(f"  → Try generating traffic through the bridge")
            return False
    
    except Exception as e:
        print(f" Error: {e}")
        return False


def setup_bridge_forwarding():
    """Setup bridge forwarding and iptables"""
    print(f"\n{BLUE}Setting up bridge forwarding...")
    
    try:
        # Enable IP forwarding
        os.system("sysctl -w net.ipv4.ip_forward=1")
        print(f" IP forwarding enabled")
        
        # Disable ICMP redirects
        os.system("sysctl -w net.ipv4.conf.all.send_redirects=0")
        os.system("sysctl -w net.ipv4.conf.all.accept_redirects=0")
        print(f" ICMP redirects disabled")
        
        # Allow forwarding
        os.system("iptables -P FORWARD ACCEPT")
        print(f" Bridge forwarding configured")
        
    except Exception as e:
        print(f" Error: {e}")


def main():
    """Main function"""
    
    # Check root
    if os.geteuid() != 0:
        print(f"ERROR: This script must be run as root!")
        print(f"Run: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    # Check interfaces
    if not check_bridge_interfaces():
        print(f"\nBridge interfaces not properly configured!")
        sys.exit(1)
    
    # Setup forwarding
    setup_bridge_forwarding()
    
    # Test traffic
    test_bridge_traffic()
    
    # Start analyzer
    print(f"\nStarting bridge packet analyzer...")
    print(f"Monitoring interfaces: {BRIDGE_IFACE_IN}, {BRIDGE_IFACE_OUT}")
    print(f"Log file: {LOG_FILE}")
    print(f"Alert file: {ALERT_FILE}")
    print(f"Blocked IPs: {BLOCK_LIST_FILE}")
    print(f"\nAuto-block triggers:")
    print(f"  • 3+ alerts from same IP")
    print(f"  • Web shell confidence >95%")
    print(f"  • Reverse shell detected")
    print(f"\nPress Ctrl+C to stop\n")
    
    analyzer = BridgePacketAnalyzer()
    
    def sniff_in():
        sniff(
            iface=BRIDGE_IFACE_IN,
            prn=analyzer.analyze_packet,
            store=False,
        )
    
    def sniff_out():
        sniff(
            iface=BRIDGE_IFACE_OUT,
            prn=analyzer.analyze_packet,
            store=False,
        )
    
    try:
        # Start sniffing threads
        thread_in = threading.Thread(target=sniff_in, daemon=True)
        thread_out = threading.Thread(target=sniff_out, daemon=True)
        
        thread_in.start()
        thread_out.start()
        
        logger.info("Bridge mode started - monitoring both interfaces")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print(f"\n\n{BLUE}Stopping bridge analyzer...")
        
        elapsed = time.time() - analyzer.start_time
        print(f"\nStatistics:")
        print(f"  Total packets analyzed: {analyzer.packet_count}")
        print(f"  Total alerts: {analyzer.alert_count}")
        print(f"  Blocked IPs: {len(analyzer.blocked_ips)}")
        print(f"  ML errors: {analyzer.ml_errors}")
        print(f"  Signature detections: {analyzer.signature_detections}")
        print(f"  Runtime: {elapsed:.1f} seconds")
        print(f"  Rate: {analyzer.packet_count/elapsed:.1f} packets/sec")
        print(f"\n  Log file: {LOG_FILE}")
        print(f"  Alert file: {ALERT_FILE}")
        print(f"  Blocked IPs: {BLOCK_LIST_FILE}")
        
        logger.info(
            f"Stopped. Packets: {analyzer.packet_count}, "
            f"Alerts: {analyzer.alert_count}, "
            f"Blocked: {len(analyzer.blocked_ips)}"
        )
    
    except Exception as e:
        print(f"\nERROR: {e}")
        logger.error(f"Fatal error: {e}", exc_info=True)


if __name__ == '__main__':
    main()