import os
import sys
import subprocess
import time
from datetime import datetime
from pathlib import Path
import signal

TARGET_IP = "192.168.1.20"
PCAP_DIR = "./pcap_captures"

SCAN_TYPES = [
    "ICMP_PING", 
    "TCP_SYN_SCAN",
    "TCP_CONNECT",
    "TCP_NULL",
    "TCP_FIN",
    "TCP_XMAS",
    "TCP_ACK",
    "UDP_SCAN",
    "OS_DETECT",
]

SCAN_DURATION = {
    "ARP_PING": 10,
    "ICMP_PING": 10,
    "TCP_SYN_PING": 10,
    "TCP_SYN_SCAN": 60,
    "TCP_CONNECT": 60,
    "TCP_NULL": 60,
    "TCP_FIN": 60,
    "TCP_XMAS": 60,
    "TCP_ACK": 60,
    "UDP_SCAN": 120,
    "OS_DETECT": 90,
}

SCAN_FILTERS = {
    "ICMP_PING": f"icmp and host {TARGET_IP}",
    "TCP_SYN_SCAN": f"tcp[13] & 0x02 != 0 and host {TARGET_IP}",
    "TCP_CONNECT": f"tcp[13] & 0x02 != 0 and host {TARGET_IP}",   
    "TCP_NULL": f"tcp[13] = 0 and host {TARGET_IP}",
    "TCP_FIN": f"tcp[13] & 0x01 != 0 and host {TARGET_IP}",
    "TCP_XMAS": f"(tcp[13] & 0x29) = 0x29 and host {TARGET_IP}",
    "TCP_ACK": f"tcp[13] & 0x10 != 0 and host {TARGET_IP}",
    "UDP_SCAN": f"(udp and host {TARGET_IP}) or (icmp[0] = 3 and icmp[1] = 3 and host {TARGET_IP})",
    "OS_DETECT": f"(tcp or icmp) and host {TARGET_IP}",
}

SNAPLEN = {
    "ICMP_PING": 96,
    "TCP_SYN_SCAN": 96,
    "TCP_CONNECT": 96,
    "TCP_NULL": 96,
    "TCP_FIN": 96,
    "TCP_XMAS": 96,
    "TCP_ACK": 96,
    "UDP_SCAN": 128,
    "OS_DETECT": 256,
}

class PCAPCapture:
    def __init__(self):
        self.interface = self.detect_interface()
        self.pcap_dir = Path(PCAP_DIR)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.process = None
        
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
    
    def detect_interface(self):
        try:
            result = subprocess.run(['ip', '-o', '-4', 'addr', 'show'],
                                  capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if '192.168' in line:
                    return line.split()[1]
            
            result = subprocess.run(['ip', 'link', 'show'],
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'state UP' in line and 'lo' not in line:
                    return line.split(':')[1].strip()
            
            return "eth0"
        except:
            return "eth0"
    
    def setup_interface(self):
        subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'],
                      capture_output=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'promisc', 'on'],
                      capture_output=True)
        
        result = subprocess.run(['ip', 'link', 'show', self.interface],
                              capture_output=True, text=True)
        if 'PROMISC' in result.stdout:
            print(f"✓ Interface {self.interface} - Promiscuous mode ON")
    
    def capture_auto(self, scan_type, duration, index, total):
        output_file = self.pcap_dir / f"{scan_type}_{self.timestamp}.pcap"
        bpf_filter = SCAN_FILTERS[scan_type]
        snaplen = SNAPLEN[scan_type]
        
        print(f"\n[{index}/{total}] {scan_type}")
        print(f"  Filter: {bpf_filter}")
        print(f"  Duration: ~{duration}s")
        print(f"  File: {output_file.name}")
        
        cmd = [
            'sudo', 'timeout', str(duration + 10),  
            'tcpdump',
            '-i', self.interface,
            '-s', str(snaplen),
            '-w', str(output_file),
            bpf_filter
        ]
        
        try:
            print(f"Capturing...", end='', flush=True)
            
            self.process = subprocess.Popen(cmd,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            
            self.process.wait(timeout=duration + 15)
            
        except subprocess.TimeoutExpired:
            if self.process:
                self.process.terminate()
                time.sleep(0.5)
        except Exception:
            pass
        finally:
            if self.process and self.process.poll() is None:
                self.process.kill()
        
        time.sleep(1)  
        
        if output_file.exists():
            packets = self.count_packets(str(output_file))
            size = self.get_size(str(output_file))
            print(f"\r  ✓ {packets} packets ({size})")
            return str(output_file)
        else:
            print(f"\r  x No packets")
            return None
    
    def capture_manual(self, scan_type, index, total):
        output_file = self.pcap_dir / f"{scan_type}_{self.timestamp}.pcap"
        bpf_filter = SCAN_FILTERS[scan_type]
        snaplen = SNAPLEN[scan_type]
        
        print(f"\n[{index}/{total}] {scan_type}")
        print(f"  Filter: {bpf_filter}")
        print(f"  File: {output_file.name}")
        
        cmd = [
            'sudo', 'tcpdump',
            '-i', self.interface,
            '-s', str(snaplen),
            '-w', str(output_file),
            bpf_filter
        ]
        
        print(f"  Capturing... (Ctrl+C khi scan xong)")
        
        try:
            self.process = subprocess.Popen(cmd,
                                          stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            self.process.wait()
            
        except KeyboardInterrupt:
            if self.process:
                self.process.terminate()
                time.sleep(0.5)
                if self.process.poll() is None:
                    self.process.kill()
            
            time.sleep(1)
            
            if output_file.exists():
                packets = self.count_packets(str(output_file))
                size = self.get_size(str(output_file))
                print(f"\r  ✓ {packets} packets ({size})")
                return str(output_file)
            else:
                print(f"\r  ✗ No packets")
                return None
    
    def count_packets(self, pcap_file):
        try:
            result = subprocess.run(['tcpdump', '-r', pcap_file, '-n'],
                                  capture_output=True, text=True,
                                  stderr=subprocess.DEVNULL)
            return len([l for l in result.stdout.split('\n') if l.strip()])
        except:
            return 0
    
    def get_size(self, pcap_file):
        try:
            size = os.path.getsize(pcap_file)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f}{unit}"
                size /= 1024.0
        except:
            return "0B"
    
    def run_auto(self):
        print(f"\n{'='*60}")
        print(f"  AUTO CAPTURE MODE")
        print(f"{'='*60}")
        print(f"Interface: {self.interface}")
        print(f"Target: {TARGET_IP}")
        print(f"Total: {len(SCAN_TYPES)} scans")
        print(f"Output: {self.pcap_dir}/")
        print(f"{'='*60}")
        
        print(f"\nHƯỚNG DẪN:")
        print("1. Giữ terminal này mở")
        print("2. Trên Attacker VM, chạy:")
        print(f"   sudo python3 attacker_nmap_scanner.py")
        print("3. Script sẽ TỰ ĐỘNG bắt từng scan")
        print("4. Đợi cho đến khi hoàn thành 12 scans")
        
        input(f"\nNhấn Enter để bắt đầu...")
        
        captured = []
        
        for idx, scan_type in enumerate(SCAN_TYPES, 1):
            duration = SCAN_DURATION[scan_type]
            pcap_file = self.capture_auto(scan_type, duration, idx, len(SCAN_TYPES))
            
            if pcap_file:
                captured.append(pcap_file)

            if idx < len(SCAN_TYPES):
                print(f"  Waiting 5s...")
                time.sleep(5)
        
        self.print_summary(captured)
    
    def run_manual(self):
        print(f"\n{'='*60}")
        print(f"  MANUAL CAPTURE MODE")
        print(f"{'='*60}")
        print(f"Interface: {self.interface}")
        print(f"Target: {TARGET_IP}")
        print(f"Total: {len(SCAN_TYPES)} scans")
        print(f"Output: {self.pcap_dir}/")
        print(f"{'='*60}")
        
        print(f"\nHƯỚNG DẪN:")
        print("1. Giữ terminal này mở")
        print("2. Trên Attacker VM, chạy:")
        print(f"   sudo python3 attacker_nmap_scanner.py")
        print("3. Với mỗi scan:")
        print("   - Nhấn Ctrl+C khi scan hoàn thành")
        print("   - Nhấn Enter cho scan tiếp theo")
        
        input(f"\nNhấn Enter để bắt đầu...")
        
        captured = []
        
        for idx, scan_type in enumerate(SCAN_TYPES, 1):
            pcap_file = self.capture_manual(scan_type, idx, len(SCAN_TYPES))
            
            if pcap_file:
                captured.append(pcap_file)
            
            if idx < len(SCAN_TYPES):
                input(f"\nNhấn Enter cho scan tiếp theo...")
        
        self.print_summary(captured)
    
    def print_summary(self, captured):
        print(f"\n{'='*60}")
        print(f"  HOÀN THÀNH")
        print(f"{'='*60}")
        print(f"Đã bắt: {len(captured)}/{len(SCAN_TYPES)} files")
        print(f"Thư mục: {self.pcap_dir}")
        
        if captured:
            print(f"\nDanh sách files:")
            for f in captured:
                print(f"  • {os.path.basename(f)}")
        
        print(f"{'='*60}\n")


def main():
    if os.geteuid() != 0:
        print(f"[!] Phải chạy với quyền root")
        print(f"    sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    print(f"\n{'='*60}")
    print(f"  PCAP CAPTURE - 12 NMAP SCANS")
    print(f"{'='*60}")
    
    capture = PCAPCapture()
    capture.setup_interface()
    
    print(f"\nChọn mode:")
    print("  1. AUTO   - Tự động bắt (khuyên dùng)")
    print("  2. MANUAL - Nhấn Ctrl+C mỗi scan")
    
    mode = input(f"\nChọn [1/2]: ").strip()
    
    if mode == "2":
        capture.run_manual()
    else:
        capture.run_auto()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[!] Đã dừng\n")
    except Exception as e:
        print(f"\n[!] Lỗi: {e}\n")
