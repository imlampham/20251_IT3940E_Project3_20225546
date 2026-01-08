from scapy.all import *
import sys
import socket
import struct
import time
from datetime import datetime

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class NetworkScanner:
    def __init__(self, target, ports=None, timeout=2):
        self.target = target
        self.timeout = timeout
        
        if ports is None:
            self.ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
                         143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        else:
            self.ports = ports
            
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[!] Không thể resolve hostname: {target}")
            sys.exit(1)
    
    def print_banner(self):
        print("=" * 60)
        print("NETWORK SCANNER - Python Implementation")
        print("=" * 60)
        print(f"Target: {self.target} ({self.target_ip})")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
    
    # ICMP PING SCAN 
    def icmp_ping_scan(self):
        """
        ICMP Ping Scan - Kiểm tra host có hoạt động không
        Gửi ICMP Echo Request và chờ Echo Reply
        """
        print("\n[*] Đang thực hiện ICMP Ping Scan...")
        
        # Tạo gói ICMP Echo Request
        packet = IP(dst=self.target_ip)/ICMP()
        
        # Gửi gói tin và nhận phản hồi
        response = sr1(packet, timeout=self.timeout, verbose=0)
        
        if response is None:
            print(f"[!] Host {self.target_ip} không phản hồi ICMP")
            return False
        elif response.haslayer(ICMP):
            if response.getlayer(ICMP).type == 0:  # Echo Reply
                print(f"[+] Host {self.target_ip} đang hoạt động (ICMP Echo Reply)")
                return True
        
        return False
    
    # TCP SYN SCAN 
    def tcp_syn_scan(self):
        """
        TCP SYN Scan (Half-Open Scan) - Stealth scan
        Gửi SYN, nếu nhận SYN-ACK thì port mở, gửi RST để không hoàn thành handshake
        """
        print("\n[*] Đang thực hiện TCP SYN Scan ...")
        open_ports = []
        
        for port in self.ports:
            # Tạo gói SYN
            src_port = RandShort()
            packet = IP(dst=self.target_ip)/TCP(sport=src_port, dport=port, flags='S')
            
            # Gửi và nhận phản hồi
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                # Không có phản hồi (filtered hoặc dropped)
                continue
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    open_ports.append(port)
                    # Gửi RST để đóng kết nối
                    rst_packet = IP(dst=self.target_ip)/TCP(sport=src_port, dport=port, flags='R')
                    send(rst_packet, verbose=0)
                    print(f"  [+] Port {port}/tcp open")
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    # Port đóng
                    pass
        
        print(f"\n[+] Tìm thấy {len(open_ports)} cổng mở")
        return open_ports
    
    # TCP CONNECT SCAN 
    def tcp_connect_scan(self):
        """
        TCP Connect Scan - Full connection scan
        Hoàn thành 3-way handshake đầy đủ
        """
        print("\n[*] Đang thực hiện TCP Connect Scan...")
        open_ports = []
        
        for port in self.ports:
            try:
                # Tạo socket và thử kết nối
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    open_ports.append(port)
                    print(f"  [+] Port {port}/tcp open")
                    
                    # Thử lấy banner
                    try:
                        sock.send(b"GET / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            print(f"      Banner: {banner[:50]}...")
                    except:
                        pass
                
                sock.close()
            except socket.error:
                pass
        
        print(f"\n[+] Tìm thấy {len(open_ports)} cổng mở")
        return open_ports
    
    # TCP NULL SCAN
    def tcp_null_scan(self):
        """
        TCP Null Scan - Gửi gói TCP không có flags
        Port mở: Không có phản hồi
        Port đóng: RST
        """
        print("\n[*] Đang thực hiện TCP Null Scan...")
        open_filtered_ports = []
        
        for port in self.ports:
            # Tạo gói TCP không có flags
            packet = IP(dst=self.target_ip)/TCP(dport=port, flags='')
            
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                # Không có phản hồi -> có thể mở hoặc filtered
                open_filtered_ports.append(port)
                print(f"  [?] Port {port}/tcp open|filtered")
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    # Port đóng
                    pass
            elif response.haslayer(ICMP):
                # ICMP unreachable -> filtered
                pass
        
        print(f"\n[+] Tìm thấy {len(open_filtered_ports)} cổng open|filtered")
        return open_filtered_ports
    
    # TCP FIN SCAN 
    def tcp_fin_scan(self):
        """
        TCP FIN Scan - Gửi gói TCP với FIN flag
        Port mở: Không có phản hồi
        Port đóng: RST
        """
        print("\n[*] Đang thực hiện TCP FIN Scan...")
        open_filtered_ports = []
        
        for port in self.ports:
            # Tạo gói TCP với FIN flag
            packet = IP(dst=self.target_ip)/TCP(dport=port, flags='F')
            
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                open_filtered_ports.append(port)
                print(f"  [?] Port {port}/tcp open|filtered")
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    pass
            elif response.haslayer(ICMP):
                pass
        
        print(f"\n[+] Tìm thấy {len(open_filtered_ports)} cổng open|filtered")
        return open_filtered_ports
    
    # TCP XMAS SCAN 
    def tcp_xmas_scan(self):
        """
        TCP Xmas Scan - Gửi gói TCP với FIN, PSH, URG flags
        Port mở: Không có phản hồi
        Port đóng: RST
        """
        print("\n[*] Đang thực hiện TCP Xmas Scan...")
        open_filtered_ports = []
        
        for port in self.ports:
            # Tạo gói TCP với FIN, PSH, URG flags
            packet = IP(dst=self.target_ip)/TCP(dport=port, flags='FPU')
            
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                open_filtered_ports.append(port)
                print(f"  [?] Port {port}/tcp open|filtered")
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    pass
            elif response.haslayer(ICMP):
                pass
        
        print(f"\n[+] Tìm thấy {len(open_filtered_ports)} cổng open|filtered")
        return open_filtered_ports
    
    # TCP ACK SCAN 
    def tcp_ack_scan(self):
        """
        TCP ACK Scan
        Dùng để xác định port có bị firewall filter không
        RST: Unfiltered
        Không có phản hồi hoặc ICMP unreachable: Filtered
        """
        print("\n[*] Đang thực hiện TCP ACK Scan ...")
        unfiltered_ports = []
        filtered_ports = []
        
        for port in self.ports:
            # Tạo gói TCP với ACK flag
            packet = IP(dst=self.target_ip)/TCP(dport=port, flags='A')
            
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                filtered_ports.append(port)
                print(f"  [!] Port {port}/tcp filtered")
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x4:  # RST
                    unfiltered_ports.append(port)
                    print(f"  [+] Port {port}/tcp unfiltered")
            elif response.haslayer(ICMP):
                filtered_ports.append(port)
                print(f"  [!] Port {port}/tcp filtered (ICMP)")
        
        print(f"\n[+] Unfiltered: {len(unfiltered_ports)}, Filtered: {len(filtered_ports)}")
        return unfiltered_ports, filtered_ports
    
    # UDP SCAN 
    def udp_scan(self):
        """
        UDP Scan - Scan cổng UDP
        Port mở: Có thể có phản hồi UDP hoặc không có gì
        Port đóng: ICMP port unreachable
        """
        print("\n[*] Đang thực hiện UDP Scan...")
        open_ports = []
        
        for port in self.ports:
            # Tạo gói UDP
            packet = IP(dst=self.target_ip)/UDP(dport=port)
            
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                # Không có phản hồi -> có thể open hoặc filtered
                open_ports.append(port)
                print(f"  [?] Port {port}/udp open|filtered")
            elif response.haslayer(UDP):
                # Nhận được phản hồi UDP -> port mở
                open_ports.append(port)
                print(f"  [+] Port {port}/udp open")
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and \
                   int(response.getlayer(ICMP).code) == 3:
                    # Port unreachable -> port đóng
                    pass
        
        print(f"\n[+] Tìm thấy {len(open_ports)} cổng UDP open|filtered")
        return open_ports
    
    # OS DETECTION 
    def os_detection(self):
        """
        OS Detection 
        Dựa trên TTL và Window Size trong phản hồi TCP/IP
        """
        print("\n[*] Đang thực hiện OS Detection...")
        # Gửi các gói khác nhau để phân tích
        # TCP SYN đến port mở (hoặc port phổ biến)
        packet = IP(dst=self.target_ip)/TCP(dport=80, flags='S')
        response = sr1(packet, timeout=self.timeout, verbose=0)
        
        if response is None:
            print("[!] Không nhận được phản hồi để phát hiện OS")
            return
        
        # Phân tích TTL
        ttl = response.ttl
        window_size = response.getlayer(TCP).window if response.haslayer(TCP) else 0
        
        print(f"[*] TTL: {ttl}")
        print(f"[*] Window Size: {window_size}")
        
        # Dự đoán OS dựa trên TTL
        os_guess = "Unknown"
        
        if ttl <= 64:
            os_guess = "Linux/Unix (TTL ~64)"
        elif ttl <= 128:
            os_guess = "Windows (TTL ~128)"
        elif ttl <= 255:
            os_guess = "Solaris/AIX (TTL ~255)"
        
        # Phân tích thêm dựa trên window size
        if window_size == 8192:
            os_guess += " - Có thể là Windows (Windows sử dụng window size 8192)"
        elif window_size >= 5840:
            os_guess += " - Có thể là Linux (Linux thường dùng window size lớn)"
        
        print(f"\n[+] OS Detection: {os_guess}")
        
        # Kiểm tra ICMP để có thêm thông tin
        icmp_packet = IP(dst=self.target_ip)/ICMP()
        icmp_response = sr1(icmp_packet, timeout=self.timeout, verbose=0)
        
        if icmp_response:
            print(f"[*] ICMP Response TTL: {icmp_response.ttl}")
        
        return os_guess


def main():
    if len(sys.argv) < 2:
        print("Sử dụng: python3 network_scanner.py <target> [ports]")
        print("Ví dụ: python3 network_scanner.py 192.168.1.1")
        print("       python3 network_scanner.py scanme.nmap.org 80,443,8080")
        sys.exit(1)
    
    target = sys.argv[1]

    ports = None
    if len(sys.argv) >= 3:
        try:
            ports = [int(p) for p in sys.argv[2].split(',')]
        except ValueError:
            print("[!] Định dạng ports không hợp lệ. Sử dụng: 80,443,8080")
            sys.exit(1)
    
    scanner = NetworkScanner(target, ports)
    scanner.print_banner()
    
    print("\nChọn loại scan:")
    print("1. ICMP Ping Scan")
    print("2. TCP SYN Scan (Stealth)")
    print("3. TCP Connect Scan")
    print("4. TCP Null Scan")
    print("5. TCP FIN Scan")
    print("6. TCP Xmas Scan")
    print("7. TCP ACK Scan (Firewall Detection)")
    print("8. UDP Scan")
    print("9. OS Detection")
    print("0. Chạy tất cả các scan")
    
    choice = input("\nNhập lựa chọn (0-9): ").strip()
    
    print("\n" + "=" * 60)
    
    if choice == '1':
        scanner.icmp_ping_scan()
    elif choice == '2':
        scanner.tcp_syn_scan()
    elif choice == '3':
        scanner.tcp_connect_scan()
    elif choice == '4':
        scanner.tcp_null_scan()
    elif choice == '5':
        scanner.tcp_fin_scan()
    elif choice == '6':
        scanner.tcp_xmas_scan()
    elif choice == '7':
        scanner.tcp_ack_scan()
    elif choice == '8':
        scanner.udp_scan()
    elif choice == '9':
        scanner.os_detection()
    elif choice == '0':
        scanner.icmp_ping_scan()
        scanner.tcp_syn_scan()
        scanner.tcp_connect_scan()
        scanner.tcp_null_scan()
        scanner.tcp_fin_scan()
        scanner.tcp_xmas_scan()
        scanner.tcp_ack_scan()
        scanner.udp_scan()
        scanner.os_detection()
    else:
        print("[!] Lựa chọn không hợp lệ")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print(f"Scan hoàn thành lúc: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Cảnh báo: Script này cần quyền root/administrator")
        print("[!] Chạy với: sudo python3 network_scanner.py <target>")
        print("[!] Một số scan có thể không hoạt động nếu không có quyền root")
        print()
    
    main()
