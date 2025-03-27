import argparse
from scapy.all import sniff, wrpcap
from scapy.interfaces import get_working_ifaces

def list_interfaces():
    print("Available interfaces:")
    for idx, iface in enumerate(get_working_ifaces()):
        print(f"{idx + 1}. {iface.name} - {iface.description}")

def capture_traffic(interface, output_file, duration=None, packet_count=None):
    print(f"\nStarting capture on interface {interface}...")
    print("Press Ctrl+C to stop capture and save to file.")
    
    try:
        sniff_kwargs = {
            'iface': interface,
            'prn': lambda pkt: print(f"Captured packet: {pkt.summary()}"),
            'store': True
        }
        
        if duration:
            sniff_kwargs['timeout'] = duration
        if packet_count:
            sniff_kwargs['count'] = packet_count
        
        packets = sniff(**sniff_kwargs)
        
        wrpcap(output_file, packets)
        print(f"\nCapture complete. Saved {len(packets)} packets to {output_file}")
        
    except Exception as e:
        print(f"\nError during capture: {e}")

def main():
    parser = argparse.ArgumentParser(description="Lightweight network sniffer for PCAP generation")
    parser.add_argument("-i", "--interface", help="Network interface to capture on")
    parser.add_argument("-o", "--output", default="capture.pcap", help="Output PCAP file (default: capture.pcap)")
    parser.add_argument("-d", "--duration", type=int, help="Capture duration in seconds")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
    parser.add_argument("-l", "--list", action="store_true", help="List available interfaces")
    
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
        return
    
    if not args.interface:
        print("Error: Please specify an interface with -i or use -l to list interfaces")
        return
    
    try:
        capture_traffic(
            interface=args.interface,
            output_file=args.output,
            duration=args.duration,
            packet_count=args.count
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user")

if __name__ == "__main__":
    main()
