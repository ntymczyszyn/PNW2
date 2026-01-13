from cicflowmeter.sniffer import create_sniffer
import os
from scapy.all import rdpcap

from scapy.all import sniff

pkts = rdpcap("S:\\PWR\\PNW\\PNW2\\pcap_files\\traffic_20260111_160419_0.pcap")
print("Packets:", len(pkts))

exit()
# Ensure output directory exists
output_dir = 'S:\\PWR\\PNW\\PNW2\\csv_files'
os.makedirs(output_dir, exist_ok=True)

# Create sniffer with correct parameters
# create_sniffer returns (sniffer, session)
sniffer = create_sniffer(
    input_file='S:\\PWR\\PNW\\PNW2\\pcap_files\\traffic_20260111_160419_0.pcap',
    input_interface=None,
    output_mode="csv",  # Must be "csv" or "url"
    output_file='S:\\PWR\\PNW\\PNW2\\csv_files\\traffic_20260111_160419_0.csv'
    )

print(f"Starting PCAP processing...")
print(f"Output will be saved to: S:\\PWR\\PNW\\PNW2\\csv_files\\")

# Start the sniffer
sniffer.start()

try:
    # Wait for completion
    sniffer.join()
    print(f"\nProcessing complete! Check the CSV files in:")
    print(f"S:\\PWR\\PNW\\PNW2\\csv_files\\")
    
except KeyboardInterrupt:
    print('\nStopping the sniffer...')
    sniffer.stop()
    sniffer.join()
    
except Exception as e:
    print(f"\nError occurred: {e}")
    import traceback
    traceback.print_exc()
    sniffer.stop()

# finally:
#     # Stop periodic GC if present
#     if hasattr(session, "_gc_stop"):
#         session._gc_stop.set()
#         session._gc_thread.join(timeout=2.0)
#     # Flush all flows at the end
#     session.flush_flows()