from cicflowmeter.sniffer import create_sniffer
from scapy.utils import wrpcap
import pandas as pd
import tempfile
import os


def packets_to_cic_df(pcap_path):

    with tempfile.TemporaryDirectory() as tmp:
        #pcap_path = os.path.join(tmp, "flow.pcap")
        csv_path = os.path.join(tmp, "flow.csv")

        # tworzenie tymczasowego PCAP
        #wrpcap(pcap_path, packets)

        #CICFlowMeter
        ret = create_sniffer(
            input_file=pcap_path,
            input_interface=None,
            output_mode="csv",
            output=csv_path,
            fields=None,
            verbose=False
        )

        if isinstance(ret, (list, tuple)):
            sniffer_thread, session = ret[0], (ret[1] if len(ret) > 1 else None)
        else:
            sniffer_thread, session = ret, None

        try:
            sniffer_thread.start()
            sniffer_thread.join()

            if session is not None and hasattr(session, "flush_flows"):
                try:
                    session.flush_flows()
                except Exception:
                    pass

            if not os.path.exists(csv_path):
                cvs = [os.path.join(tmp, f) for f in os.listdir(tmp) if f.lower().endswith('.csv')]
                if cvs:
                    csv_path = cvs[0]
                else:
                    raise RuntimeError("CICFlowMeter did not generate CSV")

            df = pd.read_csv(csv_path)
            df.columns = df.columns.str.strip()
            return df

        finally:
            try:
                if hasattr(sniffer_thread, "stop"):
                    sniffer_thread.stop()
                    sniffer_thread.join(timeout=1.0)
            except Exception:
                pass

def process_stream_features(features_dict):
    """
    Przetwarza features przychodzące ze stream_packets
    Konwertuje je na format kompatybilny z traffic_predictor
    """
    if not features_dict:
        return None
    
    df = pd.DataFrame([features_dict])
    
    # Czyszczenie kolumn
    df.columns = df.columns.str.strip()
    
    # Zamiana nieskończoności na NaN, NaN na 0
    df = df.replace([float('inf'), float('-inf')], float('nan'))
    df = df.fillna(0)
    
    return df