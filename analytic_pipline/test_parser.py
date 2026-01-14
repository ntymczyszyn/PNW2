from cicflowmeter.sniffer import create_sniffer
from scapy.utils import wrpcap
import pandas as pd
import tempfile
import os


def packets_to_cic_df(packets):

    with tempfile.TemporaryDirectory() as tmp:
        pcap_path = os.path.join(tmp, "flow.pcap")
        csv_path = os.path.join(tmp, "flow.csv")

        # 1) Save packets to temp PCAP
        wrpcap(pcap_path, packets)

        # 2) Run CICFlowMeter
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

            # jeśli sesja ma flush (czasami przydaje się wymusić)
            if session is not None and hasattr(session, "flush_flows"):
                try:
                    session.flush_flows()
                except Exception:
                    pass

            # Jeśli dokładny csv_path nie istnieje, znajdź pierwszy CSV w tmp
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
            # upewnij się, że sniffer zatrzymany
            try:
                if hasattr(sniffer_thread, "stop"):
                    sniffer_thread.stop()
                    sniffer_thread.join(timeout=1.0)
            except Exception:
                pass
