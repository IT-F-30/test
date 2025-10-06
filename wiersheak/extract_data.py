#!/usr/bin/env python3
"""
winpeer.pcapngからTCPペイロードデータを抽出してメタデータファイルを作成
"""

from scapy.all import rdpcap, IP, TCP
import json

def extract_tcp_data(pcap_file, output_file="tcp_data.json"):
    """
    pcapngファイルからTCPデータを抽出してJSONファイルに保存
    """
    print(f"[+] {pcap_file}を読み込んでいます...")
    packets = rdpcap(pcap_file)
    
    extracted_data = []
    packet_count = 0
    
    for pkt in packets:
        # IPレイヤーとTCPレイヤーが存在するか確認
        if IP in pkt and TCP in pkt:
            if pkt[IP].src == "10.40.251.11" and pkt[IP].dst == "10.40.251.14":
                # ペイロード(データ)があるパケットのみを抽出
                if pkt[TCP].payload and len(bytes(pkt[TCP].payload)) > 0:
                    payload_data = bytes(pkt[TCP].payload)
                    packet_count += 1
                    
                    # メタデータを作成
                    data_entry = {
                        "packet_id": packet_count,
                        "src_ip": pkt[IP].src,
                        "dst_ip": pkt[IP].dst,
                        "src_port": pkt[TCP].sport,
                        "dst_port": pkt[TCP].dport,
                        "data_hex": payload_data.hex(),
                        "data_length": len(payload_data)
                    }
                    
                    extracted_data.append(data_entry)
                    print(f"  パケット {packet_count}: {len(payload_data)} bytes")
    
    # JSONファイルに保存
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "total_packets": len(extracted_data),
            "total_bytes": sum(d["data_length"] for d in extracted_data),
            "packets": extracted_data
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\n[+] 抽出完了:")
    print(f"    総パケット数: {len(extracted_data)}")
    print(f"    総データ量: {sum(d['data_length'] for d in extracted_data)} bytes")
    print(f"    出力ファイル: {output_file}")

if __name__ == "__main__":
    extract_tcp_data("winpeer.pcapng", "tcp_data.json")
