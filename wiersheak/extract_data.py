#!/usr/bin/env python3
"""
winpeer.pcapngからTCPペイロードデータを抽出してメタデータファイルを作成
"""

from scapy.all import rdpcap, IP, TCP
import json

def extract_tcp_data(pcap_file, output_file="tcp_data.json"):
    """
    pcapngファイルからTCPデータを抽出してJSONファイルに保存
    ポート情報のみを保存し、各パケットはペイロードのみを保存
    """
    print(f"[+] {pcap_file}を読み込んでいます...")
    packets = rdpcap(pcap_file)
    
    payloads = []
    ports = None
    
    for pkt in packets:
        # IPレイヤーとTCPレイヤーが存在するか確認
        if IP in pkt and TCP in pkt:
            if pkt[IP].src == "10.40.251.11" and pkt[IP].dst == "10.40.251.14":
                # 最初のパケットからポート情報を取得
                if ports is None:
                    ports = {
                        "src_port": pkt[TCP].sport,
                        "dst_port": pkt[TCP].dport
                    }
                
                # ペイロード(データ)があるパケットのみを抽出
                if pkt[TCP].payload and len(bytes(pkt[TCP].payload)) > 0:
                    payload_data = bytes(pkt[TCP].payload)
                    payloads.append(payload_data.hex())
                    print(f"  パケット {len(payloads)}: {len(payload_data)} bytes")
    
    # JSONファイルに保存
    total_bytes = sum(len(bytes.fromhex(p)) for p in payloads)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "ports": ports,
            "total_packets": len(payloads),
            "total_bytes": total_bytes,
            "payloads": payloads
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\n[+] 抽出完了:")
    print(f"    総パケット数: {len(payloads)}")
    print(f"    総データ量: {total_bytes} bytes")
    print(f"    出力ファイル: {output_file}")

if __name__ == "__main__":
    extract_tcp_data("winpeer.pcapng", "tcp_data.json")
