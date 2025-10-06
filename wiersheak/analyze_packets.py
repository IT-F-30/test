#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from scapy.all import IP, TCP, RawPcapNgReader

def analyze_and_save_payloads(pcap_file, output_file, src_ip, dst_ip, sport, dport):
    print(f"[*] PCAPファイル '{pcap_file}' を低レベルリーダーで読み込んでいます...")
    all_payloads = b''
    
    try:
        with RawPcapNgReader(pcap_file) as reader:
            for pkt_data, _ in reader:
                # RawPcapNgReaderはEthernetレイヤーを返さないことがあるため、
                # IPレイヤーから直接デコードを試みる
                try:
                    packet = IP(pkt_data)
                    if TCP in packet:
                        if (packet[IP].src == src_ip and
                            packet[IP].dst == dst_ip and
                            packet[TCP].sport == sport and
                            packet[TCP].dport == dport):
                            
                            payload = bytes(packet[TCP].payload)
                            if payload:
                                all_payloads += payload
                except Exception:
                    # IPデコードに失敗したパケットは無視
                    continue
    except Exception as e:
        print(f"[!] ファイル処理中にエラーが発生しました: {e}")
        return

    if not all_payloads:
        print("[-] ペイロードが見つかりませんでした。")
        return

    try:
        with open(output_file, 'wb') as f:
            f.write(all_payloads)
        print(f"[+] 全ペイロードを '{output_file}' に保存しました ({len(all_payloads)} bytes)。")
    except Exception as e:
        print(f"[!] ファイル書き込みエラー: {e}")

if __name__ == "__main__":
    PCAP_FILE = "winpeer.pcapng"
    OUTPUT_FILE = "payloads.bin"
    SOURCE_IP = "10.40.251.11"
    DESTINATION_IP = "10.40.251.14"
    SOURCE_PORT = 49534
    DESTINATION_PORT = 50598
    analyze_and_save_payloads(PCAP_FILE, OUTPUT_FILE, SOURCE_IP, DESTINATION_IP, SOURCE_PORT, DESTINATION_PORT)