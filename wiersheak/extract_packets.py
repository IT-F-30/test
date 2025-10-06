#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# scapyライブラリが必要です。

from scapy.all import rdpcap, IP, TCP

def extract_specific_tcp_stream(pcap_file, source_ip, destination_ip):
    """
    PCAPファイルから指定された送信元・宛先IP間のTCPパケットを抽出し、
    その概要を表示します。

    Args:
        pcap_file (str): PCAPファイルのパス。
        source_ip (str): フィルタリングする送信元IPアドレス。
        destination_ip (str): フィルタリングする宛先IPアドレス。
    """
    print(f"[*] PCAPファイル '{pcap_file}' を読み込んでいます...")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] エラー: ファイル '{pcap_file}' が見つかりません。")
        return
    except Exception as e:
        print(f"[!] ファイル読み込み中にエラーが発生しました: {e}")
        return

    print(f"[*] {source_ip} -> {destination_ip} のTCPパケットを抽出します...")
    
    extracted_packets = []
    for packet in packets:
        if TCP in packet and IP in packet:
            if packet[IP].src == source_ip and packet[IP].dst == destination_ip:
                extracted_packets.append(packet)

    if not extracted_packets:
        print(f"[-] 対象のTCPパケットは見つかりませんでした。")
        return
        
    print(f"[+] {len(extracted_packets)} 個のパケットが見つかりました。概要を表示します:")
    for packet in extracted_packets:
        print(packet.summary())

if __name__ == "__main__":
    PCAP_FILE = "winpeer.pcapng"
    SOURCE_IP = "10.40.251.11"
    DESTINATION_IP = "10.40.251.14"
    extract_specific_tcp_stream(PCAP_FILE, SOURCE_IP, DESTINATION_IP)
