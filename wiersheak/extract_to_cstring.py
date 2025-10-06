#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import rdpcap, IP, TCP

def to_c_string(data_bytes):
    """
    バイト列をC String形式に変換する
    例: b'\x01\x02ABC' -> "\\001\\002ABC"
    """
    result = []
    printable_ascii_codes = set(range(32, 127))
    
    for byte_val in data_bytes:
        char = chr(byte_val)
        if char == '"':
            result.append('\\"')
        elif char == '\\':
            result.append('\\\\')
        elif byte_val in printable_ascii_codes:
            result.append(char)
        else:
            result.append(f"\\{byte_val:03o}")
    
    return '"' + "".join(result) + '"'


def extract_tcp_data_to_cstring(pcap_file, source_ip, destination_ip, source_port, destination_port, output_file):
    """
    指定されたフィルタ条件でTCPパケットを抽出し、
    そのデータ部分をC String形式でファイルに保存する
    
    Args:
        pcap_file: pcapngファイルのパス
        source_ip: 送信元IPアドレス
        destination_ip: 宛先IPアドレス
        source_port: 送信元ポート
        destination_port: 宛先ポート
        output_file: 出力ファイル名
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

    print(f"[*] フィルタ条件:")
    print(f"    ip.src == {source_ip}")
    print(f"    ip.dst == {destination_ip}")
    print(f"    tcp.srcport == {source_port}")
    print(f"    tcp.dstport == {destination_port}")
    
    extracted_data = []
    packet_count = 0
    
    for packet in packets:
        if TCP in packet and IP in packet:
            if (packet[IP].src == source_ip and 
                packet[IP].dst == destination_ip and
                packet[TCP].sport == source_port and
                packet[TCP].dport == destination_port):
                
                # TCPペイロード（データ部分）を取得
                if hasattr(packet[TCP], 'load'):
                    tcp_data = bytes(packet[TCP].load)
                    extracted_data.append(tcp_data)
                    packet_count += 1
                    print(f"[+] パケット#{packet_count}: {len(tcp_data)} バイトのデータを抽出")

    if not extracted_data:
        print(f"[-] 条件に一致するTCPデータが見つかりませんでした。")
        return
    
    # すべてのデータを結合
    combined_data = b''.join(extracted_data)
    print(f"\n[+] 合計 {packet_count} 個のパケットから {len(combined_data)} バイトのデータを抽出しました。")
    
    # C String形式に変換
    c_string = to_c_string(combined_data)
    
    # ファイルに保存
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(c_string)
        print(f"[+] C String形式で '{output_file}' に保存しました。")
        
        # 確認用に最初の100文字を表示
        preview = c_string[:100] + ('...' if len(c_string) > 100 else '')
        print(f"\n[Preview] {preview}")
        
    except Exception as e:
        print(f"[!] ファイル保存中にエラーが発生しました: {e}")


if __name__ == "__main__":
    # 設定
    PCAP_FILE = "winpeer.pcapng"
    SOURCE_IP = "10.40.251.11"
    DESTINATION_IP = "10.40.251.14"
    SOURCE_PORT = 49534
    DESTINATION_PORT = 50598
    OUTPUT_FILE = "winperer.txt"
    
    extract_tcp_data_to_cstring(
        PCAP_FILE, 
        SOURCE_IP, 
        DESTINATION_IP, 
        SOURCE_PORT, 
        DESTINATION_PORT, 
        OUTPUT_FILE
    )
