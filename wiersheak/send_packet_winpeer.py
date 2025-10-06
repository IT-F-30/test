#!/usr/bin/env python3
"""
winpeer.pcapngから tcp and ip.src == 10.40.251.11 and ip.dst == 10.40.251.14
でフィルタリングし、10.40.251.11が行っているTCP送信を再現するスクリプト
"""

from scapy.all import rdpcap, IP, TCP, send
import time

def read_and_filter_packets(pcap_file):
    """
    pcapngファイルを読み込み、指定された条件でフィルタリング
    """
    print(f"[+] {pcap_file}を読み込んでいます...")
    packets = rdpcap(pcap_file)
    
    filtered_packets = []
    for pkt in packets:
        # IPレイヤーとTCPレイヤーが存在するか確認
        if IP in pkt and TCP in pkt:
            # 送信元IP: 10.40.251.11, 宛先IP: 10.40.251.14 でフィルタリング
            if pkt[IP].src == "10.40.251.11" and pkt[IP].dst == "10.40.251.14":
                filtered_packets.append(pkt)
    
    print(f"[+] フィルタ条件に一致するパケット数: {len(filtered_packets)}")
    return filtered_packets

def display_packet_info(packets):
    """
    パケット情報を表示
    """
    print("\n[+] パケット情報:")
    print("-" * 80)
    for i, pkt in enumerate(packets, 1):
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        
        # ペイロードサイズ
        payload_len = len(tcp_layer.payload) if tcp_layer.payload else 0
        
        # TCPフラグを文字列に変換
        flags = []
        if tcp_layer.flags.S:
            flags.append("SYN")
        if tcp_layer.flags.A:
            flags.append("ACK")
        if tcp_layer.flags.F:
            flags.append("FIN")
        if tcp_layer.flags.R:
            flags.append("RST")
        if tcp_layer.flags.P:
            flags.append("PSH")
        flags_str = ",".join(flags) if flags else "None"
        
        print(f"パケット {i}:")
        print(f"  {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
        print(f"  Seq: {tcp_layer.seq}, Ack: {tcp_layer.ack}")
        print(f"  Flags: {flags_str}")
        print(f"  Payload: {payload_len} bytes")
        if payload_len > 0:
            print(f"  Data (hex): {bytes(tcp_layer.payload).hex()[:100]}...")
        print()

def reproduce_tcp_transmission(packets, target_ip="10.40.251.43", dry_run=True):
    """
    TCPパケットの送信を再現
    
    Args:
        packets: 送信するパケットのリスト
        target_ip: 宛先IPアドレス (Noneの場合は元のIPを使用)
        dry_run: Trueの場合は実際には送信しない (デフォルト: True)
    """
    if dry_run:
        print("\n[!] DRY RUN モード: 実際のパケット送信は行いません")
        print("[!] 実際に送信する場合は、dry_run=False に設定してください")
        print("[!] 注意: 実際の送信には管理者権限が必要です")
        return
    
    print("\n[+] パケット送信を開始します...")
    
    success_count = 0
    error_count = 0
    
    for i, pkt in enumerate(packets, 1):
        try:
            # 新しいパケットを構築
            new_pkt = IP(dst=target_ip if target_ip else pkt[IP].dst) / \
                      TCP(sport=pkt[TCP].sport,
                          dport=pkt[TCP].dport,
                          flags=pkt[TCP].flags,
                          seq=pkt[TCP].seq,
                          ack=pkt[TCP].ack)
            
            # ペイロードがあれば追加
            if pkt[TCP].payload:
                new_pkt = new_pkt / bytes(pkt[TCP].payload)
            
            print(f"[{i}/{len(packets)}] パケット送信中...")
            
            # fragmentオプションを有効にして送信 (OSにフラグメント化を任せる)
            send(new_pkt, verbose=False, fragment=True)
            success_count += 1
            
            # 次のパケットまで少し待機
            time.sleep(0.01)
            
        except Exception as e:
            print(f"[!] エラー: パケット {i} の送信に失敗しました: {e}")
            error_count += 1
    
    print(f"\n[+] 送信完了: 成功 {success_count}/{len(packets)}, 失敗 {error_count}/{len(packets)}")

def main():
    pcap_file = "winpeer.pcapng"
    
    try:
        # パケットを読み込んでフィルタリング
        filtered_packets = read_and_filter_packets(pcap_file)
        
        if not filtered_packets:
            print("[!] フィルタ条件に一致するパケットが見つかりませんでした")
            return
        
        # パケット情報を表示
        display_packet_info(filtered_packets)
        
        # パケット送信の再現 (デフォルトはドライラン)
        reproduce_tcp_transmission(filtered_packets, dry_run=False)
        
        print("\n[i] 実際にパケットを送信する場合:")
        print("    1. dry_run=False に変更してください")
        print("    2. 必要に応じて target_ip を指定してください")
        print("    3. sudo権限で実行してください: sudo python3 send_packet_winpeer.py")
        
    except FileNotFoundError:
        print(f"[!] エラー: {pcap_file} が見つかりません")
        print(f"[!] このスクリプトと同じディレクトリに {pcap_file} を配置してください")
    except Exception as e:
        print(f"[!] エラーが発生しました: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
