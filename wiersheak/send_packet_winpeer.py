#!/usr/bin/env python3
"""
tcp_data.jsonからTCPデータを読み込んで送信するスクリプト
"""

import time
import socket
import json
import sys

#!/usr/bin/env python3
"""
tcp_data.jsonからTCPデータを読み込んで送信するスクリプト
"""

import time
import socket
import json
import sys

def load_tcp_data(json_file="tcp_data.json"):
    """
    JSONファイルからTCPデータを読み込む
    """
    print(f"[+] {json_file}を読み込んでいます...")
    
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"[+] 総パケット数: {data['total_packets']}")
    print(f"[+] 総データ量: {data['total_bytes']} bytes")
    
    return data['packets']

def display_packet_info(packets):
    """
    パケット情報を表示（データ部分のみ）
    """
    print("\n[+] パケット情報（データのみ）:")
    print("-" * 80)
    for pkt in packets[:10]:  # 最初の10パケットのみ表示
        print(f"パケット {pkt['packet_id']}:")
        print(f"  {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
        print(f"  Payload: {pkt['data_length']} bytes")
        
        # HEX表示
        hex_data = pkt['data_hex'][:100]
        print(f"  Data (hex): {hex_data}...")
        
        # ASCII表示
        try:
            data_bytes = bytes.fromhex(pkt['data_hex'])
            ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data_bytes[:50])
            print(f"  Data (ASCII): {ascii_preview}")
        except:
            pass
        print()
    
    if len(packets) > 10:
        print(f"... 他 {len(packets) - 10} パケット")
        print()

def send_tcp_data(packets, target_ip="10.40.251.43", dry_run=False):
    """
    TCPデータを送信
    
    Args:
        packets: 送信するパケットデータのリスト
        target_ip: 宛先IPアドレス
        dry_run: Trueの場合は実際には送信しない
    """
    if dry_run:
        print("\n[!] DRY RUN モード: 実際のパケット送信は行いません")
        print("[!] 実際に送信する場合は、dry_run=False に設定してください")
        return
    
    if not packets:
        print("[!] 送信するパケットがありません")
        return
    
    print("\n[+] TCP通信でデータ送信を開始します...")
    
    # 最初のパケットからポート番号を取得
    first_pkt = packets[0]
    src_port = first_pkt['src_port']
    dst_port = first_pkt['dst_port']
    
    print(f"[i] 接続先: {target_ip}:{dst_port}")
    print(f"[i] 送信元ポート: {src_port}")
    
    total_data_bytes = 0
    success_count = 0
    
    try:
        # TCPソケットを作成
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 送信元ポートを指定してバインド（オプション）
        try:
            sock.bind(('', src_port))
            print(f"[+] 送信元ポート {src_port} にバインドしました")
        except OSError as e:
            print(f"[!] 警告: ポート {src_port} のバインドに失敗: {e}")
            print(f"[i] OSが自動的にポートを割り当てます")
        
        # タイムアウトを設定
        sock.settimeout(10)
        
        # 接続を確立
        print(f"[+] {target_ip}:{dst_port} に接続中...")
        sock.connect((target_ip, dst_port))
        print("[+] TCP接続が確立されました\n")
        
        # 各パケットのデータを送信
        for pkt in packets:
            # HEX文字列からバイナリデータに変換
            payload_data = bytes.fromhex(pkt['data_hex'])
            data_len = len(payload_data)
            total_data_bytes += data_len
            
            print(f"[{pkt['packet_id']}/{len(packets)}] データ送信中 ({data_len} bytes)...")
            
            # データを送信
            sent = sock.send(payload_data)
            
            if sent == data_len:
                success_count += 1
                print(f"  [✓] {sent} bytes 送信完了")
            else:
                print(f"  [!] 警告: {data_len} bytes 中 {sent} bytes のみ送信されました")
            
            # 少し待機
            time.sleep(0.01)
        
        print(f"\n[+] 送信完了: {success_count}/{len(packets)} パケット")
        print(f"[i] 送信した総データ量: {total_data_bytes} bytes")
        
        # 接続を閉じる
        print("[+] TCP接続を閉じています...")
        sock.close()
        print("[+] 完了")
        
    except socket.timeout:
        print("[!] エラー: 接続タイムアウト")
    except ConnectionRefusedError:
        print(f"[!] エラー: 接続が拒否されました。{target_ip}:{dst_port} が利用可能か確認してください")
    except FileNotFoundError:
        print(f"[!] エラー: データファイルが見つかりません")
    except Exception as e:
        print(f"[!] エラー: {e}")
        import traceback
        traceback.print_exc()

def main():
    json_file = "tcp_data.json"
    
    try:
        # JSONファイルからデータを読み込み
        packets = load_tcp_data(json_file)
        
        if not packets:
            print("[!] データが見つかりませんでした")
            return
        
        # パケット情報を表示
        display_packet_info(packets)
        
        # データを送信
        send_tcp_data(packets, target_ip="10.40.251.43", dry_run=False)
        
        print("\n[i] 設定オプション:")
        print("    - tcp_data.json: TCPデータを含むJSONファイル")
        print("    - target_ip: 送信先IPアドレスを変更できます")
        print("    - sudo権限は不要です")
        print("\n[i] JSONファイルの作成:")
        print("    python3 extract_data.py を実行してwinpeer.pcapngから抽出")
        
    except FileNotFoundError:
        print(f"[!] エラー: {json_file} が見つかりません")
        print(f"[!] 最初に extract_data.py を実行してデータを抽出してください:")
        print(f"    python3 extract_data.py")
    except Exception as e:
        print(f"[!] エラーが発生しました: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
