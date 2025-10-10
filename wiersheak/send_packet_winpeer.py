#!/usr/bin/env python3
"""
tcp_data.jsonからTCPデータを読み込んで送信するスクリプト（最適化版）
"""

import time
import socket
import json

def load_tcp_data(json_file="tcp_data.json"):
    """
    JSONファイルからTCPデータを読み込む
    """
    print(f"[+] {json_file}を読み込んでいます...")
    
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"[+] 総パケット数: {data['total_packets']}")
    print(f"[+] 総データ量: {data['total_bytes']} bytes")
    print(f"[+] ポート情報: {data['ports']['src_port']} -> {data['ports']['dst_port']}")
    
    return data


def send_tcp_data(data, target_ip):
    
    ports = data['ports']
    payloads = data['payloads']
    
    if not payloads:
        print("[!] 送信するパケットがありません")
        return
    
    print("\n[+] TCP通信でデータ送信を開始します...")
    print(f"[i] 接続先: {target_ip}:{ports['dst_port']}")
    print(f"[i] 送信元ポート: {ports['src_port']}")
    
    total_data_bytes = 0
    success_count = 0
    # TCPソケットを作成
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # タイムアウトを設定
    sock.settimeout(10)
    
    # 接続を確立
    sock.connect((target_ip, ports['dst_port']))
    
    # 各パケットのデータを送信
    for idx, payload_hex in enumerate(payloads, 1):
        # HEX文字列からバイナリデータに変換
        payload_data = bytes.fromhex(payload_hex)
        data_len = len(payload_data)
        total_data_bytes += data_len
        
        print(f"[{idx}/{len(payloads)}] データ送信中 ({data_len} bytes)...")
        
        # データを送信
        sent = sock.send(payload_data)
        
        if sent == data_len:
            success_count += 1
            print(f"  [✓] {sent} bytes 送信完了")
        else:
            print(f"  [!] 警告: {data_len} bytes 中 {sent} bytes のみ送信されました")
        
        # 少し待機
        time.sleep(0.01)
    # 接続を閉じる
    sock.close()

def main():
    json_file = "tcp_data.json"
    
    try:
        # JSONファイルからデータを読み込み
        data = load_tcp_data(json_file)
        
        # データを送信
        send_tcp_data(data, target_ip="10.40.251.18")
                
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
