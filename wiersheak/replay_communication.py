#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket

def send_data_from_file(destination_ip, destination_port, payload_file):
    print(f"[*] ペイロードファイル '{payload_file}' を読み込んでいます...")
    try:
        with open(payload_file, 'rb') as f:
            payload = f.read()
        if not payload:
            print("[-] ファイルが空です。送信するデータがありません。")
            return
        print(f"[+] {len(payload)} bytes のデータを読み込みました。")
    except FileNotFoundError:
        print(f"[!] エラー: ファイル '{payload_file}' が見つかりません。")
        return
    except Exception as e:
        print(f"[!] ファイル読み込みエラー: {e}")
        return

    print(f"[*] {destination_ip}:{destination_port} への接続を試みます...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((destination_ip, destination_port))
            print("[+] 接続に成功しました。")
            
            print(f"[*] 全データ ({len(payload)} bytes) を送信中...")
            s.sendall(payload)
            
            print("[+] データ送信が完了しました。")

    except ConnectionRefusedError:
        print(f"[!] エラー: {destination_ip}:{destination_port} への接続が拒否されました。")
    except Exception as e:
        print(f"[!] 通信中にエラーが発生しました: {e}")

if __name__ == "__main__":
    # --- 設定項目 ---
    # ここに送信先のIPアドレスを指定してください
    DESTINATION_IP = "10.40.251.14"
    # --- 設定項目ここまで ---
    
    PAYLOAD_FILE = "payloads.bin"
    DESTINATION_PORT = 50598 # ポート番号は固定

    send_data_from_file(DESTINATION_IP, DESTINATION_PORT, PAYLOAD_FILE)