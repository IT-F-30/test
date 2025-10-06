#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from socket import socket, AF_INET, SOCK_STREAM, timeout


def from_c_string(c_string):
    """
    C String形式の文字列をバイト列に変換する
    例: "\\001\\002ABC" -> b'\x01\x02ABC'
    """
    # クォートを削除（先頭と末尾の "）
    c_string = c_string.strip()
    if c_string.startswith('"') and c_string.endswith('"'):
        c_string = c_string[1:-1]
    
    # 正規表現でエスケープシーケンスを処理
    # - \\: バックスラッシュ自体
    # - \": ダブルクォート
    # - \d{1,3}: 1〜3桁の8進数
    # - .: その他の任意の1文字
    parts = re.findall(r'\\(\\|"|\d{1,3})|.', c_string, re.DOTALL)
    
    byte_array = bytearray()
    for part in parts:
        if part.startswith('\\'): # エスケープシーケンス
            esc_char = part[1:]
            if esc_char == '\\':
                byte_array.append(ord('\\'))
            elif esc_char == '"':
                byte_array.append(ord('"'))
            else: # 8進数
                try:
                    byte_array.append(int(esc_char, 8))
                except ValueError:
                    # 無効な8進数の場合は元の文字列として扱う
                    byte_array.extend(part.encode('latin-1'))
        else: # 通常の文字
            byte_array.extend(part.encode('latin-1'))
    
    return bytes(byte_array)


def send_data_from_cstring_file(destination_ip, destination_port, cstring_file):
    """
    C String形式のファイルを読み込み、バイト列に変換して送信する
    
    Args:
        destination_ip: 送信先IPアドレス
        destination_port: 送信先ポート番号
        cstring_file: C String形式のファイルパス
    """
    print(f"[*] C Stringファイル '{cstring_file}' を読み込んでいます...")
    try:
        with open(cstring_file, 'r', encoding='utf-8') as f:
            c_string_data = f.read()
        
        if not c_string_data:
            print("[-] ファイルが空です。送信するデータがありません。")
            return
        
        print(f"[+] C String形式のデータを読み込みました（文字数: {len(c_string_data)}）")
        
    except FileNotFoundError:
        print(f"[!] エラー: ファイル '{cstring_file}' が見つかりません。")
        return
    except Exception as e:
        print(f"[!] ファイル読み込みエラー: {e}")
        return
    
    # C Stringをバイト列に変換
    print("[*] C String形式からバイト列に変換しています...")
    try:
        packet = from_c_string(c_string_data)
        print(f"[+] {len(packet)} バイトのデータに変換しました。")
    except Exception as e:
        print(f"[!] 変換エラー: {e}")
        return
    
    # ソケット接続と送信
    print(f"[*] {destination_ip}:{destination_port} への接続を試みます...")
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(5)
    
    try:
        s.connect((destination_ip, destination_port))
        print("[+] 接続に成功しました。")
        
        print(f"[*] データを送信中... ({len(packet)} バイト)")
        s.sendall(packet)
        
        print("\n✓ 正常にデータを送信しました。")
        print(f"送信したパケット: {len(packet)} バイト")
        
        s.close()
        
    except timeout:
        print("[!] 接続がタイムアウトしました。")
    except ConnectionRefusedError:
        print(f"[!] {destination_ip}:{destination_port} への接続が拒否されました。")
    except Exception as e:
        print(f"[!] エラーが発生しました: {e}")
    finally:
        s.close()


if __name__ == "__main__":
    # --- 設定項目 ---
    DESTINATION_IP = "10.40.251.14"  # 送信先IPアドレス
    DESTINATION_PORT = 50598          # 送信先ポート番号
    CSTRING_FILE = "winperer.txt"     # C String形式のファイル
    # --- 設定項目ここまで ---
    
    send_data_from_cstring_file(DESTINATION_IP, DESTINATION_PORT, CSTRING_FILE)
