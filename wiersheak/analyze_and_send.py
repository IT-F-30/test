#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import struct
from socket import socket, AF_INET, SOCK_STREAM, timeout


def from_c_string(c_string):
    """
    Wireshark風のC言語エスケープシーケンス文字列をバイト列に変換する
    """
    c_string = c_string.strip()
    if c_string.startswith('"') and c_string.endswith('"'):
        c_string = c_string[1:-1]
    
    # 正規表現を使ってエスケープシーケンスを一度に処理する
    # - \\: バックスラッシュ自体
    # - \": ダブルクォート
    # - \d{1,3}: 1〜3桁の8進数
    # - .: 上記以外の任意の1文字
    parts = re.findall(r'\\(\\|"|\d{1,3})|.', c_string, re.DOTALL)
    
    byte_array = bytearray()
    for part in parts:
        # partは文字列またはタプルの可能性がある
        if isinstance(part, tuple):
            # タプルの場合は最初の要素を取得
            part = part[0] if part[0] else part[1] if len(part) > 1 else ''
        
        if not part:
            continue
            
        # エスケープシーケンスのチェック（バックスラッシュで始まる場合）
        # しかし、正規表現のグループマッチングによりバックスラッシュは除去されている
        if part == '\\':
            byte_array.append(ord('\\'))
        elif part == '"':
            byte_array.append(ord('"'))
        elif part.isdigit():
            # 8進数の場合
            try:
                byte_array.append(int(part, 8))
            except ValueError:
                # 8進数として無効な場合は、元の文字列として扱う
                byte_array.extend(part.encode('latin-1'))
        else:
            # 通常の文字の場合
            byte_array.extend(part.encode('latin-1'))
            
    return bytes(byte_array)


def split_into_packets(data):
    """
    データをパケット単位に分割する
    各パケットは以下の形式を持つ:
    - バイト0: 圧縮データの長さ
    - バイト1-3: \x00\x00\x00 (固定ヘッダー)
    - バイト4-: 圧縮データ
    """
    packets = []
    offset = 0
    
    print("[*] データをパケット単位に分割しています...")
    
    while offset < len(data):
        if offset + 4 > len(data):
            print(f"[!] 警告: オフセット {offset} でデータが不足しています。残り {len(data) - offset} バイト")
            break
        
        # パケット長を取得（最初のバイト）
        packet_length = data[offset]
        
        # ヘッダーを確認
        if offset + 3 < len(data) and data[offset+1:offset+4] == b'\x00\x00\x00':
            # 完全なパケット長 = 1(長さバイト) + 3(ヘッダー) + packet_length(データ)
            full_packet_length = 4 + packet_length
            
            if offset + full_packet_length > len(data):
                print(f"[!] 警告: パケット #{len(packets)+1} が不完全です")
                print(f"    期待: {full_packet_length} バイト, 残り: {len(data) - offset} バイト")
                break
            
            packet = data[offset:offset + full_packet_length]
            packets.append(packet)
            
            if len(packets) % 10 == 0:
                print(f"    分割済み: {len(packets)} パケット, オフセット: {offset}/{len(data)}", end='\r')
            
            offset += full_packet_length
        else:
            print(f"\n[!] 警告: オフセット {offset} で予期しないヘッダー形式: {data[offset:offset+4].hex()}")
            # 次の有効なヘッダーを探す
            found = False
            for i in range(offset + 1, min(offset + 1000, len(data) - 3)):
                if data[i+1:i+4] == b'\x00\x00\x00':
                    print(f"    次の有効なヘッダーをオフセット {i} で発見")
                    offset = i
                    found = True
                    break
            
            if not found:
                print(f"    有効なヘッダーが見つかりませんでした。残りデータをスキップします。")
                break
    
    print(f"\n[+] {len(packets)} 個のパケットに分割しました。")
    return packets


def send_packets(destination_ip, destination_port, packets):
    """
    パケットを順番に送信する
    """
    print(f"[*] {destination_ip}:{destination_port} への接続を試みます...")
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(60)
    
    try:
        s.connect((destination_ip, destination_port))
        print("[+] 接続に成功しました。")
        
        total_sent = 0
        import time
        
        for i, packet in enumerate(packets, 1):
            try:
                s.sendall(packet)
                total_sent += len(packet)
                
                # 進捗表示
                progress = (i / len(packets)) * 100
                print(f"    パケット {i}/{len(packets)} 送信完了 ({progress:.1f}%) - {len(packet)} バイト", end='\r')
                
                # パケット間に待機（受信側の処理時間を考慮）
                time.sleep(0.001)  # 1ミリ秒待機
                
            except Exception as e:
                print(f"\n[!] パケット #{i} の送信中にエラーが発生しました: {e}")
                print(f"    これまでに {i-1} 個のパケット（{total_sent} バイト）を送信しました。")
                raise
        
        print(f"\n✓ 正常にデータを送信しました。")
        print(f"送信したパケット: {len(packets)} 個（合計 {total_sent} バイト）")
        
        s.close()
        
    except timeout:
        print("\n[!] 接続がタイムアウトしました。")
    except ConnectionRefusedError:
        print(f"[!] {destination_ip}:{destination_port} への接続が拒否されました。")
    except Exception as e:
        print(f"\n[!] エラーが発生しました: {e}")
    finally:
        try:
            s.close()
        except:
            pass


def main():
    DESTINATION_IP = "10.40.251.43"
    DESTINATION_PORT = 50598
    CSTRING_FILE = "winperer.txt"
    
    # ファイル読み込み
    print(f"[*] C Stringファイル '{CSTRING_FILE}' を読み込んでいます...")
    try:
        with open(CSTRING_FILE, 'r', encoding='utf-8') as f:
            c_string_data = f.read().strip()
    except Exception as e:
        print(f"[!] ファイル読み込みエラー: {e}")
        return
    
    # バイト列に変換
    print("[*] C String形式からバイト列に変換しています...")
    data = from_c_string(c_string_data)
    print(f"[+] {len(data)} バイトのデータに変換しました。")
    
    # 最初の数バイトを確認
    print(f"\n[データ分析]")
    print(f"  最初の20バイト(hex): {data[:20].hex()}")
    print(f"  最初の20バイト(値): {list(data[:20])}")
    
    # パケットに分割
    packets = split_into_packets(data)
    
    if not packets:
        print("[!] パケットの分割に失敗しました。")
        return
    
    # パケット情報を表示
    print(f"\n[パケット情報]")
    for i in range(min(5, len(packets))):
        print(f"  パケット #{i+1}: {len(packets[i])} バイト, ヘッダー: {packets[i][:4].hex()}")
    
    if len(packets) > 5:
        print(f"  ... (残り {len(packets) - 5} パケット)")
    
    # 送信
    send_packets(DESTINATION_IP, DESTINATION_PORT, packets)


if __name__ == "__main__":
    main()
