#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import socket
import time
import argparse
from socket import socket as Socket, AF_INET, SOCK_STREAM, timeout


def from_c_string(c_string):
    """C String形式の文字列をバイト列に変換する"""
    c_string = c_string.strip()
    if c_string.startswith('"') and c_string.endswith('"'):
        c_string = c_string[1:-1]
    
    parts = re.findall(r'\\(\\|"|\d{1,3})|.', c_string, re.DOTALL)
    
    byte_array = bytearray()
    for part in parts:
        if part.startswith('\\'):
            esc_char = part[1:]
            if esc_char == '\\':
                byte_array.append(ord('\\'))
            elif esc_char == '"':
                byte_array.append(ord('"'))
            else:
                try:
                    byte_array.append(int(esc_char, 8))
                except ValueError:
                    byte_array.extend(part.encode('latin-1'))
        else:
            byte_array.extend(part.encode('latin-1'))
    
    return bytes(byte_array)


def send_packets_with_reconnect(destination_ip, destination_port, packets, start_from=0):
    """
    同一のTCPセッションですべてのパケットを送信する
    """
    total_sent = 0
    
    print(f"\n[接続] {destination_ip}:{destination_port} に接続しています...")
    
    s = Socket(AF_INET, SOCK_STREAM)
    s.settimeout(60)
    
    try:
        s.connect((destination_ip, destination_port))
        print(f"[+] 接続に成功しました。")
        
        for i, packet in enumerate(packets[start_from:], start=start_from):
            s.sendall(packet)
            total_sent += len(packet)
            
            # 進捗表示
            progress = ((i + 1) / len(packets)) * 100
            print(f"    パケット {i+1}/{len(packets)} 送信完了 ({progress:.1f}%) - {len(packet)} バイト", end='\r')
            
            # 各パケット間に待機
            time.sleep(0.001)
        
        print(f"\n✓ すべてのパケット送信完了！")
        print(f"送信したパケット: {len(packets)} 個（合計 {total_sent} バイト）")
        s.close()
        return True
                
    except Exception as e:
        print(f"\n[!] エラーが発生しました: {e}")
        return False
    finally:
        try:
            s.close()
        except:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="C String形式のパケットをTCPで送信するスクリプト。接続が切断された場合は再接続して続行します。"
    )
    parser.add_argument(
        "c_string_file",
        nargs='?',
        default="winperer.txt",
        help="送信するC String形式のデータが書かれたファイル名 (デフォルト: winperer.txt)"
    )
    parser.add_argument(
        "--ip",
        default="10.40.251.43",
        help="宛先IPアドレス (デフォルト: 10.40.251.43)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=50598,
        help="宛先ポート番号 (デフォルト: 50598)"
    )
    args = parser.parse_args()

    DESTINATION_IP = args.ip
    DESTINATION_PORT = args.port
    CSTRING_FILE = args.c_string_file
    
    # ファイル読み込み
    print(f"[*] C Stringファイル '{CSTRING_FILE}' を読み込んでいます...")
    try:
        with open(CSTRING_FILE, 'r', encoding='utf-8') as f:
            c_string_lines = f.readlines()
        
        c_string_lines = [line.strip() for line in c_string_lines if line.strip()]
        print(f"[+] {len(c_string_lines)} 行のデータを読み込みました。")
    except FileNotFoundError:
        print(f"[!] ファイルが見つかりません: {CSTRING_FILE}")
        return
    except Exception as e:
        print(f"[!] ファイル読み込みエラー: {e}")
        return
    
    # C Stringをバイト列に変換
    print("[*] C String形式からバイト列に変換しています...")
    try:
        packets = []
        for i, c_string_data in enumerate(c_string_lines, 1):
            packet = from_c_string(c_string_data)
            packets.append(packet)
            if i % 10 == 0:
                print(f"    変換済み: {i}/{len(c_string_lines)} パケット", end='\r')
        
        print(f"\n[+] {len(packets)} 個のパケットに変換しました。")
    except Exception as e:
        print(f"[!] 変換エラー: {e}")
        return
    
    # 送信（再接続機能付き）
    success = send_packets_with_reconnect(DESTINATION_IP, DESTINATION_PORT, packets)
    
    if success:
        print("\n✓ 全データの送信に成功しました！")
    else:
        print("\n✗ データ送信が完了できませんでした。")


if __name__ == "__main__":
    main()
