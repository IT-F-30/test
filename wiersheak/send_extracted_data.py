#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import socket
from socket import socket as Socket, AF_INET, SOCK_STREAM, timeout


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
    ファイルには改行区切りで複数のパケットが含まれている場合、順番に送信する
    1行の場合は、データを分割して送信する
    
    Args:
        destination_ip: 送信先IPアドレス
        destination_port: 送信先ポート番号
        cstring_file: C String形式のファイルパス
    """
    print(f"[*] C Stringファイル '{cstring_file}' を読み込んでいます...")
    try:
        with open(cstring_file, 'r', encoding='utf-8') as f:
            c_string_lines = f.readlines()
        
        if not c_string_lines:
            print("[-] ファイルが空です。送信するデータがありません。")
            return
        
        # 空行を除去
        c_string_lines = [line.strip() for line in c_string_lines if line.strip()]
        print(f"[+] {len(c_string_lines)} 行のデータを読み込みました。")
        
    except FileNotFoundError:
        print(f"[!] エラー: ファイル '{cstring_file}' が見つかりません。")
        return
    except Exception as e:
        print(f"[!] ファイル読み込みエラー: {e}")
        return
    
    # C Stringをバイト列に変換
    print("[*] C String形式からバイト列に変換しています...")
    try:
        packets = []
        total_bytes = 0
        
        if len(c_string_lines) == 1:
            # 1行の場合は単一の大きなデータとして扱う
            print("    単一の大きなデータとして処理します。")
            packet = from_c_string(c_string_lines[0])
            packets.append(packet)
            total_bytes = len(packet)
        else:
            # 複数行の場合は各行を個別のパケットとして扱う
            for i, c_string_data in enumerate(c_string_lines, 1):
                packet = from_c_string(c_string_data)
                packets.append(packet)
                total_bytes += len(packet)
                if i % 10 == 0:
                    print(f"    変換済み: {i}/{len(c_string_lines)} パケット", end='\r')
        
        print(f"\n[+] {len(packets)} 個のパケット（合計 {total_bytes} バイト）に変換しました。")
    except Exception as e:
        print(f"[!] 変換エラー: {e}")
        return
    
    # ソケット接続と送信
    print(f"[*] {destination_ip}:{destination_port} への接続を試みます...")
    s = Socket(AF_INET, SOCK_STREAM)
    s.settimeout(60)  # タイムアウトを60秒に延長
    
    try:
        s.connect((destination_ip, destination_port))
        print("[+] 接続に成功しました。")
        
        total_sent = 0
        import time
        
        if len(packets) == 1:
            # 単一の大きなパケットの場合は、チャンクに分けて送信
            packet = packets[0]
            chunk_size = 1460  # MTUサイズに合わせて1460バイトずつ送信
            total_size = len(packet)
            
            print(f"[*] データを {chunk_size} バイトずつ送信します...")
            
            # TCP_NODELAYを無効化（Nagleアルゴリズムを有効化）
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            
            offset = 0
            while offset < total_size:
                chunk = packet[offset:offset + chunk_size]
                try:
                    sent = s.send(chunk)  # sendallではなくsendを使用
                    if sent == 0:
                        raise RuntimeError("ソケット接続が切断されました")
                    
                    offset += sent
                    total_sent += sent
                    
                    # 進捗表示
                    progress = (offset / total_size) * 100
                    print(f"    進捗: {offset}/{total_size} バイト ({progress:.1f}%)", end='\r')
                    
                    # チャンク間に少し待機
                    time.sleep(0.001)  # 1ミリ秒待機
                    
                except Exception as e:
                    print(f"\n[!] 送信中にエラーが発生しました: {e}")
                    print(f"    これまでに {offset} バイトを送信しました。")
                    
                    # 受信側が応答を返している可能性があるので確認
                    try:
                        s.settimeout(0.1)
                        response = s.recv(1024)
                        if response:
                            print(f"    受信側からの応答: {response[:100]}")
                    except:
                        pass
                    
                    raise
            
            # 送信完了後、受信側の応答を待つ
            print(f"\n[*] 送信完了。受信側の応答を待っています...")
            try:
                s.settimeout(5)
                response = s.recv(4096)
                if response:
                    print(f"[+] 受信側からの応答を受信: {len(response)} バイト")
                    print(f"    内容(最初の200バイト): {response[:200]}")
            except timeout:
                print("    (タイムアウト: 応答なし)")
            except Exception as e:
                print(f"    応答受信中のエラー: {e}")
        else:
            # 複数パケットの場合は、各パケットを順番に送信
            for i, packet in enumerate(packets, 1):
                try:
                    s.sendall(packet)
                    total_sent += len(packet)
                    
                    # 進捗表示
                    progress = (i / len(packets)) * 100
                    print(f"    パケット {i}/{len(packets)} 送信完了 ({progress:.1f}%) - {len(packet)} バイト", end='\r')
                    
                    # 各パケット間に少し待機
                    time.sleep(0.001)  # 1ミリ秒待機
                    
                    # 定期的に受信側からのメッセージをチェック（ノンブロッキング）
                    if i % 10 == 0:
                        try:
                            s.settimeout(0.001)  # 1ミリ秒だけ待つ
                            response = s.recv(1024)
                            if response:
                                print(f"\n    [受信] パケット#{i}後に受信側から応答: {response[:100]}")
                        except:
                            pass
                        finally:
                            s.settimeout(60)  # タイムアウトを元に戻す
                    
                except Exception as e:
                    print(f"\n[!] パケット #{i} の送信中にエラーが発生しました: {e}")
                    print(f"    これまでに {i-1} 個のパケット（{total_sent} バイト）を送信しました。")
                    
                    # エラー時に受信側の応答を確認
                    try:
                        s.settimeout(0.5)
                        response = s.recv(4096)
                        if response:
                            print(f"    受信側からのエラー応答: {response}")
                    except:
                        pass
                    
                    # 接続が生きているか確認
                    try:
                        # SO_ERRORをチェック
                        err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        print(f"    ソケットエラーコード: {err}")
                    except:
                        pass
                    
                    raise
        
        print(f"\n✓ 正常にデータを送信しました。")
        print(f"送信したデータ: {total_sent} バイト")
        
        s.close()
        
    except timeout:
        print("\n[!] 接続がタイムアウトしました。")
        print(f"    送信済み: {total_sent if 'total_sent' in locals() else 0} バイト")
    except ConnectionRefusedError:
        print(f"[!] {destination_ip}:{destination_port} への接続が拒否されました。")
    except Exception as e:
        print(f"\n[!] エラーが発生しました: {e}")
    finally:
        try:
            s.close()
        except:
            pass


if __name__ == "__main__":
    # --- 設定項目 ---
    DESTINATION_IP = "10.40.251.43"  # 送信先IPアドレス
    DESTINATION_PORT = 50598          # 送信先ポート番号
    CSTRING_FILE = "winperer.txt"     # C String形式のファイル
    # --- 設定項目ここまで ---
    
    send_data_from_cstring_file(DESTINATION_IP, DESTINATION_PORT, CSTRING_FILE)
