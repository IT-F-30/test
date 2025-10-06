#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re


def from_c_string(c_string):
    """Wireshark風のC言語エスケープシーケンス文字列をバイト列に変換する"""
    c_string = c_string.strip()
    if c_string.startswith('"') and c_string.endswith('"'):
        c_string = c_string[1:-1]
    
    parts = re.findall(r'\\(\\|"|\d{1,3})|.', c_string, re.DOTALL)
    
    byte_array = bytearray()
    for part in parts:
        if isinstance(part, tuple):
            part = part[0] if part[0] else part[1] if len(part) > 1 else ''
        
        if not part:
            continue
            
        if part == '\\':
            byte_array.append(ord('\\'))
        elif part == '"':
            byte_array.append(ord('"'))
        elif part.isdigit():
            try:
                byte_array.append(int(part, 8))
            except ValueError:
                byte_array.extend(part.encode('latin-1'))
        else:
            byte_array.extend(part.encode('latin-1'))
            
    return bytes(byte_array)


# ファイル読み込み
print("[*] winperer.txtを読み込んでいます...")
with open("winperer.txt", 'r', encoding='utf-8') as f:
    c_string_data = f.read().strip()

# バイト列に変換
print("[*] バイト列に変換しています...")
data = from_c_string(c_string_data)
print(f"[+] {len(data)} バイトに変換しました\n")

# 最初の1000バイトを16進数ダンプで表示
print("=== 最初の1000バイトの16進数ダンプ ===")
for i in range(0, min(1000, len(data)), 16):
    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
    print(f"{i:08x}  {hex_part:<48}  {ascii_part}")

# パケット境界を探す
print("\n=== パケット境界の検出 ===")
print("パターン '\\x00\\x00\\x00' を検索...")

positions = []
for i in range(len(data) - 2):
    if data[i:i+3] == b'\x00\x00\x00':
        positions.append(i)
        if len(positions) <= 20:
            print(f"  位置 {i}: 前後のバイト = {data[max(0,i-2):i+6].hex()}")

print(f"\n合計 {len(positions)} 個の '\\x00\\x00\\x00' パターンを発見")

# 最初の数パケットの構造を分析
if positions:
    print("\n=== 最初の5パケットの分析 ===")
    for idx in range(min(5, len(positions))):
        pos = positions[idx]
        # パケット開始位置を推定（パターンの前）
        start = max(0, pos - 10)
        end = min(len(data), pos + 100)
        
        print(f"\nパケット #{idx+1} (パターン位置: {pos}):")
        print(f"  前10バイト: {data[start:pos].hex()}")
        print(f"  パターン+後10バイト: {data[pos:pos+13].hex()}")
