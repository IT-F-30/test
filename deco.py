import codecs
import zlib
from socket import socket, AF_INET, SOCK_STREAM, timeout

def to_wireshark_style_escape(data_bytes: bytes) -> str:
    """バイト列をWireshark風のC言語エスケープシーDケンス文字列に変換する。"""
    result = []
    printable_ascii_codes = set(range(32, 127))
    for byte_val in data_bytes:
        if chr(byte_val) == '"':
            result.append('\\"')
        elif chr(byte_val) == '\\':
            result.append('\\\\')
        elif byte_val in printable_ascii_codes:
            result.append(chr(byte_val))
        else:
            result.append(f"\\{byte_val:03o}")
    return "".join(result)

# --- データを準備する部分は変更なし ---

# Shift-JISの日本語を含むバイト列を準備
prefix_bytes = (
    b'0000042552SY0test.bat@echo off\nnecho "Hello world"\npause'
)
source_bytes = prefix_bytes

# 圧縮してヘッダを付与
compressed_payload = zlib.compress(source_bytes)
header = b'B\x00\x00\x00'
full_packet = header + compressed_payload

# --- ここからが送信部分 ---

print("これから送信する完全なパケット（バイト列）:")
print(full_packet)
print("\n人間が見るためのWireshark形式表現:")
print(to_wireshark_style_escape(full_packet))

s = socket(AF_INET, SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("10.40.251.14", 50598))
    # s.connect(("10.40.251.25", 50598))
    
    # ★★★ 修正箇所 ★★★
    # 整形後の文字列ではなく、元のバイト列 `full_packet` を送信する
    s.send(full_packet)
    
    print("\n正常にデータを送信しました。")
    s.close()
except timeout:
    print("接続がタイムアウトしました。")
except Exception as e:
    print(f"エラーが発生しました: {e}")