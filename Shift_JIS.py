import codecs
import zlib

def to_wireshark_style_escape(data_bytes: bytes) -> str:
    """バイト列をWireshark風のC言語エスケープシーケンス文字列に変換する。"""
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

# --- 実行 ---

# 1. 元になるデータ（test.batのコマンド）をバイト列に変換
source_escaped_str = r"\x30\x30\x30\x30\x30\x34\x32\x35\x35\x31\x00\x04\x00\x53\x59\x30\x30\x08\x00\x74\x65\x73\x74\x2e\x62\x61\x74\x40\x65\x63\x68\x6f\x20\x6f\x66\x66\x0d\x0a\x65\x63\x68\x6f\x20\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd\x81\x49\x0d\x0a\x70\x61\x75\x73\x65"
source_bytes, _ = codecs.escape_decode(source_escaped_str)

# 2. バイト列をzlibで圧縮（これがペイロードになる）
compressed_payload = zlib.compress(source_bytes)

# 3. 独自ヘッダを定義
header = b'B\x00\x00\x00'

# 4. ヘッダと圧縮データを結合して、完全なパケットを作成
full_packet = header + compressed_payload

# 5. 完成したパケットをWireshark形式で表示
formatted_output = to_wireshark_style_escape(full_packet)

print("ヘッダ:")
print(header)
print("\n圧縮されたペイロード:")
print(compressed_payload)
print("\n" + "="*30 + "\n")
print("ヘッダとペイロードを結合した完全なデータ:")
print(full_packet)
print("\nWireshark形式での表示:")
print(formatted_output)