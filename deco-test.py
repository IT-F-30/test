import zlib
import re
import codecs
import zlib
from socket import socket, AF_INET, SOCK_STREAM, timeout
import difflib

def from_wireshark_style_escape(c_string: str) -> bytes:
    """
    Wireshark風のC言語エスケープシーケンス文字列をバイト列に変換する。
    """
    # 正規表現を使ってエスケープシーケンスを一度に処理する
    # - \\: バックスラッシュ自体
    # - \": ダブルクォート
    # - \d{1,3}: 1〜3桁の8進数
    # - .: 上記以外の任意の1文字
    parts = re.findall(r'\\(\\|"|\d{1,3})|.', c_string, re.DOTALL)
    
    byte_array = bytearray()
    for part in parts:
        if part.startswith('\\'): # エスケープシーケンスの場合
            esc_char = part[1]
            if esc_char == '\\':
                byte_array.append(ord('\\'))
            elif esc_char == '"':
                byte_array.append(ord('"'))
            else: # 8進数の場合
                try:
                    byte_array.append(int(esc_char, 8))
                except ValueError:
                    # 8進数として無効な場合は、元の文字列として扱う（例: \9）
                    byte_array.extend(part.encode('latin-1'))
        else: # 通常の文字の場合
            byte_array.extend(part.encode('latin-1'))
            
    return bytes(byte_array)

# ユーザーがWiresharkからコピーしたと想定されるC-String
# この文字列を実際のデータに置き換えてください
packet_bytes = b"2\000\000\000x\23430\000\002\023#\023cc\006\026\206\340H\003\003\016\206\202\324\324\"\275\222\212\022C\003=\023\003=##\v=\v+C\v\vc.\000\317\367\t~"

# 2 ヘッダーを検証・削除
compressed_data = packet_bytes[4:]
# 3. zlibで展開
try:
    decompressed_data = zlib.decompress(compressed_data)
    print(f"decode {decompressed_data}")
except zlib.error as e:
    print(f"\n[エラー] zlibでの展開に失敗しました: {e}")
except Exception as e:
    print(f"\n[エラー] 予期せぬエラーが発生しました: {e}")

meta_data = "peer.txt10.40.228.8:1883\n"
header_data = str(int("0000042501")+len(str(meta_data))).zfill(10)

# print(str(original_data_bytes))
original_data_bytes = header_data.encode('latin-1') + "\x00\x04\x00SY00\x08\x00".encode('latin-1') + meta_data.encode('latin-1')
print("uncode", original_data_bytes)

# to_wireshark_style_escape関数を再利用
def to_wireshark_style_escape(data_bytes: bytes) -> str:
    """バイト列をWireshark風のC言語エスケープシーケンス文字列に変換する。"""
    result = []
    # 表示可能なASCII文字コードのセット（32から126）
    printable_ascii_codes = set(range(32, 127))
    
    for byte_val in data_bytes:
        char = chr(byte_val)
        if char == '"':
            result.append('\\"')
        elif char == '\\':
            result.append('\\\\')
        # 表示可能なASCII文字はそのまま追加
        elif byte_val in printable_ascii_codes:
            result.append(char)
        # それ以外は8進数エスケープ
        else:
            result.append(f"\\{byte_val:03o}")
    return "".join(result)

# print("--- エンコードと圧縮のプロセス ---")
# print(f"入力データ（バイト列）: {original_data_bytes}")

# 1. zlibで圧縮
# (エンコードはすでに入力がバイト列なので不要)
compressed_payload = zlib.compress(original_data_bytes)

# 2. ヘッダーを付与
hedchr = chr(int(len(str(original_data_bytes[19:]))+21))
header = b'\x00\x00\x00'
final_packet_bytes = hedchr.encode('latin-1') + header + compressed_payload

print("Pythonのバイトリテラル表現:")
print(final_packet_bytes)

def compare_strings_with_color(str1, str2, label1="String 1", label2="String 2"):
    """
    二つの文字列を比較して差分を色付きで表示し、部分一致も検出する (difflibを使用)
    """
    # ANSI色コード
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    
    print(f"\n--- 文字列比較: {label1} vs {label2} ---")
    
    if str1 == str2:
        print(f"{GREEN}✓ 文字列は完全に一致しています{RESET}")
        return
    
    print(f"{RED}✗ 文字列に差分があります{RESET}")
    
    matcher = difflib.SequenceMatcher(None, str1, str2)
    
    # 共通部分の情報を表示
    matching_blocks = [block for block in matcher.get_matching_blocks() if block.size > 0]
    if matching_blocks:
        print(f"{BLUE}📍 共通部分が見つかりました ({len(matching_blocks)}箇所):{RESET}")
        for idx, (a, b, size) in enumerate(matching_blocks):
            text = str1[a:a+size]
            print(f"  {idx+1}. '{text[:30]}{'...' if len(text) > 30 else ''}' "
                  f"(長さ: {size})")

    # 文字ごとの比較結果を格納
    result1 = []
    result2 = []
    
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == 'equal':
            result1.append(str1[i1:i2])
            result2.append(str2[j1:j2])
        elif tag == 'delete':
            result1.append(f"{RED}{str1[i1:i2]}{RESET}")
        elif tag == 'insert':
            result2.append(f"{GREEN}{str2[j1:j2]}{RESET}")
        elif tag == 'replace':
            result1.append(f"{RED}{str1[i1:i2]}{RESET}")
            result2.append(f"{GREEN}{str2[j1:j2]}{RESET}")

    print(f"\n{label1}:")
    print("".join(result1))
    print(f"\n{label2}:")
    print("".join(result2))
    
    # 統計情報
    match_percentage = matcher.ratio() * 100
    
    print(f"\n{YELLOW}統計情報:{RESET}")
    print(f"  - 長さ: {label1}={len(str1)}, {label2}={len(str2)}")
    print(f"  - 一致率: {match_percentage:.1f}%")

# 実際のWiresharkからの文字列と生成した文字列を比較
wireshark_string = to_wireshark_style_escape(packet_bytes)
generated_string = to_wireshark_style_escape(final_packet_bytes)

compare_strings_with_color(generated_string, wireshark_string, 
                          "生成された文字列", "Wiresharkの文字列")



s = socket(AF_INET, SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("10.40.251.14", 50598))
    
    # ★★★ 修正箇所 ★★★
    # 整形後の文字列ではなく、元のバイト列 `final_packet_bytes` を送信する
    s.send(final_packet_bytes)

    print("\n正常にデータを送信しました。")
    s.close()
except timeout:
    print("接続がタイムアウトしました。")
except Exception as e:
    print(f"エラーが発生しました: {e}")