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
# 10.40.111.111
packet_bytes_111 = b'5\000\000\000x\23430\000\002\023#\023c\v\006\026\206\340H\003\003A\006g\253\230\362\314\274\202\324\324\242\230\314\002\275\222\212\022C\003=\023\003=CCC\020\006\000\035\374\f\"'

# 10.40.111.11
# b'5\000\000\000x\23430\000\002\023#\023cs\006\026\206\340H\003\003A\006g\253\230\362\314\274\202\324\324\242\230\314\002\275\222\212\022C\003=\023\003=CCC \006\000\021\263\013\360'

# 10.40.111.1
packet_bytes = b'k\001\000\000x\234\215\222MK\0031\020\206{\360\224?\340uXXP\320\356\266V\321\342\212\342I\360 \366$\024J\334\314\322@6\t\311\254m/\376v\223\354\332\366\340\301\334\346\353\235gfR\226\341\315\246\3277W\267\243\223\321\342\243,OG\317\363\345Fj\213\350\226\256\323\253\226K=\376\344\364\210\365\332\200i\032\346\221\224\251\271b\016[xG.\340\345\r\270\020\016\275\207\306\231\026\244\035\323\226@j\2405\202\347-\202\220\016k2n\027\313!\363\265\223\226V\301[\345\337\302\226Y\357\226v\325H\205U~\210\347\275X\306\230l@\033\002\334J\037R\363!7\317\340\214Ax\211o\350\034\363\032\323i\261gHz\a\212q*\261\274\363\330\027k\321\317\224\214\255$(>a\302\316Y\342*l\020^\r#V\367G\275#T2\207`\236UU\366\027\221\364\200\255\245\035\030\027\230\276\270\222\342\337\fu\347\024\\6~\361\n\227\006\262x\232\264\022\310\326Dv^\024\307\000\363\331\335\344zZD<_\354SY:\326SG\246\345$C\023\265\003\201\n\t\323z\204\331he\270@\001\277%\020\025.\340\370\v\\\000\217\033\355\a\342\r\241\203I\t\036k\243\205g$[4]\200\246\350}\320\235b\241C\274i\017;=\270\216E\207\300\017\355\356\321o'

print(f"パケット111の長さ: 全体={len(packet_bytes_111)}, 圧縮データ={len(packet_bytes_111[4:])}, 最初のバイト={packet_bytes_111[0]}")
print(f"パケット1の長さ: 全体={len(packet_bytes)}, 圧縮データ={len(packet_bytes[4:])}, 最初のバイト={packet_bytes[0]}")

# 2 ヘッダーを検証・削除
compressed_data = packet_bytes[4:]
# 3. zlibで展開
try:
    decompressed_data = zlib.decompress(compressed_data)
    print(f"decode {decompressed_data}")
    print(f"デコード後の長さ: {len(decompressed_data)}")
    print(f"デコード後のIPアドレス部分: {decompressed_data[26:]}")
except zlib.error as e:
    print(f"\n[エラー] zlibでの展開に失敗しました: {e}")
except Exception as e:
    print(f"\n[エラー] 予期せぬエラーが発生しました: {e}")

meta_data = "C:\\winpeer\\ip.txt10.40.244.144"
# ヘッダー数値の計算: 42389 + デコード後の全体長
# デコード後の全体長 = 10(ヘッダー) + 9(固定部分) + len(meta_data)
decoded_length = 10 + 9 + len(meta_data)
header_data = str(42389 + decoded_length).zfill(10)

# print(str(original_data_bytes))
original_data_bytes = header_data.encode('latin-1') + "\x00\x04\x00SY00\x11\x00".encode('latin-1') + meta_data.encode('latin-1')
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
# 最初のバイトは圧縮後のペイロード長さ（4バイトヘッダーを除く）
hedchr = chr(len(compressed_payload))
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
# 10.40.111.111のパケットと比較
wireshark_string = to_wireshark_style_escape(packet_bytes_111)
generated_string = to_wireshark_style_escape(final_packet_bytes)

print("\n=== 生成されたパケット vs 10.40.111.111のパケット ===")
compare_strings_with_color(generated_string, wireshark_string, 
                          "生成された文字列(10.40.111.11)", "Wiresharkの文字列(10.40.111.111)")

print("\n=== 生成されたバイト列 ===")
print(f"長さ: {len(final_packet_bytes)}")
print(f"最初の10バイト: {final_packet_bytes[:10]}")
print(f"圧縮データ長: {len(final_packet_bytes[4:])}")

# 生成したパケットをデコードして検証
try:
    test_decompressed = zlib.decompress(final_packet_bytes[4:])
    print(f"\n生成パケットのデコード結果: {test_decompressed}")
    expected_value = header_data.encode('latin-1') + b'\x00\x04\x00SY00\x11\x00' + meta_data.encode('latin-1')
    print(f"期待される値: {expected_value}")
    if test_decompressed == expected_value:
        print("✓ 生成されたパケットは正しくエンコードされています！")
    else:
        print("✗ エンコードに問題があります")
        print(f"  デコード結果の長さ: {len(test_decompressed)}")
        print(f"  期待値の長さ: {len(expected_value)}")
except Exception as e:
    print(f"デコードエラー: {e}")



s = socket(AF_INET, SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("10.40.251.39", 50598))
    
    # ★★★ 修正箇所 ★★★
    # 整形後の文字列ではなく、元のバイト列 `final_packet_bytes` を送信する
    s.send(packet_bytes)

    print("\n正常にデータを送信しました。")
    s.close()
except timeout:
    print("接続がタイムアウトしました。")
except Exception as e:
    print(f"エラーが発生しました: {e}")