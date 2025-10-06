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

# ip.txt
packet_bytes_iptxt = b'5\000\000\000x\23430\000\002\023#\023c\v\006\026\206\340H\003\003A\006g\253\230\362\314\274\202\324\324\242\230\314\002\275\222\212\022C\003=\023\003=CCC\020\006\000\035\374\f\"'

# peer.txt
packet_bytes_peer = b"R\000\000\000x\234\r\3011\016\200 \f\005P\006\a\017c\240\277-\332p\r'G$e&\206\301\343\353{D?e=\020\226p^Dk\030\356O\234\357\234m\224\224@Q)2[\264\0023\331v\264JM\345\356\214^\265\"k\026\222C\240\236\335\361\001\034\033\023\366"

packet_bytes = b'5\000\000\000x\23430\000\002\023#\023c3\006\026\206\340H\003\003A\006g\253\230\362\314\274\202\324\324\242\230\314\002\275\222\212\022C\003=\023\003=CCC=C\000\005\235\v\276'

# print(f"パケット111の長さ: 全体={len(packet_bytes_111)}, 圧縮データ={len(packet_bytes_111[4:])}, 最初のバイト={packet_bytes_111[0]}")
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

def create_packet(file_path, ip_or_data):
    """
    ファイルパスとIPアドレス(またはその他のデータ)からパケットを生成する
    
    【パケット構造の説明】
    圧縮前のデータ構造:
      - バイト 0-9:   ヘッダー数値 (10桁の文字列、42389 + データ全体長)
      - バイト 10-18: 固定部分
        * バイト 10-12: \x00\x04\x00
        * バイト 13-16: "SY00" (固定文字列)
        * バイト 17:    ファイルパスの長さ (★重要★ここが自動調整されます)
        * バイト 18:    \x00
      - バイト 19-:   メタデータ (ファイルパス + IPアドレスなど)
    
    圧縮後のパケット構造:
      - バイト 0:     圧縮データの長さ
      - バイト 1-3:   \x00\x00\x00 (固定ヘッダー)
      - バイト 4-:    zlib圧縮されたデータ
    
    Args:
        file_path: ファイルのフルパス (例: "C:\\winpeer\\ip.txt" または "peer.txt")
        ip_or_data: IPアドレスやその他のデータ (例: "10.40.241.126" または "tcp://10.40.228.8:1883,...")
    
    Returns:
        tuple: (生成されたパケット(バイト列), 圧縮前の元データ(バイト列))
    
    使用例:
        # ip.txtの場合
        packet, original = create_packet("C:\\winpeer\\ip.txt", "10.40.241.126")
        
        # peer.txtの場合
        packet, original = create_packet("peer.txt", "tcp://10.40.228.8:1883,...")
        
        # 任意のファイルパスの場合
        packet, original = create_packet("D:\\data\\config.txt", "192.168.1.1")
    """
    # メタデータ部分を結合
    meta_data = file_path + ip_or_data
    
    # ファイルパスの長さを計算 (バイト17に設定する値)
    file_path_length = len(file_path.encode('latin-1'))
    
    # ヘッダー数値の計算: 42389 + デコード後の全体長
    # デコード後の全体長 = 10(ヘッダー) + 9(固定部分) + len(meta_data)
    decoded_length = 10 + 9 + len(meta_data.encode('latin-1'))
    header_data = str(42389 + decoded_length).zfill(10)
    
    # 固定部分を構築 (バイト17にファイルパスの長さを設定)
    # フォーマット: \x00\x04\x00SY00[ファイルパス長]\x00
    fixed_part = b'\x00\x04\x00SY00' + bytes([file_path_length]) + b'\x00'
    
    # 元データを構築
    original_data_bytes = header_data.encode('latin-1') + fixed_part + meta_data.encode('latin-1')
    
    # zlibで圧縮
    compressed_payload = zlib.compress(original_data_bytes)
    
    # ヘッダーを付与
    hedchr = chr(len(compressed_payload))
    header = b'\x00\x00\x00'
    final_packet_bytes = hedchr.encode('latin-1') + header + compressed_payload
    
    return final_packet_bytes, original_data_bytes


# 使用例1: ip.txt のパケットを生成 (元のパケットと同じIPアドレスを使用)
packet_ip, original_ip = create_packet("C:\\winpeer\\ip.txt", "10.40.111.111")

# 使用例2: peer.txt のパケットを生成
packet_peer, original_peer = create_packet("peer.txt", "tcp://10.40.228.8:1883,61ca0c43bf21fa4a15453037314e5ee1")

# 使用例3: カスタムIPアドレスでip.txtパケットを生成
packet_ip_custom, original_ip_custom = create_packet("C:\\winpeer\\peer.txt", "tcp://10.40.228.8:1883,61ca0c43bf21fa4a15453037314e5ee1")

# 元のmeta_data変数も残す（後続のコードとの互換性のため）
meta_data = "C:\\winpeer\\ip.txt10.40.241.126"
decoded_length = 10 + 9 + len(meta_data)
header_data = str(42389 + decoded_length).zfill(10)
file_path_length = len("C:\\winpeer\\ip.txt".encode('latin-1'))
original_data_bytes = header_data.encode('latin-1') + b'\x00\x04\x00SY00' + bytes([file_path_length]) + b'\x00' + meta_data.encode('latin-1')
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
wireshark_string = to_wireshark_style_escape(packet_bytes)
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


# ===== 新しい関数で生成したパケットを検証 =====
print("\n" + "="*60)
print("新しいcreate_packet関数で生成したパケットの検証")
print("="*60)

# ip.txt パケットの検証
print("\n--- ip.txt パケットの検証 ---")
print(f"生成されたパケット長: {len(packet_ip)} バイト")
print(f"元のパケット長: {len(packet_bytes_iptxt)} バイト")

try:
    decoded_ip = zlib.decompress(packet_ip[4:])
    print(f"デコード成功: {repr(decoded_ip)}")
    print(f"ファイルパス長バイト(バイト17): 0x{decoded_ip[17]:02x} ({decoded_ip[17]})")
    
    expected_path = "C:\\winpeer\\ip.txt"
    print(f"実際のファイルパス: '{expected_path}' = {len(expected_path)} バイト")
    
    # 元のパケットと比較
    decoded_original_ip = zlib.decompress(packet_bytes_iptxt[4:])
    if decoded_ip == decoded_original_ip:
        print("✓ 元のip.txtパケットと完全に一致！")
    else:
        print(f"✗ 差異あり: 生成={len(decoded_ip)}バイト, 元={len(decoded_original_ip)}バイト")
except Exception as e:
    print(f"✗ エラー: {e}")

# peer.txt パケットの検証
print("\n--- peer.txt パケットの検証 ---")
print(f"生成されたパケット長: {len(packet_peer)} バイト")
print(f"元のパケット長: {len(packet_bytes_peer)} バイト")

try:
    decoded_peer = zlib.decompress(packet_peer[4:])
    print(f"デコード成功: {repr(decoded_peer)}")
    print(f"ファイルパス長バイト(バイト17): 0x{decoded_peer[17]:02x} ({decoded_peer[17]})")
    print(f"実際のファイルパス: 'peer.txt' = {len('peer.txt')} バイト")
    
    # 元のパケットと比較
    decoded_original_peer = zlib.decompress(packet_bytes_peer[4:])
    if decoded_peer == decoded_original_peer:
        print("✓ 元のpeer.txtパケットと完全に一致！")
    else:
        print(f"✗ 差異あり: 生成={len(decoded_peer)}バイト, 元={len(decoded_original_peer)}バイト")
except Exception as e:
    print(f"✗ エラー: {e}")

# 任意のファイルパスでのテスト例
print("\n--- カスタムパケットの生成例 ---")
custom_path = "C:\\winpeer\\peer.txt"
custom_packet, custom_original = create_packet(custom_path, "tcp://10.40.228.8:1883,61ca0c43bf21fa4a15453037314e5ee1")
try:
    decoded_custom = zlib.decompress(custom_packet[4:])
    print(f"カスタムパケット生成成功: {repr(decoded_custom)}")
    print(f"ファイルパス長: {decoded_custom[17]} バイト (期待値: {len(custom_path)})")
except Exception as e:
    print(f"エラー: {e}")


s = socket(AF_INET, SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("10.40.251.43", 50598))
    
    # 新しい関数で生成したパケットを送信
    # 送信したいファイルとデータに応じて選択できます
    
    # 元のIPアドレスと一致するパケット
    # s.send(packet_ip)  # ip.txt with 10.40.111.111

    # 元のpeer.txtパケット
    # s.send(packet_peer)  # peer.txt with tcp://10.40.228.8:1883,61ca0c43bf21fa4a15453037314e5ee1
    
    # カスタムIPアドレスのパケット
    s.send(packet_ip_custom)  # peer.txt with tcp://10.40.241.126
    
    print("\n正常にデータを送信しました。")
    print(f"送信したパケット: ip.txt ({len(packet_ip)} バイト)")
    s.close()
except timeout:
    print("接続がタイムアウトしました。")
except Exception as e:
    print(f"エラーが発生しました: {e}")