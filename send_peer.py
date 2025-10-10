import zlib
import zlib
from socket import socket, AF_INET, SOCK_STREAM, timeout

file_path = "C:\\winpeer\\peer.txt"
ip_or_data = "tcp://10.40.233.124:1883,bd9ecadf9f425c922301f2230d59bab5"
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
    
s = socket(AF_INET, SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("10.40.251.14", 50598))
    
    # カスタムIPアドレスのパケット
    s.send(final_packet_bytes)
    
    print("\n正常にデータを送信しました。")
    s.close()
except timeout:
    print("接続がタイムアウトしました。")
except Exception as e:
    print(f"エラーが発生しました: {e}")