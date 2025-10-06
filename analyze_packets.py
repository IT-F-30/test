import zlib

# ip.txt のパケット
packet_bytes_iptxt = b'5\000\000\000x\23430\000\002\023#\023c\v\006\026\206\340H\003\003A\006g\253\230\362\314\274\202\324\324\242\230\314\002\275\222\212\022C\003=\023\003=CCC\020\006\000\035\374\f\"'

# peer.txt のパケット
packet_bytes_peer = b"R\000\000\000x\234\r\3011\016\200 \f\005P\006\a\017c\240\277-\332p\r'G$e&\206\301\343\353{D?e=\020\226p^Dk\030\356O\234\357\234m\224\224@Q)2[\264\0023\331v\264JM\345\356\214^\265\"k\026\222C\240\236\335\361\001\034\033\023\366"

def analyze_packet(packet_bytes, label):
    print(f"\n{'='*60}")
    print(f"{label} の分析")
    print(f"{'='*60}")
    
    # ヘッダー情報
    print(f"全体長: {len(packet_bytes)} バイト")
    print(f"最初のバイト (圧縮データ長): {packet_bytes[0]} (0x{packet_bytes[0]:02x})")
    print(f"ヘッダー部分 (最初4バイト): {packet_bytes[:4]}")
    
    # 圧縮データを展開
    compressed_data = packet_bytes[4:]
    print(f"圧縮データ長: {len(compressed_data)} バイト")
    
    try:
        decompressed_data = zlib.decompress(compressed_data)
        print(f"展開後のデータ長: {len(decompressed_data)} バイト")
        print(f"\n展開後のデータ (hex):")
        print(' '.join(f'{b:02x}' for b in decompressed_data[:50]))
        
        print(f"\n展開後のデータ (テキスト表示可能部分):")
        print(repr(decompressed_data))
        
        # 構造を解析
        print(f"\n--- データ構造の解析 ---")
        
        # 最初の10バイト: ヘッダー数値
        header_num = decompressed_data[:10].decode('latin-1')
        print(f"ヘッダー数値 (10バイト): '{header_num}'")
        
        # 次の9バイト: 固定部分
        fixed_part = decompressed_data[10:19]
        print(f"固定部分 (9バイト): {fixed_part} = {repr(fixed_part)}")
        print(f"  - バイト10: 0x{fixed_part[0]:02x} ({fixed_part[0]})")
        print(f"  - バイト11: 0x{fixed_part[1]:02x} ({fixed_part[1]})")
        print(f"  - バイト12: 0x{fixed_part[2]:02x} ({fixed_part[2]})")
        print(f"  - バイト13-16: {repr(fixed_part[3:7])}")
        print(f"  - バイト17: 0x{fixed_part[7]:02x} ({fixed_part[7]})")
        print(f"  - バイト18: 0x{fixed_part[8]:02x} ({fixed_part[8]})")
        
        # メタデータ部分
        metadata = decompressed_data[19:]
        print(f"メタデータ部分 (残り{len(metadata)}バイト): {repr(metadata.decode('latin-1'))}")
        
        # メタデータをさらに分析
        try:
            metadata_str = metadata.decode('latin-1')
            # ファイルパスとIPアドレスを分離できるか試す
            if '\\' in metadata_str:
                # Windowsパスが含まれている
                parts = metadata_str.split('\\')
                print(f"\nメタデータの内訳:")
                for i, part in enumerate(parts):
                    print(f"  部分{i}: '{part}' ({len(part)}バイト)")
                
                # ファイル名部分を特定
                if len(parts) >= 3:
                    filename = parts[-1]
                    # IPアドレスが含まれているか確認
                    if '.' in filename and any(c.isdigit() for c in filename):
                        # ファイル名とIPアドレスが結合されている可能性
                        for i in range(len(filename)):
                            if filename[i:i+1].isdigit():
                                possible_filename = filename[:i]
                                possible_ip = filename[i:]
                                if possible_filename and '.' in possible_ip:
                                    print(f"\n推定:")
                                    print(f"  ファイル名: '{possible_filename}' ({len(possible_filename)}バイト)")
                                    print(f"  IPアドレス: '{possible_ip}' ({len(possible_ip)}バイト)")
                                    break
        except Exception as e:
            print(f"メタデータ解析エラー: {e}")
        
        return decompressed_data
        
    except zlib.error as e:
        print(f"展開エラー: {e}")
        return None

# 両方のパケットを解析
data_iptxt = analyze_packet(packet_bytes_iptxt, "ip.txt")
data_peer = analyze_packet(packet_bytes_peer, "peer.txt")

# 差分を比較
if data_iptxt and data_peer:
    print(f"\n{'='*60}")
    print("差分の比較")
    print(f"{'='*60}")
    
    print(f"\n長さの違い:")
    print(f"  ip.txt:   {len(data_iptxt)} バイト")
    print(f"  peer.txt: {len(data_peer)} バイト")
    print(f"  差分:     {len(data_peer) - len(data_iptxt)} バイト")
    
    # バイト単位で比較
    min_len = min(len(data_iptxt), len(data_peer))
    print(f"\n共通部分のバイト比較 (最初の{min_len}バイト):")
    
    diff_positions = []
    for i in range(min_len):
        if data_iptxt[i] != data_peer[i]:
            diff_positions.append(i)
    
    if diff_positions:
        print(f"差異がある位置: {diff_positions}")
        for pos in diff_positions[:10]:  # 最初の10個だけ表示
            print(f"  位置{pos}: ip.txt=0x{data_iptxt[pos]:02x} vs peer.txt=0x{data_peer[pos]:02x}")
    else:
        print("最初の共通部分は完全に一致")
    
    # 固定部分を比較
    print(f"\n固定部分 (バイト10-18) の比較:")
    print(f"  ip.txt:   {data_iptxt[10:19]}")
    print(f"  peer.txt: {data_peer[10:19]}")
    
    # メタデータ部分を比較
    print(f"\nメタデータ部分の比較:")
    print(f"  ip.txt:   {repr(data_iptxt[19:])}")
    print(f"  peer.txt: {repr(data_peer[19:])}")
