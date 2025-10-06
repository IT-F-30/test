from socket import socket, AF_INET, SOCK_STREAM, timeout
import re
import time

# Function to parse the sendpacketmetadata.txt file and extract peer data
def parse_peer_data(file_path):
    peer_data = {}
    with open(file_path, 'r') as file:
        content = file.read()
        matches = re.finditer(r'char (peer0_\d+)\[\] = \{([^}]+)\};', content)
        for match in matches:
            peer_name = match.group(1)
            data = match.group(2).strip().split(',')
            # Filter out comments and whitespace, and convert valid hex values to bytes
            byte_values = [byte.strip() for byte in data if byte.strip().startswith('0x')]
            peer_data[peer_name] = bytes(int(byte, 16) for byte in byte_values)
    return peer_data

# Function to send data with retry mechanism
def send_data_with_retry(peer_name, data, max_retries=3):
    for attempt in range(max_retries):
        try:
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(10)  # タイムアウトを10秒に延長
            s.connect(("10.40.251.43", 50598))
            
            # Send the data for the current peer
            s.send(data)
            s.close()
            
            print(f"正常にデータを送信しました: {peer_name}")
            return True
        except timeout:
            if attempt < max_retries - 1:
                print(f"タイムアウト - リトライ中 ({attempt + 1}/{max_retries}): {peer_name}")
                time.sleep(1)  # リトライ前に1秒待機
            else:
                print(f"接続がタイムアウトしました: {peer_name}")
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"エラー - リトライ中 ({attempt + 1}/{max_retries}): {peer_name} - {e}")
                time.sleep(1)
            else:
                print(f"エラーが発生しました ({peer_name}): {e}")
        finally:
            try:
                s.close()
            except:
                pass
    return False

# Extract peer data from sendpacketmetadata.txt
peer_data = parse_peer_data("sendpacketmetadata.txt")

# Iterate through peer0_0 to peer0_100 and send their data
success_count = 0
fail_count = 0

for i in range(102):
    peer_name = f"peer0_{i}"
    if peer_name in peer_data:
        if send_data_with_retry(peer_name, peer_data[peer_name]):
            success_count += 1
        else:
            fail_count += 1
        
        # 送信間隔に小さな遅延を追加（サーバー負荷軽減）
        time.sleep(0.1)

print(f"\n送信完了: 成功={success_count}, 失敗={fail_count}")