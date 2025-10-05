from socket import socket, AF_INET, SOCK_STREAM, timeout
import re

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

# Extract peer data from sendpacketmetadata.txt
peer_data = parse_peer_data("sendpacketmetadata.txt")

# Iterate through peer0_0 to peer0_100 and send their data
for i in range(101):
    peer_name = f"peer0_{i}"
    if peer_name in peer_data:
        try:
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(5)
            s.connect(("10.40.251.39", 50598))

            # Send the data for the current peer
            s.send(peer_data[peer_name])

            print(f"正常にデータを送信しました: {peer_name}")
            s.close()
        except timeout:
            print(f"接続がタイムアウトしました: {peer_name}")
        except Exception as e:
            print(f"エラーが発生しました ({peer_name}): {e}")