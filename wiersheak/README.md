# TCP Data Sender

pcapng ファイルから TCP データを抽出して、任意のサーバーに送信するツールです。

## 使い方

### ステップ 1: データ抽出

pcapng ファイルから TCP ペイロードデータを JSON 形式で抽出します。

```bash
python3 extract_data.py
```

これにより `tcp_data.json` ファイルが生成されます。

### ステップ 2: データ送信

抽出したデータを指定した IP アドレスに送信します。

```bash
python3 send_packet_winpeer.py
```

## ファイル説明

- **extract_data.py**: pcapng からデータを抽出するスクリプト
- **send_packet_winpeer.py**: JSON ファイルからデータを読み込んで送信するスクリプト
- **tcp_data.json**: 抽出された TCP データ（自動生成）

## tcp_data.json の形式

```json
{
  "total_packets": 57,
  "total_bytes": 145230,
  "packets": [
    {
      "packet_id": 1,
      "src_ip": "10.40.251.11",
      "dst_ip": "10.40.251.14",
      "src_port": 49152,
      "dst_port": 8080,
      "data_hex": "48656c6c6f...",
      "data_length": 1024
    }
  ]
}
```

## カスタマイズ

### 送信先 IP アドレスを変更

`send_packet_winpeer.py` の `main()` 関数内で `target_ip` を変更:

```python
send_tcp_data(packets, target_ip="192.168.1.100", dry_run=False)
```

### ドライランモード

実際に送信せずにテストする場合:

```python
send_tcp_data(packets, target_ip="10.40.251.43", dry_run=True)
```

## 必要な環境

- Python 3.6 以上
- scapy（データ抽出時のみ必要）

```bash
pip install scapy
```

データ送信時は標準ライブラリのみで動作するため、追加のインストールは不要です。

## 注意事項

- データ送信時は sudo 権限は不要です
- 送信先のサーバーがポートを開いている必要があります
- 接続が拒否される場合は、送信先のファイアウォール設定を確認してください
