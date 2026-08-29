# Share Safe Pack

記事・README・設定例・納品物などを外へ出す前に、うっかり混ざった公開NG候補をまとめてチェックする無料OSSです。

```bash
python share_safe_pack.py ./folder --html report.html --json report.json --redact-out ./safe-copy
```

## できること
- メールアドレス候補
- 電話番号候補
- APIキー / token / password候補
- プライベートIP
- `/home/...` や `C:\Users\...` などのローカルパス
- TODO / FIXME / DRAFT / WIP / PLACEHOLDER
- HTML / JSONレポート
- 公開用の伏せ字コピー生成

元ファイルは変更しません。Python 3.10+ / 外部ライブラリ不要 / MIT License。
- BOOTH 0円DL: https://amase-memo.booth.pm/items/8778714
- 作者サイト: https://paper-daemon.github.io/

