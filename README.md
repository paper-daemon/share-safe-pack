# Share Safe Pack

記事・README・設定例・納品物などを外へ出す前に、うっかり混ざった公開NG候補をまとめてチェックする無料OSSです。

```bash
python share_safe_pack.py ./folder --html report.html --json report.json --redact-out ./safe-copy
```

## できること
- メールアドレス候補
- 電話番号候補
- APIキー / token / password候補
  - フォルダ走査でも `.env` / `.env.*` を対象に含める
  - GitHub公式token prefix（`ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_`）
- プライベートIP
- `/home/...` や `C:\Users\...` などのローカルパス
- TODO / FIXME / DRAFT / WIP / PLACEHOLDER
- 読み取り不能なテキスト候補を `scan_error` として警告（文字コードやI/Oエラーを黙って安全扱いしない）
- HTML / JSONレポート
- 公開用の伏せ字コピー生成

## Release status

GitHub Release `v1.0.0` は初回公開版です。`main` にはその後の安全性修正（symlink境界、redact出力先の再帰/上書き防止、GitHub token prefix追加、`.env` / `.env.*` のフォルダ走査、読み取り不能候補のfail-closed報告、CI）が入っています。

現在のソースを確認する場合は `main` を参照してください。次のtagged releaseを作るまでは、既存release artifact自体は `v1.0.0` のままです。

元ファイルは変更しません。Python 3.10+ / 外部ライブラリ不要 / MIT License。
- BOOTH 0円DL: https://amase-memo.booth.pm/items/8778714
- 作者サイト: https://paper-daemon.github.io/
