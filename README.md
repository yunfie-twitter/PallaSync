# PallaSync Protocol 3.0 relay

Rust/Axum + SQLiteで実装したblind relayです。唯一の仕様は [PALLASYNC-3.0-R1](docs/v3.0.md)、protocol identifierは `pallasync/3`、APIは `/pallasync/v3/` です。変更の根拠と検証範囲は [仕様対応表](docs/conformance.md) を参照してください。

リレーは公開署名・構造・権限・epoch連鎖を検証し、暗号文と公開証拠を保存します。レコード、デバイスメタデータ、epoch secret、mnemonic、復旧共有、RMS、RSWK、復旧パッケージの復号や解釈を行う機能はありません。Shamir recovery・AEAD・競合解決・snapshotの平文完全性検証はクライアントの責務です（§1、§2.1、§7.11、§15、Appendix B）。

## 起動

Linux/Dockerで鍵保護・既定privacy文書の入力/署名・HTTPS起動までコマンドで行う場合は、[セットアップ手順](docs/docker-setup.md)を参照してください。

```sh
bash scripts/setup-docker.sh setup --origin https://api.yunfi.f5.si --cloudflare
```

```sh
cargo build --locked --release
cargo run --locked --release
```

起動前に次の実値を設定してください。未設定・不正な署名・不整合な開示では起動しません。

| 環境変数 | 内容 |
|---|---|
| `PALLASYNC_RELAY_SIGNING_SEED` | 独立したrelay Ed25519 seedのcanonical Base64URL、32 bytes。OS keystore/KMS等で保護された運用者鍵を起動時に注入する。リポジトリや平文の`.env`へ保存しない。 |
| `PALLASYNC_PRIVACY_MARKDOWN` | 運用者が実値を記載したUTF-8 `privacy.md`のパス。 |
| `PALLASYNC_PRIVACY_JSON` | 同じ文書の厳密なbytesのhashを含む、運用者鍵で署名済みの `RelayPrivacyDisclosure` のパス。 |
| `PALLASYNC_QUOTA_BYTES` | 任意の固定per-chain quota。未設定はconfigured quotaなし。開示された範囲・allocation ruleと一致させる。 |
| `DATABASE_URL` | `sqlite:pallasync.sqlite` が既定値。永続ストレージが必須。 |
| `PALLASYNC_BIND_ADDR` | `127.0.0.1:3000` が既定値。公開側はTLS 1.2以上のreverse proxyを必須とする。 |
| `PALLASYNC_SHUTDOWN_AT_MS` | 任意の公表した停止日時。可能な限り30日前に告知する。 |
| `PALLASYNC_MIGRATION_ORIGIN` | 任意の正規化HTTPS origin。利用者への候補提示のみ。 |
| `PALLASYNC_STOP_WRITES` | `true` でsource cutoverの新規書込みを停止。既定値 `false`。読取り・export・認証済み削除は継続する。 |

実装が提供するtierは `single-durable`、削除保証はバックアップを持たない `backup-expiry` です。SQLite WAL + `synchronous=FULL` + `secure_delete=ON` を使用します。複製、バックアップ、crypto-shredを提供したとは広告しません。実装外でコピーやバックアップを作る場合は、その保護・期限・台帳照合を実装し、開示とtierを変更する前に検証する必要があります。

public policyは `/privacy.md` と `/privacy.json` で匿名公開します。`docs/privacy.md` は**開示要件**であり、稼働用の運用者ポリシーではありません。実際の所在地・アクセス主体・copy lifetime・鍵保護・削除期限・運用手順を記入した別文書が必要です。公開文書と実際の設定の一致、人間向け説明の真実性、TLS・ファイルシステムのfsync保証は運用者が確認します（§7.13、§17.1、§17.12）。

quotaのused bytesはJCSで保存されたsigned objects、ID/hash証拠、LogEntry、UploadReceipt、transparency entry/head、idempotency outcome、cursor、offer/requestを合算した論理bytesです。SQLite page/indexの物理使用量とは別です。transparencyもquota対象に含み、quotaによる自動削除は行いません。nonce cache・registry transition等の運用索引は別途物理容量を確保してください。

rate bucketはsource IPのSHA-256と最終更新時刻をSQLiteに保持します。raw IPやtokenをログへ出しませんが、このdigestも運用メタデータです。現在の実装にはrate indexの期限削除がないため、privacy.jsonのmetadataは `ip`・`timing`、目的・アクセス主体・`indefinite` 保持を開示し、copies.cacheはmetadata/retain_metadataとして記載してください。WALとstagingもpresentです。これらを「保持しない」とする開示では起動しません（§7.13、§17.12）。

## Docker

```sh
docker compose up --detach --build
curl --fail http://127.0.0.1:3000/pallasync/v3/health
```

Composeはhostのloopbackにのみ公開します。`PALLASYNC_OPERATOR_DIR` に実値を記載した2文書を配置し、保護されたseedを実行環境へ注入してください。公開HTTPS originはprivacy.jsonとtokenの `aud` に一致させます。policyとkeyは永続化されたorigin/key/revision pinで検査され、無断の鍵交換や同じrevisionでの文書差替えは拒否します。

## 検証

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

公式JCS・SyncRecord署名・attestationベクトル、token binding/replay、restart barrier、atomic epoch/CAS、pending enrollment、revocation、immutable receipts、cursor、export、import/re-seed、pruning、削除台帳を検証します。テスト用の固定鍵・不透明な暗号文は運用へ流用しないでください。

## 保存済みデータと復旧

必要な追加tableを作成し、旧テーブルを自動削除・変換しません。v2形式をv3 endpointへ受け入れるalias/fallbackはありません。§0 D-02／§9に従い、保存された凍結v2 chainのparameters・devices・recordsを別の `/pallasync/v2/` 経路で読み取れます。旧版の作成・登録・書込みを拒否し、明示的な旧chain DELETEだけを旧tableへ適用します。v3 chainには作用しません。

旧実装がChainParametersの元の署名を保存していなかった場合、parametersの取得は空bodyの500となります。空署名・未知の署名方式・saltの推測で補いません。元の端末／exportに原public JSONが残っていれば、DBの元のsalt・creator・admin・時刻との一致を照合して保持できます。

```sh
cargo run --locked --bin pallasync-operator -- retain-legacy-parameters ORIGINAL_CHAIN_PARAMETERS.json sqlite:/absolute/path/pallasync.sqlite
```

このコマンドはpublic bytesの保持だけを行い、旧parameter署名を認証したとは扱いません。v2.1 §4.1にその署名contextと署名者が定義されていない点は移行reportへ明示する必要があります。旧authority・署名・ciphertextを新しいv3 authorityへ流用せず、§9の明示的なclient移行で再暗号化・再署名します。

健全な再起動ではlog_id、transparency_id、receipt、nonce cacheを保存します。acknowledged suffixを失ったバックアップをそのままlive DBに置き戻すことは認めません。削除台帳・公開証拠・nonce状態を独立に保全し、復旧時は台帳と突き合わせ、source履歴を `/chains/import` へstagingして、明示的なadmin署名・新しいgeneration/epoch・完全snapshotによるre-seedを行います（§17.2–§17.5）。sourceの署名だけでは歴史的acceptanceを捏造できません。保持されたLogEntryと一致しないrepairは `REPAIR_PROOF_REQUIRED` とします。

replay cacheを確実に保全できない運用では、公開開示を `restart_barrier` に設定できます。起動時にDBへ単調な `B=R+60000` を記録し、`issued_at_ms < B` のtokenは `TOKEN_NOT_YET_VALID` と待機情報で拒否します。全accepting processは同じDB barrierを参照します。信頼できる時計・台帳照合が確立してから公開してください。

削除は最初にauthorization/CASに結び付く台帳・DeleteReceiptをcommitし、その後に暗号文・metadata・staging・cursor・旧LogEntryを消去しWALをtruncateします。完了確認後に新しいcompletion receiptを署名し、初回202の結果と以前の公開証拠を保持します。証拠を保持するcopyは `authority_evidence` として開示し、削除対象の暗号文を混入させません。運用者外・端末側のコピーの物理消去を証明するものではありません。
