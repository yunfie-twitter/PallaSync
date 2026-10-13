# PALLASYNC-3.0-R1 サーバー実装の対応表

唯一の規範は [v3.0.md](v3.0.md) です。このファイル、README、実装、設定、テストは仕様を変更しません。

同梱した仕様は依頼時の添付文書の無改変コピーです。SHA-256は `df3963183db187a2080283860ae5af51d31dc11e6c2947d58753d586ba2cec56`、同梱privacy.schema.jsonは `be96cba6152cedd087cb08875cfa5d074211cf37b0540014e61fdeecd4ceff23` です。

| 変更 | 根拠 | 実装と検証 |
|---|---|---|
| 3.0識別子・閉じたendpoint catalogue・media type・typed problemsへ変更 | §0、§10、§19 | `sync.rs`、`error.rs`。v3へのv2 alias、独自error code、旧pagination headerを削除。v3応答にDate/no-store/protocol header。凍結した旧版は別経路で扱う。 |
| wire JSONをtyped validationの前に検査 | §3.1–§3.6、§12.2、C.1 | `jcs.rs`、`wire.rs`。重複キー・負数・小数/exponent・unsafe integer・depth 33・BOM・surrogate・未知member・非正規b64u・UUID/NFC違反を拒否。JCS-01–04のbytes/hashを照合。 |
| pure Ed25519・専用context・strict A/R/S検証 | §4、§4.1、C.5/C.9 | `verify.rs`。prime-order非identity点とcanonical scalar、X25519 canonical coordinate/zero-DHをvetted librariesで確認。旧prehash fallbackを削除。nested signatureを残してown signatureだけ除外。 |
| raw requestに結び付くCapability Tokenとdurable replay protection | §6.1–§6.4 | `auth.rs`。aud/method/exact path/query/body digest、120s fixture/300s acceptance ceiling、±60s、再利用拒否。nonce reservationをoperationとは別transactionで先にcommitし、失敗でも消費。再起動・競合・barrierをテスト。 |
| plaintext metadataをSyncRecordから排除 | §7.1、§14.1–§14.3 | `wire.rs`、`domain.rs`。version/generation/UUIDv4/nullable tag/standard bucketsだけを検査。collection/action/Lamport等を受け付けない。暗号文の内容・HMAC・AEADは解釈しない。 |
| admin-rooted enrollmentとimmutable registry | §7.4、§7.9、§10.4–§10.8、§18.1–§18.5 | `mutation.rs`、`domain.rs`。both keys・certificate/request hash・subject signatureを検証。pendingは自分のkey stateだけを読め、current key ackでactive化。自動再登録を削除。 |
| complete epoch bundle・CAS・失効のatomic commit | §7.6–§7.7、§13.1–§13.4、§17.2 | `domain.rs`、`mutation.rs`。exact membership、predecessor、current generation、recovery hash、全member envelope、authorityを検査。device/envelope/admin/epochの順序でcommit。競合・不完全bundleはheadを変えない。 |
| 独立クライアントによるepoch/CAS/失効の隔離検証 | §7.10、§10.8–§10.10、§13.3–§13.4、§17.9 | `tests/reference/epoch_interop.py`。Pythonが全memberのHPKE・commitmentを確認し、別提案のCAS失敗、不完全bundle、正確な再送、再起動、新epoch暗号文、誤targetの拒否、atomic失効、全元receiptとH/Tを照合。対象ケースの実行であり、Android UI・全三者ITの完了ではない。relay runtimeへの復号処理追加なし。 |
| old-envelope expiryをsafe handoffに限定 | §13.5–§13.6、§16.7 | `retention.rs`。retainは保持。windowed/immediateもadmin-authorized pruneとcurrent-epoch snapshotが揃うまで保持。未handoffのimmediate enrollmentを制限。時計だけでhistoryを消さない。scheduledはkey生成を行わず通常writeを許可。 |
| fsynced acceptance・immutable ID evidence・台帳保全 | §9、§12.2、§17.1–§17.3 | `db`、`store.rs`。FULL WAL、unique ID/hash、per-chain log_id/seq/H、nonce/idempotency保存。旧DBの破壊的resetを廃止。 |
| signed receiptsと独立transparency chain | §7.12、§10.17、§17.9–§17.11 | `store.rs`、`read.rs`。H/Tの規定recurrenceを使用。receipt/entry/headは同じcommit。retryはoriginal receipt。rejectはauthenticated parsed candidateだけを記録。readやtoken失敗をlog floodにしない。 |
| pinned paginationとbounded transfer | §10.9、§10.16–§10.17、§17.8 | `read.rs`、`export.rs`。opaque stored CSPRNG cursor、24h、resource/filter/generation/log/origin binding、registry/requestのpinned versions、8MiB byte bound、transparency streaming、2 concurrent transfers。 |
| snapshot store・pruning・repairの分離 | §7.8、§10.11–§10.13、§16.6–§16.7 | snapshot partはeventに混入しない。part hash/generation/epoch/author/coverage boundaryを検査。semantic completeness/HMACはclient、pruneはadmin署名。ID/hash・control evidence・receipts/transparencyを保存。historical proof不足のrepairを拒否。 |
| export/import/re-seed | §10.3、§10.14、§17.4–§17.6 | bounded JCS JSONL、dual pinned cuts、D exportのrecovery omission、source signed DAG、staging、generation+1/global epoch+1、fresh pending subjects、old members retirement、coverage 0 snapshot。target receiptsをsourceのreceiptと偽らない。 |
| authenticated deletionとanti-resurrection | §7.10、§7.12.3、§10.15、§17.7、§17.11 | `deletion.rs`。admin/policy-permitted D、CAS、exact target hash、ledger recurrence、original202 retry、authorized post-deletion proof、active erasure/WAL checkpoint後のcompletion。private metadataをauthority proofへ残さない。 |
| 独立relay鍵・署名済みoperator disclosure・lower limits | §7.13、§17.8–§17.12 | `config.rs`。正確な同梱schema、semantic/URL/binary/Markdown hash/signature/revision/quota/tierの検査。実値未設定では起動拒否。rate bucketのIP digest/時刻を運用メタデータとして開示し、WAL/staging/cacheの実在を検査。暗号処理はrelay attestationだけで、client E2EE/root鍵を保持しない。 |
| コマンド式Dockerセットアップと既定privacyひな形 | §7.13、§17.1、§17.8–§17.12 | `setup-docker.sh`、`docker_config.py`、`pallasync-operator`、`deploy/privacy.*.in`。運用固有値を入力し、既存のJCS/Ed25519と同一validatorで署名。age保護鍵をtmpfsから稼働環境へ注入し、既存鍵・公開版・永続ストアを再利用。匿名HTTPS文書とhealthを照合。追加HTTP APIやclient暗号処理なし。 |
| 公開operator文書の保存と署名検証 | §7.13、§17.9、§17.12 | `operator/api.yunfi.f5.si`、`tests/operator_policy.rs`。実際の公開版を厳密なbytesで保存し、公開検証鍵とv3 contextで検証。デプロイのTLS条件に関する残事項は同directoryのREADMEに記載。 |
| Palleria native生成objectとの接続回帰検証 | §3.4、§4.1、§6、§10.2、§10.5–§10.6 | `tests/fixtures/palleria-v3-genesis.json`、`tests/v3_integration.rs`。公開KDF-01 mnemonicのテスト用genesis/recordを受理し、v2 mediaとUUIDv7を拒否。200の部分拒否でも受理objectのreceiptを維持。fixtureのseedは公開テスト鍵であり、実ユーザー・relayの鍵ではない。 |
| shutdown/migration noticeとwrite freeze | §10.14、§17.6、§7.12.2 | 既存notice型を公表しexact valueをmigrate transparency entryへ結ぶ。configured originは候補のみ。redirect、Authorization forwarding、federation、automatic chain deletionを追加しない。freezeは503で、読取りとexportを保全。 |
| 凍結したv2.1読取りと明示的な旧chain削除 | §0 D-02、§9.1–§9.4（旧wireはv2.1 §6/§7/§10） | `legacy.rs`。v2.1 capability context、raw path/query/body hash、永続nonce、200行のkeyset pagingとoperator byte limit。ciphertext・元署名を維持し、旧版のPOST/PUTを拒否。旧版DELETEは旧tableだけに作用し、v3のnonce・H/T・削除台帳を操作しない。24 integration testsとoperator test、fmt/clippyが成功。 |
| 失われた旧ChainParameters署名を生成しない | §9.1–§9.3 | 未保存の原JSONは500/空bodyで失敗し、空署名や新しい署名contextを作らない。`pallasync-operator retain-legacy-parameters`は原public bytesと旧DBのsalt・creator・admin・時刻の一致だけを照合して保持し、署名を認証済みと扱わない。v2.1 §4.1にparameter署名context/署名者がない点はclient移行の仕様解釈確認中。 |

## 依頼者が確認した解釈

§7.7の「device tokenでrecovery envelopeを返してはならない」を優先し、§10.9 `/log` と§10.17 `/receipts`でも、該当objectをDに返す要求は `403 ENVELOPE_ACCESS_DENIED` とします。依頼者がこの解釈を明示的に承認しました。LogEntryのobject差替え、未知のomitted形式、別hash、代替APIは追加していません。Aは完全なlog/exportを取得でき、Dのevent pullとtransparency readは使用できます。

## サーバー検証の境界

§5.5/§7.11のローカル専用artifact 8種とmnemonic/passphrase入力objectは、公開wireのextへ入れ子にしてもINVALID_FIELDで拒否します。暗号文の復号・検査はしません。通常文字列や一般の許可されたextは維持します。署名済み不正record 9件と正常record 1件のHTTP batchで、前者は保存されずHを進めず、後者だけが原receiptとともに受理されることを確認しました。現行serverの25 integration＋1 operator試験、fmt/clippy/bins buildは成功しています。

旧版ChainParametersの署名は、依頼者の指定に従い仕様で定義された方式のみを使います。v2.1 §4.1/§7.4にcontext・署名者・対象memberの指定がないため、該当する定義の提示待ちです。署名未検証のparameterを信頼する代替解釈は承認済みとして扱いません。

2026-10-13、独立Pythonの`run_legacy_interop.py`は現行relay binaryの隔離HTTPS/SQLiteで成功しました。v2.1 KDF、端末/record原署名、AEAD、凍結paging、欠落parameter署名の報告、再起動後nonce拒否、明示旧版削除とv3 Hの維持を確認しています。Androidの旧版変換・信頼確認・再開journalと全三者ITは未完了です。

`tests/reference`は独立したPython参照クライアントです。Rust/JNIと暗号実装を共用せず、
GF(256)は`galois`の多項式`0x11b`で検証します。隔離HTTPSリレーで新規chain、暗号化レコード、
署名済みreceiptの正確な再取得、H/T連鎖のページ検証、再起動後のnonce拒否、§7.7のアクセス拒否を
実行します。この試験の成功は、Androidアプリを含むIT-01〜IT-50全件の成功を意味しません。

テストはrelay側の構造・署名・認可・atomicity・公開hash/receipt・paging・storage動作を検証します。独立した2つのクライアントを用いたAppendix Bのend-to-end certification、実際のクライアント復号・state commitmentの再計算、Shamir ceremony、端末secure storage、実ディスク/停電試験、外部copyの消去、deployment TLSとoperator説明の真実性はこのサーバーのテストだけでは証明できません。これらをrelay側の復号機能で代替しません。

acknowledged suffix lossからの復旧は、削除台帳・nonce状態・sourceの公開証拠を独立に照合し、staging/importと明示的admin re-seedを行います。live DBを古いバックアップで上書きする自動restore、旧log_idの偽装、未証明のhistorical acceptance、source receiptの再署名は実装しません。詳細はREADMEの運用手順を参照してください。

§8.6の復旧監査をPython参照clientで独立に検査するよう追加しました（tests/reference/recovery_audit.py、test_recovery_audit.py）。公開メタデータ以外のfield、holder ID、誤ったt/n/count、whole-set／ceremonyの非null holder_kindを拒否します。全25 reference unit試験は1.003秒で成功しました。署名／AEAD roundtripは参照client内の試験で、Androidを含む三者ITの完了ではありません。relay runtimeへ復号／schema解釈を追加していません。

2026-10-13の再検証ではserverの全26試験、fmt／clippy／bins build、独立Python／隔離HTTPS relayのepoch・CAS・atomic失効、peer承認、凍結legacy／nonce／旧版削除、Docker設定生成が通過しました（target/qualification-*.log）。Androidの全機能、全50 IT、production更新は完了していません。

同日、再生成client APKと隔離relayで `run_android_interop.py --rotate-epoch --peer-enrollment` を再実行し190.27秒で成功しました（`target/qualification-android-resume-interop.log`）。Android由来の暗号化record・同期・epoch・peer承認証拠を、Python参照clientが独立に検証します。この対象試験はAppendix Bの完全な認証、Android recovery lifecycle全件、IT-01〜IT-50を意味しません。
