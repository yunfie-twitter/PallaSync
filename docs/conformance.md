# PALLASYNC-3.0-R1 サーバー実装の対応表

唯一の規範は [v3.0.md](v3.0.md) です。このファイル、README、実装、設定、テストは仕様を変更しません。

同梱した仕様は依頼時の添付文書の無改変コピーです。SHA-256は `df3963183db187a2080283860ae5af51d31dc11e6c2947d58753d586ba2cec56`、同梱privacy.schema.jsonは `be96cba6152cedd087cb08875cfa5d074211cf37b0540014e61fdeecd4ceff23` です。

| 変更 | 根拠 | 実装と検証 |
|---|---|---|
| 3.0識別子・閉じたendpoint catalogue・media type・typed problemsへ変更 | §0、§10、§19 | `sync.rs`、`error.rs`。v2 alias、独自error code、旧pagination headerを削除。全応答にDate/no-store/protocol header。 |
| wire JSONをtyped validationの前に検査 | §3.1–§3.6、§12.2、C.1 | `jcs.rs`、`wire.rs`。重複キー・負数・小数/exponent・unsafe integer・depth 33・BOM・surrogate・未知member・非正規b64u・UUID/NFC違反を拒否。JCS-01–04のbytes/hashを照合。 |
| pure Ed25519・専用context・strict A/R/S検証 | §4、§4.1、C.5/C.9 | `verify.rs`。prime-order非identity点とcanonical scalar、X25519 canonical coordinate/zero-DHをvetted librariesで確認。旧prehash fallbackを削除。nested signatureを残してown signatureだけ除外。 |
| raw requestに結び付くCapability Tokenとdurable replay protection | §6.1–§6.4 | `auth.rs`。aud/method/exact path/query/body digest、120s fixture/300s acceptance ceiling、±60s、再利用拒否。nonce reservationをoperationとは別transactionで先にcommitし、失敗でも消費。再起動・競合・barrierをテスト。 |
| plaintext metadataをSyncRecordから排除 | §7.1、§14.1–§14.3 | `wire.rs`、`domain.rs`。version/generation/UUIDv4/nullable tag/standard bucketsだけを検査。collection/action/Lamport等を受け付けない。暗号文の内容・HMAC・AEADは解釈しない。 |
| admin-rooted enrollmentとimmutable registry | §7.4、§7.9、§10.4–§10.8、§18.1–§18.5 | `mutation.rs`、`domain.rs`。both keys・certificate/request hash・subject signatureを検証。pendingは自分のkey stateだけを読め、current key ackでactive化。自動再登録を削除。 |
| complete epoch bundle・CAS・失効のatomic commit | §7.6–§7.7、§13.1–§13.4、§17.2 | `domain.rs`、`mutation.rs`。exact membership、predecessor、current generation、recovery hash、全member envelope、authorityを検査。device/envelope/admin/epochの順序でcommit。競合・不完全bundleはheadを変えない。 |
| old-envelope expiryをsafe handoffに限定 | §13.5–§13.6、§16.7 | `retention.rs`。retainは保持。windowed/immediateもadmin-authorized pruneとcurrent-epoch snapshotが揃うまで保持。未handoffのimmediate enrollmentを制限。時計だけでhistoryを消さない。scheduledはkey生成を行わず通常writeを許可。 |
| fsynced acceptance・immutable ID evidence・台帳保全 | §9、§12.2、§17.1–§17.3 | `db`、`store.rs`。FULL WAL、unique ID/hash、per-chain log_id/seq/H、nonce/idempotency保存。旧DBの破壊的resetを廃止。 |
| signed receiptsと独立transparency chain | §7.12、§10.17、§17.9–§17.11 | `store.rs`、`read.rs`。H/Tの規定recurrenceを使用。receipt/entry/headは同じcommit。retryはoriginal receipt。rejectはauthenticated parsed candidateだけを記録。readやtoken失敗をlog floodにしない。 |
| pinned paginationとbounded transfer | §10.9、§10.16–§10.17、§17.8 | `read.rs`、`export.rs`。opaque stored CSPRNG cursor、24h、resource/filter/generation/log/origin binding、registry/requestのpinned versions、8MiB byte bound、transparency streaming、2 concurrent transfers。 |
| snapshot store・pruning・repairの分離 | §7.8、§10.11–§10.13、§16.6–§16.7 | snapshot partはeventに混入しない。part hash/generation/epoch/author/coverage boundaryを検査。semantic completeness/HMACはclient、pruneはadmin署名。ID/hash・control evidence・receipts/transparencyを保存。historical proof不足のrepairを拒否。 |
| export/import/re-seed | §10.3、§10.14、§17.4–§17.6 | bounded JCS JSONL、dual pinned cuts、D exportのrecovery omission、source signed DAG、staging、generation+1/global epoch+1、fresh pending subjects、old members retirement、coverage 0 snapshot。target receiptsをsourceのreceiptと偽らない。 |
| authenticated deletionとanti-resurrection | §7.10、§7.12.3、§10.15、§17.7、§17.11 | `deletion.rs`。admin/policy-permitted D、CAS、exact target hash、ledger recurrence、original202 retry、authorized post-deletion proof、active erasure/WAL checkpoint後のcompletion。private metadataをauthority proofへ残さない。 |
| 独立relay鍵・署名済みoperator disclosure・lower limits | §7.13、§17.8–§17.12 | `config.rs`。正確な同梱schema、semantic/URL/binary/Markdown hash/signature/revision/quota/tierの検査。実値未設定では起動拒否。rate bucketのIP digest/時刻を運用メタデータとして開示し、WAL/staging/cacheの実在を検査。暗号処理はrelay attestationだけで、client E2EE/root鍵を保持しない。 |
| コマンド式Dockerセットアップと既定privacyひな形 | §7.13、§17.1、§17.8–§17.12 | `setup-docker.sh`、`docker_config.py`、`pallasync-operator`、`deploy/privacy.*.in`。運用固有値を入力し、既存のJCS/Ed25519と同一validatorで署名。age保護鍵をtmpfsから稼働環境へ注入し、既存鍵・公開版・永続ストアを再利用。匿名HTTPS文書とhealthを照合。追加HTTP APIやclient暗号処理なし。 |
| shutdown/migration noticeとwrite freeze | §10.14、§17.6、§7.12.2 | 既存notice型を公表しexact valueをmigrate transparency entryへ結ぶ。configured originは候補のみ。redirect、Authorization forwarding、federation、automatic chain deletionを追加しない。freezeは503で、読取りとexportを保全。 |

## 依頼者が確認した解釈

§7.7の「device tokenでrecovery envelopeを返してはならない」を優先し、§10.9 `/log` と§10.17 `/receipts`でも、該当objectをDに返す要求は `403 ENVELOPE_ACCESS_DENIED` とします。依頼者がこの解釈を明示的に承認しました。LogEntryのobject差替え、未知のomitted形式、別hash、代替APIは追加していません。Aは完全なlog/exportを取得でき、Dのevent pullとtransparency readは使用できます。

## サーバー検証の境界

テストはrelay側の構造・署名・認可・atomicity・公開hash/receipt・paging・storage動作を検証します。独立した2つのクライアントを用いたAppendix Bのend-to-end certification、実際のクライアント復号・state commitmentの再計算、Shamir ceremony、端末secure storage、実ディスク/停電試験、外部copyの消去、deployment TLSとoperator説明の真実性はこのサーバーのテストだけでは証明できません。これらをrelay側の復号機能で代替しません。

acknowledged suffix lossからの復旧は、削除台帳・nonce状態・sourceの公開証拠を独立に照合し、staging/importと明示的admin re-seedを行います。live DBを古いバックアップで上書きする自動restore、旧log_idの偽装、未証明のhistorical acceptance、source receiptの再署名は実装しません。詳細はREADMEの運用手順を参照してください。
