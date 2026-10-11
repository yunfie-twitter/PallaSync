# Linux / Docker のコマンド式セットアップ

`deploy/privacy.md.in` と `deploy/privacy.json.in` が既定の文書ひな形です。実装で確定する値を記載し、運用者固有の値だけを対話入力します。ひな形は未署名・未完成で、そのまま公開できません。`docs/privacy.md` は仕様の開示要件であり、運用者文書の代用にはしません（§7.13、§17.12）。

Docker Engine、Compose v2、Python 3.10以上を導入したLinuxで実行してください。Ubuntu/Debianで補助コマンドを入れる場合：

```sh
sudo apt-get update
sudo apt-get install --yes age openssl python3 curl util-linux
```

Docker未導入の場合は[公式のLinux向け導入手順](https://docs.docker.com/engine/install/)と[Compose pluginの導入手順](https://docs.docker.com/compose/install/linux/)を使用します。

既存Cloudflareの転送先がこのサーバーの3090ポートになっている状態で、リポジトリ内から次の1コマンドを実行します。Cloudflareの設定は変更せず、proxyを追加しません。

```sh
bash scripts/setup-docker.sh setup --origin https://api.yunfi.f5.si --cloudflare
```

運用者名、アカウント不要の連絡先URL、保存地域と委託先・アクセス主体、保存用暗号化・アクセス制御、守れる削除期限、quota、告知・過去版の実際の公開URLと最低告知期間を入力します。実値に未回答なら進めません。バックアップ・レプリカ・外部snapshot・サポートコピー・永続アクセスログがないこと、swapが無効か暗号化されcore dumpがないことも確認します。この既定構成と実際の運用が異なる場合、ひな形を署名して提供開始してはいけません。

コマンドがimageをbuildし、独立した32-byte CSPRNG relay seedを作成してageでpassphrase暗号化します。鍵生成時と解除時にageの対話入力があります。既存の `~/.config/pallasync/relay-seed.age` は再利用します。age passphraseは別に保管し、秘密鍵ファイルやリポジトリと一緒に保存しないでください。seedを表示するコマンドはありません（§17.9）。

次に、image内の `pallasync-operator` がseedをstdinで受け取り、既存のEd25519/JCS署名処理とサーバーと同一のschema・意味検証を使って文書を生成します。revision 1、UUIDv4 disclosure ID、公開/適用UTC時刻、relay key ID、厳密なMarkdown hashを生成し、`PALLASYNC-RELAY-PRIVACY-v3\0` で署名します。再実行は既存の文書と鍵を検証し、同じrevisionの文書を書き換えません（§7.13）。

生成されたCompose構成で永続SQLiteを起動し、既定では `0.0.0.0:3090` に公開します。`--host-bind 127.0.0.1` で同一ホストのproxyだけに限定できます。旧imageのUIDを使った既存データは、このproject専用のvolume内だけ所有者をUID/GID 10001へ合わせます。ネットワークと鍵を持たない一時helperを使用し、データは消去しません。最後に匿名healthと公開privacy文書を取得し、origin・鍵・limits・本文を照合します。DNS/TLSの検証が失敗した場合は成功を表示せず、起動したコンテナと永続データは残します。既存経路を修正後に同じコマンドを再実行できます。

| 保存物 | 既定の場所 |
|---|---|
| 暗号化したrelay seed | `~/.config/pallasync/relay-seed.age`（directory 700、file 600） |
| 署名済みの公開文書・公開検証鍵 | `~/.local/share/pallasync/policy/` |
| 未署名の下書き・運用入力・生成Compose・Caddyfile | `~/.local/share/pallasync/` |
| SQLite | Compose volume `pallasync_pallasync-data` |
| HTTPS証明書等 | ComposeのCaddy用永続volumes |

XDG_CONFIG_HOME/XDG_DATA_HOMEがある場合はそちらを使います。`--key-file`、`--state-dir`、`--host-port`、`--host-bind`、`--project` で変更できます。運用状態と鍵はbuild contextの外に置きます。運用情報をshellコードとして読み込まず、平文seedをCompose環境、Docker設定、`.env`、引数、イメージ層へ保存しません。

起動時は解除した鍵をstdinからUID 10001専用のtmpfsに渡し、entrypointが読んでファイルを消去した後、サーバープロセスの環境に渡します。メモリにある秘密鍵へホスト/Docker管理者や侵害されたプロセスがアクセスできる点は変わりません。serverの512 MiBと署名helperの128 MiB cgroupでswapを無効化します。ホストがswapを使う場合、セットアップをsystemd user scopeのMemorySwapMax=0で再実行し、Docker daemonにも同じ制限があることを検査します。事前設定が必要な場合は `sudo systemctl set-property docker.service MemorySwapMax=0` を実行します。core dumpはセットアップとコンテナの両方で無効化します。

ホスト/コンテナ再起動・再作成後は同じ永続データを使い、解除までサーバーを待機させます：

```sh
bash scripts/setup-docker.sh start
bash scripts/setup-docker.sh status
bash scripts/setup-docker.sh stop
```

`stop` はデータを削除しません。カスタムのstate/key/projectを使った場合は同じoptionを指定してください。自動の無人解除・鍵交換・DB巻戻しは行いません。保護鍵を紛失した場合は既存policyのpinと異なる鍵を自動生成せず停止します。Dockerログ保存を無効にした構成なので、`status` でコンテナ状態とhealthを確認します。診断のために認証情報やrequestログを有効にする場合は、その実際の保持を別途開示する必要があります。

既にHTTPS reverse proxyがある場合：

```sh
bash scripts/setup-docker.sh setup --origin https://api.yunfi.f5.si --no-proxy
```

既存proxyを使用するのが既定です。Cloudflareを使用する場合は `--cloudflare` で第三者の通信メタデータ処理を開示します。relayは転送されたIPヘッダーを信頼せず、直近proxyのIP枠を共有することを既定文書にも開示します。

新しくHTTPS proxyが必要な別の環境では `--with-proxy` を明示するとCaddyを追加します。その場合だけDNSのA/AAAAと外部からの80/443到達性を用意してください。

文書変更は告知・旧版の公開・revision増加・再署名・再同意が必要です。セットアップの再実行で既存版を上書きする機能はありません。公開notice/archive URLの提供は運用者の既存サイトで行い、仕様にないrelay APIを追加しません（§7.13、§11.7、§17.12）。

## 検証

```sh
cargo build --locked --bin pallasync-operator
python3 tests/test_docker_setup.py
bash -n scripts/setup-docker.sh
sh -n docker/entrypoint.sh
```

テストは生成文書を実際のRust署名/検証コマンドへ渡し、改変、異なる鍵、quota不一致、未完成の運用値、既存版の上書きを拒否することを確認します。テスト鍵は公開された固定テスト入力であり、運用には使いません。

CIの `tests/docker_smoke.sh` は実際のimageと起動コマンドを使い、tmpfsでの鍵受渡し、Docker設定への平文seed不在、公開文書、旧UIDのvolume所有者調整、再起動後の永続データを検証します。このテストではage解除と公開DNS/TLSを固定fixtureで置き換えるため、本番のpassphrase入力・証明書発行・ドメイン到達性の検証はセットアップ時の実際のHTTPS照合で行います。
