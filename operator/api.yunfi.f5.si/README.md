# api.yunfi.f5.si 公開文書

運用者「ゆんふぃ」の初版（revision 1）、2026-10-11 15:04:53.217 UTCの公開文書と公開検証鍵を収録しています。公開版は `https://api.yunfi.f5.si/privacy.md` と `https://api.yunfi.f5.si/privacy.json` です。Markdownの厳密なbytesと署名付きJSONを保存します（§7.13、§17.12）。

日本の既存サーバーで、既存のage保護鍵を再利用して署名しました。3090ポートとCloudflare経路を維持し、同じ永続Docker volumeを利用します。既存のCompose編集は元checkoutに残し、デプロイ用checkoutは `/home/oronami/PallaSync-deploy` に作成しています。

公開HTTPSのhealth、両文書、Markdown hash、relay key IDの一致を確認しました。Dockerの設定には平文seedを入れず、tmpfsのseedファイルは消去済みです。起動処理とDocker daemonにMemorySwapMax=0を設定し、serverは512 MiB・swapなしで動きます。age署名helperは128 MiB・swapなしです（§17.9）。

初版のため過去版はありません。今後の予告・公開版は、このリポジトリの公開PRとそのcommitで確認する運用です。文書変更はrevision増加・再署名・再同意を必要とします。

## 運用上の残事項

Cloudflare設定は依頼者の指示に従い変更していません。2026-10-11の確認では、TLS 1.1を指定した接続でも `/pallasync/v3/health` が `200 OK` を返しました。§17.1のTLS 1.2以上の条件について、公開側の最小TLS設定を整える作業が残ります。API稼働と文書署名の確認を、公開側の全条件の適合認証とは扱いません。

再起動後は次のコマンドで同じ保護鍵を解除します。

```sh
bash /home/oronami/PallaSync-deploy/scripts/setup-docker.sh start
```
