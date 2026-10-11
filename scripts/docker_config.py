"""Command-only deployment prompts and public drafts. Never handles relay secrets."""
import argparse
import html
import ipaddress
import json
import re
import string
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MAX_INTEGER = 9007199254740991


def url(value, origin=False):
    p = urlsplit(value)
    # Accessing port checks syntax/range; urlsplit alone accepts malformed ports.
    p.port
    if (not value.isascii() or len(value) > 4096 or p.scheme != "https"
            or not p.hostname or p.username is not None or p.password is not None
            or p.fragment or "\\" in value or any(c.isspace() for c in value)):
        raise ValueError("HTTPS URL（認証情報・fragmentなし）が必要です")
    if origin:
        # This automatic certificate setup accepts normalized DNS origins on port 443.
        label = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
        if (not re.fullmatch(r"https://" + label + r"(?:\." + label + r")*", value)
                or p.path or p.query):
            raise ValueError("小文字のDNS名を使う正規化HTTPS originが必要です（末尾/なし）")
    return value


def text(value):
    value = unicodedata.normalize("NFC", value.strip())
    if not 1 <= len(value) <= 1024 or any(ord(c) < 32 for c in value):
        raise ValueError("1〜1024文字の単一行を入力してください")
    return value


def integer(value, minimum=0):
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError("整数を入力してください")
    n = int(value)
    if not minimum <= n <= MAX_INTEGER:
        raise ValueError(f"{minimum}〜{MAX_INTEGER}を入力してください")
    return n


def ask(label, validate=text, default=None):
    while True:
        value = input(f"{label}" + (f" [{default}]" if default is not None else "") + ": ").strip()
        if not value and default is not None:
            value = str(default)
        try:
            return validate(value)
        except ValueError as e:
            print(e)


def cloudflare_defaults(profile):
    """Disclose the existing processor; this never configures Cloudflare."""
    profile["proxy_metadata"] = (
        "既存CloudflareをHTTPS終端・通信転送に利用します。CloudflareはIP、User-Agent、接続/request情報、status、時刻、byte count等を処理し、"
        "セキュリティ・可用性・トラフィック分析のNetwork Dataを保持します。Cloudflare側メタデータには有限の最大保持期限を約束せず、"
        "この開示ではindefiniteとして扱います。処理地域は日本に限定されず、Cloudflareとその委託先がアクセスします。"
        "リレーのno-store応答を使用し、リレーDBの複製・backupとして使用しません。Cloudflareの設定は変更しません。"
        "提供者の取扱い: https://www.cloudflare.com/privacypolicy/ ; cache規則: https://developers.cloudflare.com/cache/concepts/default-cache-behavior/")
    profile["proxy_fields"] = ["ip", "user_agent", "connection_time", "request_path_class", "response_status", "timing", "byte_count"]
    profile["proxy_copy"] = dict(present=True, content="metadata", retention=dict(mode="indefinite"),
                                locations=["Cloudflare global network; processing may occur outside Japan"],
                                recipients=["Cloudflare, Inc. and its service providers"],
                                purpose="Network security, service availability and traffic analysis; no finite metadata retention maximum promised",
                                after_delete=dict(mode="retain_metadata", max_ms=None))
    return profile


def collect(origin, proxy, host_port, cloudflare=False):
    url(origin, origin=True)
    print("実値を入力します。空欄の運用情報や架空の値では署名しません。")
    operator = ask("公開する運用者名")
    contact = ask("アカウントなしで利用できる連絡先HTTPS URL", url)
    location = ask("保存地域・ホスティング委託先と役割（自宅運用ならその旨）")
    recipients = ask("保存データにアクセスできる主体と役割（運用者・委託先等）")
    storage_protection = ask("ホストの保存用暗号化・アクセス制御の実際の方法（暗号化なしなら明記）")
    delete_ms = ask("削除受理から稼働コピー処理までの最長期限（ms）", lambda v: integer(v, 1))
    quota = ask("全チェーン共通quota（bytes、未設定ならnone）",
                lambda v: None if v == "none" else integer(v), "none")
    notice = ask("変更告知を実際に公開するHTTPS URL", url)
    archive = ask("過去版を実際に公開するHTTPS URL", url)
    notice_ms = ask("ポリシー変更前の最低告知期間（ms）", integer)
    print("\nこの既定構成はsingle-durable、バックアップ/レプリカ/外部snapshot/サポートコピーなし。")
    print("IPハッシュ・時刻のrate metadata、公開署名証拠・削除台帳は無期限保持です。")
    print("リレーのDockerログ保存は無効。鍵処理とリレーはswapへ退避させず、core dumpなし。")
    if cloudflare:
        print("既存Cloudflareの通信メタデータ処理は別に開示し、有限の最大保持期限を宣言しません。")
    print("未記載のコピー・アクセスログがなく、連絡/告知/過去版URLを公開し、")
    print("入力した保存場所・アクセス主体・削除期限が実際の運用に一致する場合だけ続行してください。")
    if input("確認して続行するには yes と入力: ").strip() != "yes":
        raise ValueError("運用条件の確認が完了していないため中断しました")
    p = dict(origin=origin, operator=operator, contact=contact, location=location,
                recipients=recipients, storage_protection=storage_protection, delete_ms=delete_ms, quota=quota,
                notice=notice, archive=archive, notice_ms=notice_ms,
                proxy=proxy, host_port=host_port)
    return cloudflare_defaults(p) if cloudflare else p


def render(profile):
    q = profile["quota"]
    quota_rule = ("All chains have no configured quota. " if q is None else f"Every chain has a fixed quota of {q} bytes. ") + (
        "Count stored signed objects, IDs/hashes, log wrappers, receipts, transparency/head evidence, outcomes, cursors and offers; exclude SQLite/WAL physical overhead.")
    slots = {"__" + k.upper() + "__": v for k, v in profile.items()}
    slots.update(__QUOTA_MIN__=0 if q is None else q, __QUOTA_MAX__=q,
                 __QUOTA_UNCONFIGURED__=q is None, __QUOTA_RULE__=quota_rule)

    def replace(v):
        if isinstance(v, str):
            return slots.get(v, v)
        if isinstance(v, dict):
            return {k: replace(x) for k, x in v.items()}
        if isinstance(v, list):
            return [replace(x) for x in v]
        return v

    disclosure = replace(json.loads((ROOT / "deploy/privacy.json.in").read_text(encoding="utf-8")))
    if profile.get("proxy_copy"):
        disclosure["copies"]["operational_log"] = profile["proxy_copy"]
        disclosure["metadata"]["retained_fields"] = profile["proxy_fields"]
        disclosure["metadata"]["purposes"].append(profile["proxy_copy"]["purpose"])
        disclosure["metadata"]["recipients"].extend(profile["proxy_copy"]["recipients"])
    # Escape public prose values once, without recursively interpreting $ in operator input.
    prose = {k: html.escape(str(v)).replace("|", "\\|") for k, v in profile.items()}
    prose.update(quota_text="max_bytes = null（設定quotaなし）" if q is None else f"max_bytes = {q} bytes（固定値）",
                 quota_rule=quota_rule,
                 contact_details=html.escape(profile.get("contact_details", "上記HTTPS URLの連絡方法を利用してください。")),
                 proxy_metadata=html.escape(profile.get("proxy_metadata", "proxyの永続アクセスログは作成しません。")),
                 operational_log_text="有。Cloudflareの通信メタデータ。有限の最大期限を約束せずindefinite・retain_metadataで開示" if profile.get("proxy_copy") else "永続ログは作成しない",
                 archive_details=html.escape(profile.get("archive_details", "過去版は上記archive URLで確認できます。")))
    md = string.Template((ROOT / "deploy/privacy.md.in").read_text(encoding="utf-8")).substitute(prose)
    return md, disclosure


def compose(profile, state):
    # A standalone Compose file avoids plaintext-key interpolation and inherited .env files.
    service = {
        "image": "pallasync-server:local", "restart": "unless-stopped", "init": True,
        "environment": {"PALLASYNC_BIND_ADDR": "0.0.0.0:3000", "DATABASE_URL": "sqlite:///data/pallasync.sqlite",
                        "PALLASYNC_PRIVACY_MARKDOWN": "/policy/privacy.md", "PALLASYNC_PRIVACY_JSON": "/policy/privacy.json",
                        "PALLASYNC_RELAY_SIGNING_SEED_FILE": "/run/pallasync/relay-seed"},
        "ports": [f"{profile['host_bind']}:{profile['host_port']}:3000"],
        "volumes": ["pallasync-data:/data", {"type": "bind", "source": str(state / "policy"), "target": "/policy", "read_only": True}],
        "read_only": True, "tmpfs": ["/tmp:size=16m,mode=1777", "/run/pallasync:size=1m,mode=0700,uid=10001,gid=10001"],
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
        "ulimits": {"core": {"soft": 0, "hard": 0}}, "logging": {"driver": "none"}}
    # No plaintext relay-key pages may be swapped from the service cgroup.
    service.update(mem_limit="512m", memswap_limit="512m")
    if profile["quota"] is not None:
        service["environment"]["PALLASYNC_QUOTA_BYTES"] = str(profile["quota"])
    result = {"services": {"pallasync": service}, "volumes": {"pallasync-data": {}}}
    if profile["proxy"]:
        result["services"]["caddy"] = {
            "image": "caddy:2", "restart": "unless-stopped", "ports": ["80:80", "443:443"],
            "volumes": [{"type": "bind", "source": str(state / "Caddyfile"), "target": "/etc/caddy/Caddyfile", "read_only": True},
                        "caddy-data:/data", "caddy-config:/config"],
            "logging": {"driver": "none"}, "ulimits": {"core": {"soft": 0, "hard": 0}}}
        result["volumes"].update({"caddy-data": {}, "caddy-config": {}})
    return result


def prepare(profile, state):
    if state.is_relative_to(ROOT):
        raise ValueError("状態ディレクトリはリポジトリ/build contextの外に置いてください")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    draft = state / "draft"
    draft.mkdir(mode=0o700, exist_ok=True)
    md, disclosure = render(profile)
    (draft / "privacy.md").write_text(md, encoding="utf-8", newline="\n")
    (draft / "privacy.json").write_text(json.dumps(disclosure, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    (state / "compose.generated.json").write_text(json.dumps(compose(profile, state), ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    # No access log directive; discard runtime error logs that could carry request metadata.
    (state / "Caddyfile").write_text("{\n\tadmin off\n\tlog {\n\t\toutput discard\n\t}\n}\n" +
                                  profile["origin"] + " {\n\treverse_proxy pallasync:3000\n}\n", encoding="utf-8", newline="\n")
    (state / "deployment.json").write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    print(f"公開文書の下書き: {draft}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--host-port", type=int, default=3090)
    parser.add_argument("--host-bind", default="0.0.0.0")
    parser.add_argument("--project", default="pallasync")
    parser.add_argument("--no-proxy", action="store_true")
    parser.add_argument("--with-proxy", action="store_true")
    parser.add_argument("--cloudflare", action="store_true")
    args = parser.parse_args()
    state = args.state_dir.expanduser().resolve()
    if (state / "deployment.json").exists():
        p = json.loads((state / "deployment.json").read_text(encoding="utf-8"))
        if p["origin"] != args.origin:
            raise ValueError("既存deploymentのoriginを変更できません")
        if p["project"] != args.project:
            raise ValueError("既存deploymentのCompose projectを変更できません")
        print("既存の運用設定と署名済み文書を再利用します")
        return
    if not 1 <= args.host_port <= 65535:
        raise ValueError("host portは1〜65535です")
    ipaddress.IPv4Address(args.host_bind)
    if args.with_proxy and args.cloudflare:
        raise ValueError("既存Cloudflareと追加proxyを同時に選択しないでください")
    profile = collect(args.origin, args.with_proxy and not args.no_proxy, args.host_port, args.cloudflare)
    profile["project"] = args.project
    profile["host_bind"] = args.host_bind
    prepare(profile, state)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, EOFError, KeyboardInterrupt) as e:
        raise SystemExit(str(e)) from None
