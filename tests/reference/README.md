# Independent PALLASYNC-3.0-R1 test client

These test modules import no Palleria Rust/JNI code or server crypto implementation. They use PyNaCl,
cryptography, RFC 8785, the English BIP39 word list and `galois.GF(256, irreducible_poly=0x11b)`.
All dependencies are pinned in `requirements.lock`. HPKE's base-suite schedule is a test reference
calculation, not production relay cryptography. Python's immutable secret objects do not implement
the protected holder or root-session memory requirements of a production client.

Run from the server repository with Python 3.10:

```sh
python -m venv target/reference-venv
target/reference-venv/bin/python -m pip install -r tests/reference/requirements.lock
target/reference-venv/bin/python -m unittest discover -s tests/reference -p 'test_*.py' -v
cargo build --locked --bin pallasync-server
target/reference-venv/bin/python tests/reference/run_relay_interop.py --relay-binary target/debug/pallasync-server
```

On Windows, use `target/reference-venv/Scripts/python.exe` and `target/debug/pallasync-server.exe`.
The boundary runner always creates its own temporary SQLite database, test relay key, signed
operator documents and a TLS 1.2-or-newer loopback endpoint. It reuses that database when testing
restart, then removes the disposable environment. It cannot take a production URL or volume.
Each chain request revalidates the signed policy pair against an explicitly accepted test binding.

The vectors currently cover §§3–5, §15.5 and Appendices C.2/C.3/C.7/C.8/C.9/C.10. C.10 checks
the complete state-array MAC and partition independence; it does not establish snapshot semantic
coverage, staging installation or pruning authority. The HTTPS runner verifies
genesis, encrypted record delivery, exact retry receipts, complete H/T suffixes, durable nonce replay
denial after restart and the approved §7.7 device-envelope access restriction. It does **not** claim
IT-01–IT-50 completion, full application materialization, Android protected-storage validation,
recovery UI, snapshot semantics, migration or production conformance.

`--public-evidence-output PATH` optionally writes only the public signed genesis/response/record,
root public identity, log/transparency heads and pages, and test origin/key. These artifacts allow Palleria to independently verify
and decrypt a Python-produced fixture using the public C.2 mnemonic. No private seeds, RMS or raw
shares are written by this option. C.9/C.11 examples in `fixtures` are exact public specification
examples; their mocked prior bounds never establish a production checkpoint.

The isolated runner also verifies exact mnemonic enrollment retries, pending-device restrictions,
HPKE envelope receipt/commitment and acknowledgement using independent Python crypto.
`run_android_interop.py` runs one real coordinator/JNI/Room/Keystore enrollment/outbox case on
only the disposable `PallaSyncV3Conformance` AVD. It discovers the running emulator serial via
`adb devices` and `adb emu avd name`, and requires exactly one matching AVD; it does not assume a
fixed emulator serial. It then independently verifies
and decrypts its records. It requires freshly built APKs and explicit disposable TLS arguments.
An absent Android harness argument skips the instrumentation case; it does not mark an IT passed.
This targeted case is not completion of the 50 three-party IT cases or the Android stress tests.

`run_relay_interop.py --epoch-checks --relay-binary target/debug/pallasync-server` additionally
checks a device-signed complete rotation, independent HPKE/commitment readback for both members,
incomplete-bundle rejection, exact retry, competing CAS, persistent restart, current-epoch records,
and admin-authorized atomic revocation. A wrong admin target leaves the old head unchanged.
It verifies the complete final H/T chain and every original acceptance receipt, including the
unchanged device-token restriction on recovery-envelope log entries. This mode paces its disposable
transport within the same disclosed limits. It writes only public signed objects if an evidence
output is requested. The actual submitted admin payload retains its array order even when the
relay orders log entries differently; Palleria tests independently verify that binding through JNI.
These are targeted boundaries, not completion of IT-14, IT-50 or the full Android rotation UI.

`run_android_interop.py --rotate-epoch` also leaves two old-epoch local edits queued and one
already accepted record held for reconciliation. Android verifies the complete cut, preserves
accepted source evidence, and constructs fresh records only for unaccepted edits. Independent
Python decrypts both public source ciphertext and accepted replacements, checking new IDs/nonces,
author sequence, Lamports, exact operation body/context and predecessor links. `--rebase-fault`
accepts SOURCE_STAGED, DESTINATION_COMMITTED or SOURCE_RETIRED to interrupt the corresponding
durable rebase boundary. With `--reseed`, it also accepts RESEED_ROOM_COMMITTED,
RESEED_KEYSTORE_PROMOTED, RESEED_OUTBOX_REBASED, RESEED_ORIGIN_SELECTED or
RESEED_COMPLETE_COMMITTED to interrupt each journaled cross-store cutover boundary and retry the
same staged commit. Native sessions end and the OS journal is reopened before resumption. These
standard boundary retries use the same instrumentation process and do not complete the entire IT
catalogue; `--rebase-process-death` separately verifies fresh-process recovery for the five reseed
cutover boundaries. A successful `--reseed` case also explicitly replays the retired source after cutover and requires
the Android coordinator to report a verified empty suffix.

The `--reseed --rebase-fault` cutover path has passed against the disposable AVD for all five
durable boundaries (`RESEED_ROOM_COMMITTED`, `RESEED_KEYSTORE_PROMOTED`,
`RESEED_OUTBOX_REBASED`, `RESEED_ORIGIN_SELECTED`, and `RESEED_COMPLETE_COMMITTED`), plus a
no-fault cutover. Adding `--rebase-process-death` kills instrumentation after the selected
boundary, then starts a fresh process against the test-only file-backed Room database and
persistent Android Keystore state. All five process-death resumes passed. These targeted runs do
not prove late-writer/split-view reconciliation or the full relay-migration catalogue.

`--rebase-fault RESEED_SOURCE_CAPTURED --rebase-process-death --reseed-late-source-write` injects
one valid Python device record into the old generation after Android durably captures its final
source report and the app process exits. Android must resume cutover from the saved report, then
report exactly one unimported edit; Python verifies that the record remains on the source and is
absent from the target. This precise race case passed. Other concurrent-write timings and signed
split-view/fork response cases remain unverified.

`run_legacy_interop.py --relay-binary PATH` injects a frozen legacy fixture only into its own
disposable SQLite file. Independent Python derives the v2.1 keys and verifies original device
and record signatures, AEAD, paging and nonce denial after restart. It checks that the absent
original parameter signature is reported instead of fabricated and that explicit legacy deletion
leaves v3 heads unchanged. It does not invent a ChainParameters signature context or certify the
Android conversion/journal/legacy provenance rules.

`run_peer_interop.py --relay-binary PATH` exercises §10.7/§18.1 with an independent prospective
client that holds no mnemonic/admin key. It checks the bound offer/request, both independently
computed SAS values, the subject's signed DeviceRecord, HPKE/commitment, pending-token denial,
own-envelope delivery/ack, relay restart and identical original approval receipts, then an accepted
encrypted application record and its full data-log prefix. This is a Python/isolated-relay case;
it does not certify Android peer UI, protected storage or the complete three-party IT catalogue.

`generate_peer_jni_fixture.py --relay-binary PATH --output PATH` emits only public signed genesis
objects/ciphertext and original real-relay receipts. Its fixed keys are public test inputs in code,
never user credentials. Android host JNI uses this independently generated source to verify
positive typed key allocation and erasure. The golden `fixtures/peer-sas.json` tests the same
12-character SAS independently; its placeholder heads are not accepted source history.

`run_android_interop.py --peer-enrollment --rotate-epoch` uses the Android approver service with
an independent Python prospective subject. Exact public signed objects/ciphertext travel through
test-owned private local files, never a new relay mailbox. Test inputs explicitly compare and
confirm the two SAS values. It verifies protected approval journal readback, original signed
receipts, pending-token denial, own-envelope retrieval and ack, then a three-device epoch and
the original full H/T. The Android portion passed in 221.313 seconds. This is a service/crypto
integration case; human peer UI and Android subject protected storage/ack remain separate work.

`test_recovery.py` independently checks Appendix C.8's signed manifest/share, fixed RSWK
AEAD/commitment, blob ciphertext hash/tag/object hash and derived identity, plus §7.11.4's
fixed Argon2id parameters, credential NFKD and failed unlocks. The reference unit suite has
22 passing tests, including canonical PSR3 encoding, numbered fragment conflict/hash checks,
and independent live SAS/HPKE, directional controls, gaps, exact retries and denied confirmation.
`generate_recovery_c8_fixture.py` uses only the document's public fixed
test inputs to produce a protected-package fixture and conflicting signed status for JNI
holder-state tests. `recovery_crypto.py` is client test infrastructure, never a relay runtime
module or production holder. `recovery_artifacts.py` independently checks exact public schemas,
integer/holder bindings, signed status ancestry and known-head rollback, before crypto/bindings.
This does not certify OS buffer erasure, globally fresh status or physical holder independence.

`recovery_pair.py` implements independent local descriptor/SAS/HPKE primitives and callback
processing for future Android interoperability. It caches encrypted transfers and public replies,
never decrypted payloads. It validates payload schemas and literal §19 result codes, aborts invalid
sessions and preserves only an authenticated sequence gap for retry. Callers validate known set status and holder/root
authorization; unit crypto success does not certify the full recovery state machine or UI.

`run_android_interop.py --delete-chain --delete-response-lost` commits an admin DELETE on the isolated relay and closes only that request's HTTP response. Android must retain its chain while proof is unavailable, then reuse its exact saved signed request after retry backoff, verify GET `/deletion`, and erase only after proof/bundle readback and explicit confirmation. The disposable AVD run passed in 133.415 seconds; physical SAF and the broader deletion fault catalogue remain outside this case.

`run_android_interop.py --reseed --reseed-split-view` arms a one-shot source-relay response after the target device key acknowledgement. The proxy changes `head_hash` in the signed transparency head and re-signs the complete object with the isolated relay's published test key; it does not alter production code or use a forged/invalid signature. Android must reject local origin cutover, quarantine the exact signed contradictory head, pause source writes and retain the source authority/keys. The 2026-10-19 dedicated `PallaSyncV3Conformance` AVD run passed in 148.238 seconds with error `C_LOG_HASH_MISMATCH` and `write_state=integrity_paused`; the runner independently confirmed the target relay had reached generation 1 while the client remained on source generation 0. This covers the same-sequence signed data-head contradiction at the post-target-commit/pre-local-cutover boundary only; other split-view timings and physical relay-migration scenarios remain unverified. Protocol basis: §§11.5, 17.3, 17.5–17.6, 17.9–17.10.

`run_android_interop.py --reseed --reseed-pre-capture-write` injects an independently device-signed, accepted generation-0 record at the target device-key acknowledgement boundary, before Android's final source replay. The dedicated AVD run passed in 165.47 seconds: Android completed generation+1 cutover and reported one unimported edit; the independent runner verified that record on the source relay and absent from the target. This complements `--reseed-late-source-write`, which injects after the durable final source report and resumes in a fresh app process. Neither case covers writers during earlier snapshot staging or every concurrent schedule. Protocol basis: §§11.5, 17.5–17.6.

`run_android_interop.py --reseed --reseed-staging-write` injects an independent source write immediately after the target accepts a snapshot part. The Android client must detect the changed source head before sending the generation commit, retain a source-conflict report, and after explicit source synchronization rebuild the snapshot under a fresh compaction ID. The journal reset is limited to a proven uncommitted snapshot; no commit result or transparency proof may exist, and accepted old parts remain retained. The 2026-10-19 dedicated AVD run passed (AndroidJUnitRunner `OK (1 test)`, 199.103 seconds). Independent Python derived the target epoch secret from the signed recovery envelope, verified the signed compaction and part hashes/signatures, decrypted the snapshot, and found the racing source entity; it also confirmed the original signed source record was not copied verbatim into the target event log. This covers one injected snapshot-staging interleaving, not arbitrary simultaneous writers or the complete A-27 catalogue. Protocol basis: §§7.8, 10.11–10.12, 16.6, 17.5–17.6, 17.9.

`run_android_interop.py --records-413-split` injects one valid protocol `PAYLOAD_TOO_LARGE` response at a test-only HTTPS proxy endpoint, then observes the coordinator's retries. It requires the exact four original record IDs to be accepted in smaller batches and the independent Python receiver to decrypt all four operations. The proxy fault endpoint exists only in this disposable test harness; it is not part of the relay API. This case does not exercise process restart during reduced-batch retry or a request rejected by the actual Rust server limit.
