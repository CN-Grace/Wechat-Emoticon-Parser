# WeChat Decryptor

> A local data decryption tool for WeChat 4.1.x (Windows) — emoticon pack export & chat image decryption

Decrypts WeChat's locally-encrypted data via memory scanning and key derivation:
emoticon packs (including store-pack caption naming) and V2-format chat images.

---

## Features

- **Emoticon export**: store packs by package name, files named by caption only (`拜拜啦.gif`);
  favorites named by collection order (`favorite_001.gif`); everything in a single flat dir via `--notype`
- **One-shot pipeline**: locate data dir → scan seed in memory → derive key → self-contained DB
  decryption → decrypt files → stream-parse containers → name by DB metadata → CDN favorites
- **Fully self-contained DB decryption**: WCDB key scanned from process memory (no external tool)
- **wxgf animation support**: HEVC stream extraction + first-frame conversion (GIF/PNG/JPEG direct)
- **Chat image decryption**: V2-format `.dat` full restoration (`--images`)
- **Structured manifest**: `{packs, favorites, unknown, summary}` mirrored to the directory tree, sorted
- **Lightweight**: only requires `pycryptodome` (optional `imageio-ffmpeg` for transcoding)

---

## Algorithms

### 1. Emoticon file encryption

Emoticon files are encrypted under `business/emoticon/` in `Persist` / `PersistStore` / `Thumb` / `ThumbStore`
directories (files named by content md5).

```
Cipher: AES-128-CBC + PKCS7, key = IV
key    = md5(f"{seed}{wxid}EMOTICON") hex-decoded, first 16 bytes
```

| Parameter | Source |
|---|---|
| `seed` | Account-level constant present in the WeChat process memory (decimal, extracted by memory scan) |
| `wxid` | Data directory name minus the `_b487` suffix |

Notes:

- All emoticon files share a **single key** (different batches show different first-block C0 only because the
  plaintext header — wxgf length fields — differs)
- `PersistStore` container files = multiple emoticons of a pack concatenated by magic
  (`GIF8` / `89PNG` / `FFD8FF`); split by **streaming structural parse** (PNG→IEND, GIF→trailer 0x3B,
  JPEG→EOI) which ignores stray magic bytes inside compressed data — no corrupted slices
- `wxgf` files = raw H.265 stream after the magic (cut from `00 00 00 01 40 01` VPS), first frame extracted via ffmpeg
- The key exists as raw 16 bytes in the main process heap, inside the account session key table (next to the wxid string)

### 2. Chat image encryption (V2 .dat)

Chat images reside in `msg/`:

```
[15B header: 6B signature 07 08 56 32 08 07 | aes_size(4) | xor_size(4) | pad(1)]
[AES-128-ECB region][raw plaintext region][single-byte XOR tail]

key    = md5(f"{seed}{wxid}")[:16]   (16-char alphanumeric ASCII)
XOR key = seed & 0xFF (verified by reversing from JPEG tail FF D9)
```

### 3. Databases (WCDB)

WeChat 4.1+ no longer keeps the plaintext key in process memory (only the passphrase remains).
The script **fully embeds** the runtime decryption: scan `com.Tencent.WCDB.Config.Cipher` objects in the
WeChat process memory → XOR deobfuscation → candidate key extraction → HMAC-SHA512 verification
(SQLCipher4 spec) → AES-256-CBC page-by-page decryption. `emoticon.db` holds all emoticon metadata
(packs, captions, ordering, CDN mappings). No external tool required.

### 4. Generic key discovery flow (memory scan → derive → verify)

```
1. Candidates   ReadProcessMemory over the Weixin.exe main process → regex-extract digit strings (seed candidates)
2. Derive       md5(f"{seed}{wxid}EMOTICON"), take first 16 bytes
3. Verify       AES-CBC(key=IV) decrypt any emoticon file's first block (C0) → magic hit confirms
                (89504e47 / GIF8 / FFD8FF / wxgf)
```

This flow depends on no third-party tool; only a running WeChat is required.

---

## Project structure

```
wechat/
├── wechat_emoticon_export.py   unified tool: emoticon export + V2 chat image decryption + key scan
├── README.md
└── README_CN.md
```

## Output layout

```
emoticon_export/                  # default output
├── store/<包名>/<标题>.gif        # store stickers, named by caption (index/md5 kept in manifest)
├── favorite/001.gif              # favorites, named by collection order (kFavEmoticonOrderTable)
├── unknown/<md5>.jpg             # unmapped leftovers (intact files only)
└── manifest.json                 # structured: {packs, favorites, unknown, summary}

emoticon_export_all/              # with --notype: every file flattened, named 组名_表情名 / favorite_序号
decoded_images/                   # V2 chat images (menu [2] / --images)
decrypted_db/                     # ALL plaintext databases (menu [4]) — contact/message/sns/...
wechat_keys.txt                   # extracted keys (menu [6])
```

## Installation

```bash
pip install pycryptodome          # required
pip install imageio-ffmpeg        # optional: wxgf/hevc animation transcoding
```

## Usage

```bash
# Interactive menu (no arguments):
#   [1] emoticon export   [2] V2 chat images   [3] flatten-only export
#   [4] decrypt ALL databases (db_storage -> decrypted_db/)
#   [5] extract & show keys
#   [0] exit
python wechat_emoticon_export.py

# Argument mode (offline / custom paths)
python wechat_emoticon_export.py --key <hex key>                      # emoticon export
python wechat_emoticon_export.py --images --seed <seed>               # V2 images
python wechat_emoticon_export.py --data-dir <xwechat_files/wxid_xxx_b487> \
                                 --db <decrypted emoticon.db> --out <output dir> --notype

# Options
--no-cdn          skip CDN favorite download
--no-wxgf         skip wxgf/hevc transcoding
--notype          flatten-only output into emoticon_export_all/ (组名_表情名 / favorite_序号)
--keep-decrypted  keep intermediate decrypted files & temp db
```

---

## Acknowledgements

The key-extraction approach and memory-scanning methodology are inspired by the following open-source projects:

- [TANGandXue/wcdb-key-tool](https://github.com/TANGandXue/wcdb-key-tool) — WCDB database runtime scan & decryption
- [LifeArchiveProject/WeChatDataAnalysis](https://github.com/LifeArchiveProject/WeChatDataAnalysis) — key derivation formula & candidate verification
- [WeChatMsgDump](https://github.com/junuo-S/WeChatMsgDump) — process memory reading architecture
- [93857536-pixel/WeChatExporter](https://github.com/93857536-pixel/WeChatExporter) — emoticon CDN download & wxgf parsing
- [CipherTalk](https://github.com/CipherTalk/wechat-key-tool) — account seed extraction

## License

MIT
