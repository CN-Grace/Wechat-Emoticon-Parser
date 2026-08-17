#!/usr/bin/env python3
"""wechat_emoticon_export.py — 微信表情包全通路一键导出

全链路:
  1. 定位微信data dir + 自动提取 wxid
  2. 内存扫描 seed (Weixin.exe 主进程) -> 派生 emoticon key
     key = md5(f"{seed}{wxid}EMOTICON") hex 解码前 16B, AES-128-CBC key=IV
  3. Decrypting emoticon 全部文件 (Persist/PersistStore/Thumb/ThumbStore)
  4. PersistStore 容器按魔数分割
  5. 对照 emoticon.db (kStoreEmoticonFilesTable/CaptionsTable/PackageTable)
     按包分组 + 序号_标题_md5 命名
  6. wxgf 动图转 JPEG (需 imageio-ffmpeg)
  7. 输出 manifest (完整元数据)

用法:
  python wechat_emoticon_export.py [--data-dir PATH] [--db PATH] [--key HEX]
                                   [--out PATH] [--no-wxgf] [--no-db]

依赖: pycryptodome (必需), imageio-ffmpeg (wxgf 转码, 可选)
"""
import argparse
import ctypes
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes as wt

# ============ 界面语言 (按 c 切换中/英) ============
LANG = {"cur": "en"}


def T(zh, en):
    return zh if LANG["cur"] == "zh" else en


# ==================== 常量 ====================
MAGICS = (b'\x89PNG', b'GIF8', b'\xff\xd8\xff', b'wxgf', b'RIFF')
MEM_COMMIT = 0x1000
READABLE = {2, 4, 8, 16, 32, 64, 128}
MAX_REGION = 200 * 1024 * 1024
CHUNK = 4 * 1024 * 1024
RE_SEED = re.compile(rb'(?<![0-9])(\d{8,12})(?![0-9])')
DEFAULT_BASES = [
    r"E:\Program\Tencent Files\xwechat_files",
    r"D:\Program Files\Tencent\xwechat_files",
    r"C:\Program Files\Tencent\xwechat_files",
    r"%USERPROFILE%\Documents\xwechat_files",
]

# ==================== Windows 内存读取 ====================
class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wt.DWORD), ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
        ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_pad2", wt.DWORD),
    ]


kernel32 = ctypes.windll.kernel32


def read_mem(h, addr, sz):
    buf = ctypes.create_string_buffer(sz)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, sz, ctypes.byref(n)):
        return buf.raw[: n.value]
    return None


def enum_regions(h):
    regs = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < MAX_REGION:
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def get_pids():
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return [int(l.strip('"').split('","')[1]) for l in r.stdout.strip().split('\n') if l.strip() and '","' in l]


def scan_seeds_from_memory(pid=None):
    """扫描 Weixin.exe 主进程内存, 提取 seed 候选 (数字串)"""
    pids = [pid] if pid else get_pids()[:1]
    seeds = set()
    for pid in pids:
        h = kernel32.OpenProcess(0x0410, False, pid)  # QUERY_INFO | VM_READ
        if not h:
            print(f"[!] cannot open PID {pid}")
            continue
        for base, size in enum_regions(h):
            off = 0
            tail = b""
            while off < size:
                cur = min(CHUNK, size - off)
                chunk = read_mem(h, base + off, cur)
                if chunk:
                    data = tail + chunk
                    for m in RE_SEED.finditer(data):
                        v = int(m.group(0))
                        if 100_000_000 < v < 4_000_000_000:
                            seeds.add(v)
                    tail = data[-64:]
                else:
                    tail = b""
                off += cur
        kernel32.CloseHandle(h)
        print(f"[*] PID {pid}: seed candidates {len(seeds)}")
    return seeds


# ==================== key 派生与验证 ====================
def derive_key(seed, wxid):
    d = hashlib.md5(f"{seed}{wxid}EMOTICON".encode()).hexdigest()
    return bytes.fromhex(d)[:16]


def verify_key(key, c0):
    try:
        from Crypto.Cipher import AES
        dec = AES.new(key, AES.MODE_CBC, key).decrypt(c0)
        return dec[:4] in MAGICS
    except Exception:
        return False


def find_key_from_memory(c0, wxid):
    """内存扫描 seed -> 派生 -> C0 验证, 返回 (seed, key) 或 None"""
    seeds = scan_seeds_from_memory()
    print(f"[*] Verifying {len(seeds)} candidates (wxid={wxid})...")
    for seed in sorted(seeds):
        key = derive_key(seed, wxid)
        if verify_key(key, c0):
            return seed, key
    return None


# ==================== data dir定位 ====================
def find_data_dir():
    for base in DEFAULT_BASES:
        b = os.path.expandvars(base)
        if not os.path.isdir(b):
            continue
        for d in sorted(os.listdir(b)):
            if d.startswith("wxid_"):
                return os.path.join(b, d)
    return None


def auto_wxid(data_dir):
    name = os.path.basename(data_dir)
    return name[:-5] if name.endswith("_b487") else name


def find_emoticon_dir(data_dir):
    for sub in ["business/emoticon", "emoticon"]:
        p = os.path.join(data_dir, sub)
        if os.path.isdir(p):
            return p
    return None


def find_db():
    """自动搜索已解密的 emoticon.db (旧快照 fallback)"""
    pats = [
        r"C:\Users\%USERNAME%\AppData\Local\Temp\wcdb-key-tool\decrypted\emoticon\emoticon.db",
        os.path.expandvars(r"%LOCALAPPDATA%\Temp\wcdb-key-tool\decrypted\emoticon\emoticon.db"),
        "emoticon.db",
    ]
    for p in pats:
        p = os.path.expandvars(p)
        if os.path.isfile(p):
            return p
    return None


# ==================== WCDB 数据库自包含Decrypting ====================
# 移植自 TANGandXue/wcdb-key-tool (Windows 4.1+ 主路径):
#   内存扫 com.Tencent.WCDB.Config.Cipher 对象 -> XOR 反混淆 -> 候选 enc_key
#   -> HMAC-SHA512 校验 -> AES-256-CBC 逐页Decrypting (SQLCipher4 规范)
WCDB_PAGE = 4096
WCDB_SALT_SZ = 16
WCDB_HMAC_SZ = 64
WCDB_RESERVE = 80
WCDB_CIPHER_NAME = b"com.Tencent.WCDB.Config.Cipher"
WCDB_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b450048844c2448488944254048584c24")
WCDB_LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")
WCDB_BLOB_MAX = 1024
WCDB_MAX_ADDR = 0x0000_8000_0000_0000


def wcdb_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0] if off + 8 <= len(data) else 0


def wcdb_xor_repeat(data, mask):
    return bytes(v ^ mask[i % len(mask)] for i, v in enumerate(data))


def wcdb_verify_key(enc_key, page1):
    """HMAC-SHA512 校验 enc_key 是否匹配 db 页1 (SQLCipher4 规范)"""
    from Crypto.Cipher import AES  # noqa: F401 (确认依赖)
    salt = page1[:WCDB_SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=32)
    hmac_data = page1[WCDB_SALT_SZ: WCDB_PAGE - WCDB_RESERVE + 16]
    stored = page1[WCDB_PAGE - WCDB_HMAC_SZ: WCDB_PAGE]
    hm = hmac.new(mac_key, hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hmac.compare_digest(hm.digest(), stored)


def wcdb_decrypt_page(enc_key, page, pgno):
    from Crypto.Cipher import AES
    iv = page[WCDB_PAGE - WCDB_RESERVE: WCDB_PAGE - WCDB_RESERVE + 16]
    if pgno == 1:
        dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(page[WCDB_SALT_SZ: WCDB_PAGE - WCDB_RESERVE])
        return b"SQLite format 3\x00" + dec + b"\x00" * WCDB_RESERVE
    dec = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(page[: WCDB_PAGE - WCDB_RESERVE])
    return dec + b"\x00" * WCDB_RESERVE


def wcdb_scan_candidate_keys(pid):
    """只读扫描一次进程内存, 收集所有 Config.Cipher 中的 enc_key 候选 (去重)"""
    h = kernel32.OpenProcess(0x0410, False, pid)
    if not h:
        return []
    try:
        regions = enum_regions(h)
        needle_addrs = set()
        for base, size in regions:
            off = 0
            tail = b""
            tail_base = base
            while off < size:
                cur = min(CHUNK, size - off)
                chunk = read_mem(h, base + off, cur)
                if chunk:
                    data = tail + chunk
                    dbase = tail_base if tail else base + off
                    pos = data.find(WCDB_CIPHER_NAME)
                    while pos >= 0:
                        needle_addrs.add(dbase + pos)
                        pos = data.find(WCDB_CIPHER_NAME, pos + 1)
                    tail = data[-32:]
                    tail_base = dbase + max(0, len(data) - len(tail))
                else:
                    tail = b""
                    tail_base = base + off + cur
                off += cur
        if not needle_addrs:
            return []
        cands = []
        seen = set()
        patterns = [struct.pack("<Q", a) + struct.pack("<Q", len(WCDB_CIPHER_NAME)) for a in needle_addrs]
        for base, size in regions:
            off = 0
            tail = b""
            tail_base = base
            while off < size:
                cur = min(CHUNK, size - off)
                chunk = read_mem(h, base + off, cur)
                if chunk:
                    data = tail + chunk
                    dbase = tail_base if tail else base + off
                    for pat in patterns:
                        pos = data.find(pat)
                        while pos >= 0:
                            qaddr = dbase + pos
                            node = read_mem(h, qaddr - 0x10, 0x50)
                            if node and len(node) >= 0x40:
                                if (wcdb_u64(node, 0x10) in needle_addrs
                                        and wcdb_u64(node, 0x18) == len(WCDB_CIPHER_NAME)):
                                    cfg = wcdb_u64(node, 0x28)
                                    if 0x10000 <= cfg < WCDB_MAX_ADDR:
                                        obj = read_mem(h, cfg + 0x88, 0x28)
                                        if obj and len(obj) >= 0x18:
                                            dp = wcdb_u64(obj, 0x8)
                                            dl = wcdb_u64(obj, 0x10)
                                            if 0 < dl <= WCDB_BLOB_MAX and 0x10000 <= dp < WCDB_MAX_ADDR:
                                                blob = read_mem(h, dp, int(dl))
                                                if blob and len(blob) == dl:
                                                    decoded = wcdb_xor_repeat(blob, WCDB_XOR_MASK)
                                                    for m in WCDB_LITERAL_RE.finditer(decoded):
                                                        run = m.group(1).decode("ascii").lower()
                                                        starts = [0]
                                                        if len(run) > 96:
                                                            starts.extend(range(0, len(run) - 63, 32))
                                                        for st in dict.fromkeys(starts):
                                                            if st + 64 > len(run):
                                                                continue
                                                            try:
                                                                ek = bytes.fromhex(run[st:st + 64])
                                                            except ValueError:
                                                                continue
                                                            if len(set(ek)) < 15:
                                                                continue
                                                            if ek not in seen:
                                                                seen.add(ek)
                                                                cands.append(ek)
                            pos = data.find(pat, pos + 1)
                    tail = data[-0x80:]
                    tail_base = dbase + max(0, len(data) - len(tail))
                else:
                    tail = b""
                    tail_base = base + off + cur
                off += cur
        return cands
    finally:
        kernel32.CloseHandle(h)


def wcdb_scan_key(pid, page1):
    """兼容单库场景: 扫候选后验证匹配 db 的 enc_key 或 None"""
    for ek in wcdb_scan_candidate_keys(pid):
        if wcdb_verify_key(ek, page1):
            return ek
    return None


def decrypt_emoticon_db(data_dir, out_path):
    """Self-contained emoticon.db decryption (扫内存 key -> 逐页解密), 返回明文路径或 None"""
    db_path = os.path.join(data_dir, "db_storage", "emoticon", "emoticon.db")
    if not os.path.isfile(db_path):
        return None
    # 微信是否运行
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if not r.stdout.strip():
        print("[!] WeChat not running, cannot decrypt DB; using old snapshot")
        return None
    # 主进程 (内存最大)
    pids = []
    for line in r.stdout.strip().split("\n"):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            try:
                pids.append((int(p[1]), int(p[4].replace(",", "").replace(" K", "") or 0)))
            except ValueError:
                pass
    if not pids:
        return None
    pids.sort(key=lambda x: -x[1])
    pid = pids[0][0]

    sz = os.path.getsize(db_path)
    if sz < WCDB_PAGE:
        return None
    with open(db_path, "rb") as f:
        page1 = f.read(WCDB_PAGE)
    print(f"[*] Self-contained emoticon.db decryption ({sz // 1024}KB, pid={pid})...")
    enc_key = wcdb_scan_key(pid, page1)
    if not enc_key:
        print("[!] Memory scan found no DB key, using old snapshot")
        return None
    print(f"[*] DB key found: {enc_key.hex()[:16]}...")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    total = (sz + WCDB_PAGE - 1) // WCDB_PAGE
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total + 1):
            page = fin.read(WCDB_PAGE)
            if len(page) < WCDB_PAGE:
                if not page:
                    break
                page = page + b"\x00" * (WCDB_PAGE - len(page))
            fout.write(wcdb_decrypt_page(enc_key, page, pgno))
    print(f"[*] Latest db: {out_path} ({total}  pages)")
    return out_path


# ==================== Decrypting ====================
def decrypt_file(path, key):
    from Crypto.Cipher import AES
    C = open(path, "rb").read()
    dec = AES.new(key, AES.MODE_CBC, key).decrypt(C)  # 每文件独立 cipher (避免状态污染)
    pad = dec[-1]
    if not (0 < pad <= 16 and all(b == pad for b in dec[-pad:])):
        return None
    return dec[:-pad]


def fmt_of(dec):
    if dec[:4] == b'\x89PNG':
        return 'png'
    if dec[:3] == b'GIF':
        return 'gif'
    if dec[:3] == b'\xff\xd8\xff':
        return 'jpg'
    if dec[:4] == b'wxgf':
        return 'wxgf'
    if dec[:4] == b'RIFF':
        return 'webp'
    return 'dat'


def decrypt_all(emo_dir, key, out_dir):
    """Decrypting Persist/PersistStore/Thumb/ThumbStore, 返回 {md5: (subdir, filename, fmt)}"""
    os.makedirs(out_dir, exist_ok=True)
    mapping = {}
    for sub in ["Persist", "PersistStore", "Thumb", "ThumbStore"]:
        sd = os.path.join(emo_dir, sub)
        if not os.path.isdir(sd):
            continue
        od = os.path.join(out_dir, sub)
        os.makedirs(od, exist_ok=True)
        n_ok = n_fail = 0
        for root, dirs, names in os.walk(sd):
            for n in names:
                base = n[:-6] if n.endswith(".thumb") else n
                if len(base) != 32 or not all(c in "0123456789abcdef" for c in base):
                    continue
                dec = decrypt_file(os.path.join(root, n), key)
                if dec is None:
                    n_fail += 1
                    continue
                f = fmt_of(dec)
                fn = f"{base}.{f}"
                open(os.path.join(od, fn), "wb").write(dec)
                mapping[base] = (sub, fn, f)
                n_ok += 1
        print(f"[*] Decrypting {sub}: {n_ok} ok {n_fail} failed")
    return mapping


# ==================== 容器分割 ====================
# ==================== 容器分割 ====================
def _png_end(data, start):
    """从 PNG 签名解析块链到 IEND, 返回结束位置或 None"""
    if data[start:start + 8] != b'\x89PNG\r\n\x1a\n':
        return None
    pos = start + 8
    n = len(data)
    while pos + 8 <= n:
        ln = struct.unpack('>I', data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        if pos + 8 + ln + 4 > n:
            return None
        if typ == b'IEND':
            return pos + 8 + ln + 4
        pos += 8 + ln + 4
    return None


def _gif_end(data, start):
    """按 GIF 块结构解析到 trailer 0x3B, 返回结束位置或 None"""
    if data[start:start + 6] not in (b'GIF87a', b'GIF89a'):
        return None
    pos = start + 6
    n = len(data)
    if pos + 7 > n:
        return None
    flags = data[pos + 4]
    pos += 7
    if flags & 0x80:  # 全局色表
        pos += 3 * (2 ** ((flags & 0x07) + 1))
    while pos < n:
        b = data[pos]
        if b == 0x3B:  # trailer
            return pos + 1
        if b == 0x21:  # extension: label + data sub-blocks
            pos += 2
        elif b == 0x2C:  # image descriptor
            pos += 10
            if pos <= n and data[pos - 1] & 0x80:  # 局部色表
                pos += 3 * (2 ** ((data[pos - 1] & 0x07) + 1))
            if pos >= n:
                return None
            pos += 1  # LZW 最小码长
        else:
            return None
        # 数据子块 (长度前缀, 0 结束): LZW 图像数据 / 扩展数据
        while pos < n:
            sz = data[pos]
            pos += 1
            if sz == 0:
                break
            pos += sz
        if pos > n:
            return None
    return None


def _jpeg_end(data, start):
    """按 marker 段解析到 EOI (FF D9), 返回结束位置或 None"""
    if data[start:start + 2] != b'\xff\xd8':
        return None
    pos = start + 2
    n = len(data)
    no_len = {0x01, *range(0xD0, 0xD8)}
    while pos + 2 <= n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        if data[pos + 1] == 0x00:  # 字节填充
            pos += 2
            continue
        marker = data[pos + 1]
        if marker == 0xD9:  # EOI
            return pos + 2
        if marker in no_len or marker == 0x01:
            pos += 2
            continue
        if pos + 4 > n:
            return None
        seg_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]
        if seg_len < 2 or pos + 2 + seg_len > n:
            return None
        pos += 2 + seg_len
    return None


def _magic_at(data, i):
    if data[i:i + 8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if data[i:i + 6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    if data[i:i + 2] == b'\xff\xd8':
        return 'jpg'
    if data[i:i + 4] == b'wxgf':
        return 'wxgf'
    if data[i:i + 4] == b'RIFF':
        return 'webp'
    return None


def _parse_end(data, i, ext):
    if ext == 'png':
        return _png_end(data, i)
    if ext == 'gif':
        return _gif_end(data, i)
    if ext == 'jpg':
        return _jpeg_end(data, i)
    return None  # wxgf/webp: 结构不定, 无法精确解析


def split_container(data):
    """流式分割: 完整解析一个文件到结束标记, 从结束位置继续 -> 天然跳过内部魔数误匹配

    只认能解析到结构结束的魔数 (PNG->IEND, GIF->0x3B, JPEG->EOI);
    数据内部的误匹配魔数无法形成完整结构 -> 自动忽略。
    """
    parts = []
    i = 0
    n = len(data)
    while i < n - 3:
        ext = _magic_at(data, i)
        if ext is None:
            i += 1
            continue
        end = _parse_end(data, i, ext)
        if end is None:
            # wxgf/webp 或误匹配: 若为不确定格式且后面有真实魔数, 切到下一个魔数
            if ext in ('wxgf', 'webp'):
                nxt = None
                for j in range(i + 4, n - 3):
                    if _magic_at(data, j):
                        nxt = j
                        break
                end = nxt if nxt is not None else n
            else:
                i += 1
                continue  # 误匹配
        if end - i < 16:  # 过小, 视为误匹配
            i += 1
            continue
        parts.append(data[i:end])
        i = end
    return parts


def extract_store(dec_dir, out_dir):
    """分割 PersistStore 容器, 返回 {md5: filename}"""
    src = os.path.join(dec_dir, "PersistStore")
    if not os.path.isdir(src):
        return {}
    od = os.path.join(out_dir, "store_extra")
    os.makedirs(od, exist_ok=True)
    extracted = {}
    for f in os.listdir(src):
        data = open(os.path.join(src, f), "rb").read()
        for pi, part in enumerate(split_container(data)):
            md5 = hashlib.md5(part).hexdigest()
            ext = fmt_of(part)
            if ext == 'dat':
                continue
            fn = f"{md5}.{ext}" if md5 not in extracted else f"{md5}_{pi}.{ext}"
            open(os.path.join(od, fn), "wb").write(part)
            extracted[md5] = fn
    print(f"[*] Container split: {len(extracted)} stickers")
    return extracted


# ==================== db 匹配与命名 ====================
def match_and_name(dec_dir, extracted, db_path, out_dir, do_wxgf=True):
    """对照 emoticon.db 按包分组命名, 返回结构化 result: {packs, favorites, unknown}"""
    result = {"packs": {}, "favorites": [], "unknown": []}
    pkg_dir = os.path.join(out_dir, "store")
    fav_dir = os.path.join(out_dir, "favorite")
    unk_dir = os.path.join(out_dir, "unknown")
    os.makedirs(pkg_dir, exist_ok=True)
    os.makedirs(fav_dir, exist_ok=True)
    os.makedirs(unk_dir, exist_ok=True)

    if db_path and os.path.isfile(db_path):
        import sqlite3
        db = sqlite3.connect(db_path)
        cur = db.cursor()
        fav_md5s = {r[0] for r in cur.execute("SELECT md5 FROM kNonStoreEmoticonTable")}
        pkg_names = dict(cur.execute("SELECT package_id_, package_name_ FROM kStoreEmoticonPackageTable"))
        caps = {}
        cap_pkg = {}  # md5 -> package_id (历史标题库, 含未安装包)
        for pid, md5, lang, cap in cur.execute(
                "SELECT package_id_, md5_, language_, caption_ FROM kStoreEmoticonCaptionsTable"):
            caps[md5] = cap
            cap_pkg[md5] = pid
        file_info = {}
        for pid, md5, typ, sort in cur.execute(
                "SELECT package_id_, md5_, type_, sort_order_ FROM kStoreEmoticonFilesTable"):
            file_info[md5] = (pid, sort)
        db.close()
    else:
        print("[!] No emoticon.db, md5-only naming")
        fav_md5s, pkg_names, caps, cap_pkg, file_info = set(), {}, {}, {}, {}

    clean = lambda s: re.sub(r'[\\/:*?"<>|\x00-\x1f]', '_', str(s)).strip() or 'untitled'
    n_pkg = n_fav = n_unk = 0
    sort_counter = {}  # 包 -> 递增序号 (unknown 无 sort_order_)
    used_names = {}  # (包名, 标题) -> 已用次数, 用于重名去重

    # 组装所有待命名文件: 仅 Persist 原图 + 容器分割切片
    # (PersistStore 容器文件本身不参与命名 — 已被分割为 store_extra)
    all_files = {}  # md5 -> src_path
    sd = os.path.join(dec_dir, "Persist")
    if os.path.isdir(sd):
        for fn in os.listdir(sd):
            md5 = fn.split('.')[0]
            all_files.setdefault(md5, os.path.join(sd, fn))
    # 容器切片: 全部保留 (完整解析出的切片都是真实文件;
    # 匹配 db 的进 store, 不匹配的进 unknown 保留)
    for md5, fn in extracted.items():
        all_files.setdefault(md5, os.path.join(out_dir, "store_extra", fn))

    for md5, src in all_files.items():
        ext = src.split('.')[-1]
        size = os.path.getsize(src)
        if md5 in fav_md5s:
            # favorites come from CDN — 由 CDN 全量下载 (见 cdn_fill_favorites)
            continue
        elif md5 in file_info:
            pid, sort = file_info[md5]
            pname = clean(pkg_names.get(pid, ''))
            cap = clean(caps.get(md5, ''))
            pd = os.path.join(pkg_dir, pname)
            os.makedirs(pd, exist_ok=True)
            # 文件名 = titled (序号/md5 只存 JSON)
            base = cap if cap and cap != 'untitled' else md5
            cnt = used_names.get((pname, base), 0)
            fn = f"{base}.{ext}" if cnt == 0 else f"{base}_{cnt+1}.{ext}"
            used_names[(pname, base)] = cnt + 1
            dst = os.path.join(pd, fn)
            shutil.copy2(src, dst)
            pack = result["packs"].setdefault(pname, {"package_id": pid, "stickers": []})
            pack["stickers"].append({"md5": md5, "caption": caps.get(md5, ''), "sort": sort,
                                     "file": f"store/{pname}/{fn}", "ext": ext, "size": size})
            n_pkg += 1
        else:
            # unknown: 无法归类的全部进 unknown (含仅有标题无包名的)
            cap = caps.get(md5, '')
            pid = cap_pkg.get(md5, '')
            pname = clean(pkg_names.get(pid, ''))
            if cap and pname:
                sort_counter[pname] = sort_counter.get(pname, 0) + 1
                capc = clean(cap)
                base = capc if capc != 'untitled' else md5
                cnt = used_names.get((pname, base), 0)
                fn = f"{base}.{ext}" if cnt == 0 else f"{base}_{cnt+1}.{ext}"
                used_names[(pname, base)] = cnt + 1
                dst = os.path.join(pkg_dir, pname, fn)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
                pack = result["packs"].setdefault(pname, {"package_id": pid, "stickers": []})
                pack["stickers"].append({"md5": md5, "caption": cap, "sort": sort_counter[pname],
                                         "file": f"store/{pname}/{fn}", "ext": ext, "size": size})
                n_pkg += 1
            else:
                dst = os.path.join(unk_dir, f"{md5}.{ext}")
                shutil.copy2(src, dst)
                item = {"md5": md5, "file": f"unknown/{md5}.{ext}", "ext": ext, "size": size}
                if cap:
                    item["caption"] = cap  # 保留标题信息供参考
                result["unknown"].append(item)
                n_unk += 1

    # wxgf 转码 (遍历结构化 result)
    if do_wxgf:
        try:
            import imageio_ffmpeg
            ff = imageio_ffmpeg.get_ffmpeg_exe()
            n_wxgf = 0
            def iter_items():
                for pack in result["packs"].values():
                    for s in pack["stickers"]:
                        yield s
                for s in result["unknown"]:
                    yield s
            for item in iter_items():
                if item["file"].endswith(".wxgf"):
                    fp = os.path.join(out_dir, item["file"])
                    data = open(fp, 'rb').read()
                    vps = data.find(b'\x00\x00\x00\x01\x40\x01')
                    sps = data.find(b'\x00\x00\x00\x01\x42\x01')
                    cut = min(x for x in (vps, sps) if x >= 0)
                    if cut < 0:
                        continue
                    hpath = fp + '.h265'
                    open(hpath, 'wb').write(data[cut:])
                    jpg = fp[:-5] + '.jpg'
                    r = subprocess.run([ff, '-y', '-hide_banner', '-loglevel', 'error',
                                        '-i', hpath, '-frames:v', '1', jpg], capture_output=True)
                    os.remove(hpath)
                    if os.path.exists(jpg) and os.path.getsize(jpg) > 100:
                        os.remove(fp)
                        item["file"] = item["file"][:-5] + '.jpg'
                        item["ext"] = 'jpg'
                        item["size"] = os.path.getsize(jpg)
                        n_wxgf += 1
            print(f"[*] wxgf transcoded: {n_wxgf}")
        except ImportError:
            print("[!] No imageio-ffmpeg, skipping wxgf transcode")

    print(f"[*] Named: store {n_pkg}, favorites {n_fav}, unknown {n_unk}")
    return result


# ==================== CDN favorites补全 ====================
CDN_UA = "Mozilla/5.0"
CDN_TIMEOUT = 20
CDN_MAGIC = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG": "png",
    b"GIF8": "gif",
    b"RIFF": "webp",
    b"WXGF": "wxgf",
}


def cdn_fetch(url):
    if not url or url == "null":
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": CDN_UA})
        with urllib.request.urlopen(req, timeout=CDN_TIMEOUT) as r:
            data = r.read()
            return data if data else None
    except Exception:
        return None


def cdn_decrypt(data, aes_key_hex):
    """encrypt_url 密文 -> AES-128-CBC(key=IV=aes_key) 明文"""
    try:
        from Crypto.Cipher import AES
        key = bytes.fromhex(aes_key_hex)
        if len(key) != 16:
            return None
        return AES.new(key, AES.MODE_CBC, key).decrypt(data)
    except Exception:
        return None


def cdn_ext(data):
    for sig, ext in CDN_MAGIC.items():
        if data[: len(sig)] == sig:
            return ext
    return "gif"


def cdn_sanitize(name):
    cleaned = re.sub(r'[\\/:*?"<>|]', "_", str(name)).strip()
    return cleaned or "favorites"


def cdn_fill_favorites(db_path, fav_dir, favorites):
    """CDN favorites downloaded表情, 追加到结构化 favorites 列表, 返回补全数"""
    if not db_path or not os.path.isfile(db_path):
        return 0
    import sqlite3
    db = sqlite3.connect(db_path)
    cur = db.cursor()
    favs = {}
    for md5, aes, cdn, enc, pid in cur.execute(
            "SELECT md5, aes_key, cdn_url, encrypt_url, product_id FROM kNonStoreEmoticonTable"):
        if md5:
            favs[md5] = (aes, cdn, enc, pid)
    # favorites顺序 (行序 = favorites序号)
    fav_order = {}
    for idx, (md5,) in enumerate(cur.execute("SELECT md5 FROM kFavEmoticonOrderTable")):
        fav_order[md5] = idx
    db.close()
    if not favs:
        return 0

    have = {e["md5"] for e in favorites}
    todo = [m for m in favs if m not in have]
    if not todo:
        print(f"[*] CDN favorites: all downloaded ({len(favs)})")
        return 0
    print(f"[*] CDN favorites downloaded: {len(todo)}/{len(favs)}")

    os.makedirs(fav_dir, exist_ok=True)
    n_ok = 0

    def dl(md5):
        aes, cdn, enc, pid = favs[md5]
        data = cdn_fetch(cdn)
        if data is None and enc and aes:
            raw = cdn_fetch(enc)
            if raw:
                data = cdn_decrypt(raw, aes)
        if not data or len(data) < 4:
            return None
        ext = cdn_ext(data)
        return ext if data else None, data, pid

    with ThreadPoolExecutor(max_workers=12) as pool:
        futs = {pool.submit(dl, m): m for m in todo}
        for fut in as_completed(futs):
            md5 = futs[fut]
            try:
                res = fut.result()
            except Exception:
                continue
            if not res:
                print(f"  ! {md5[:12]} download failed")
                continue
            _, data, pid = res
            ext = cdn_ext(data)
            # 文件名 = 仅favorites序号 (md5 只存 JSON)
            idx = fav_order.get(md5)
            fn = f"{idx+1:03d}.{ext}" if idx is not None else f"{md5}.{ext}"
            # 扁平存储: 全部直接放 favorite/ 根目录
            with open(os.path.join(fav_dir, fn), "wb") as f:
                f.write(data)
            favorites.append({"md5": md5, "sort": idx + 1 if idx is not None else None,
                              "product_id": pid, "file": f"favorite/{fn}",
                              "ext": ext, "size": len(data), "source": "cdn"})
            n_ok += 1
    print(f"[*] CDN filled: {n_ok}/{len(todo)}")
    return n_ok


# ==================== V2 图片Decrypting ====================
V2_MAGIC = b"\x07\x08V2\x08\x07"
V1_MAGIC = b"\x07\x08V1\x08\x07"
V1_KEY = b"cfcd208495d565ef"


def v2_find_xor(dat_files):
    """从 JPEG 尾部 FF D9 反推单字节 XOR key"""
    from collections import Counter
    tail_counts = Counter()
    for f in dat_files[:40]:
        try:
            sz = os.path.getsize(f)
            with open(f, "rb") as fp:
                head = fp.read(6)
                fp.seek(sz - 2)
                tail = fp.read(2)
            if head == V2_MAGIC and len(tail) == 2:
                tail_counts[(tail[0], tail[1])] += 1
        except OSError:
            continue
    if not tail_counts:
        return 0x88
    (x, y), _ = tail_counts.most_common(1)[0]
    return x ^ 0xFF  # 校验 y^0xD9 == xor 一致则成立


def v2_decrypt(path, key, xor_key):
    from Crypto.Cipher import AES
    from Crypto.Util import Padding
    data = open(path, "rb").read()
    if len(data) < 15:
        return None
    sig = data[:6]
    if sig not in (V2_MAGIC, V1_MAGIC):
        return None
    aes_size, xor_size = struct.unpack_from("<LL", data, 6)
    if sig == V1_MAGIC:
        key = V1_KEY
    aligned = aes_size + (16 - aes_size % 16) if aes_size % 16 else aes_size + 16
    off = 15
    if off + aligned > len(data):
        return None
    try:
        dec_aes = Padding.unpad(AES.new(key, AES.MODE_ECB).decrypt(data[off:off + aligned]), 16)
    except (ValueError, IndexError):
        return None
    off += aligned
    raw_end = len(data) - xor_size
    raw = data[off:raw_end] if off < raw_end else b""
    xor_tail = bytes(b ^ xor_key for b in data[max(off, raw_end):])
    return dec_aes + raw + xor_tail


def v2_ext(header):
    if header[:3] == b"\xff\xd8\xff":
        return "jpg"
    if header[:4] == b"\x89PNG":
        return "png"
    if header[:3] == b"GIF":
        return "gif"
    if header[:4] == b"RIFF":
        return "webp"
    if header[:4] == b"wxgf":
        return "hevc"
    return "bin"


def v2_export(data_dir, out_dir, seed, wxid):
    """V2 聊天图片解密: key = md5(f"{seed}{wxid}")[:16] (16字符 ASCII)"""
    v2key = hashlib.md5(f"{seed}{wxid}".encode()).hexdigest()[:16].encode()
    print(f"[*] V2 key = md5({seed}{wxid})[:16] = {v2key.decode()}")

    msg_dir = os.path.join(data_dir, "msg")
    if not os.path.isdir(msg_dir):
        print(f"[!] no msg dir: {msg_dir}")
        return 0
    dat_files = []
    for root, _d, names in os.walk(msg_dir):
        for n in names:
            if n.endswith(".dat"):
                dat_files.append(os.path.join(root, n))
    print(f"[*] .dat files: {len(dat_files)}")

    xor_key = v2_find_xor(dat_files)
    print(f"[*] XOR key: 0x{xor_key:02x}")

    out_img = out_dir if out_dir.endswith("decoded_images") else os.path.join(out_dir, "decoded_images")
    os.makedirs(out_img, exist_ok=True)
    ok = fail = 0
    seen = set()
    with open(os.path.join(out_img, "decoded_manifest.csv"), "w", encoding="utf-8") as mf:
        mf.write("source,size,type\n")
        for p in dat_files:
            result = v2_decrypt(p, v2key, xor_key)
            if not result:
                fail += 1
                continue
            ext = v2_ext(result)
            if ext == "bin":
                fail += 1
                continue
            base = os.path.basename(p)[:-4]
            for suf in ("_t", "_h"):
                if base.endswith(suf):
                    base = base[:-len(suf)]
                    break
            name = f"{base}.{ext}"
            if name in seen:
                name = f"{base}_{os.path.getsize(p)}.{ext}"
            seen.add(name)
            open(os.path.join(out_img, name), "wb").write(result)
            mf.write(f"{p},{len(result)},{ext}\n")
            ok += 1
    print(f"[*] V2 image decryption: ok {ok}, failed {fail} -> {out_img}")

    # hevc (wxgf) 转码为 jpg 首帧
    try:
        import imageio_ffmpeg
        ff = imageio_ffmpeg.get_ffmpeg_exe()
        n_ok = n_fail = 0
        for f in os.listdir(out_img):
            if not f.endswith(".hevc"):
                continue
            src = os.path.join(out_img, f)
            jpg = src[:-5] + ".jpg"
            r = subprocess.run([ff, "-y", "-hide_banner", "-loglevel", "error",
                                "-i", src, "-frames:v", "1", jpg], capture_output=True)
            if os.path.exists(jpg) and os.path.getsize(jpg) > 100:
                os.remove(src)
                n_ok += 1
            else:
                n_fail += 1
        print(f"[*] hevc transcoded: {n_ok} ok {n_fail} failed")
    except ImportError:
        print("[!] No imageio-ffmpeg, skipping hevc transcode")
    return ok


# ==================== 主流程 ====================
# ==================== 核心流程 (菜单与参数模式共用) ====================
def run_images(data_dir, wxid, emo_dir, out_dir, seed=None):
    """V2 聊天图片解密"""
    t0 = time.time()
    if not seed:
        if not emo_dir or not os.path.isdir(emo_dir):
            print("[!] Need emoticon dir for C0 verification, or use --seed")
            return None
        c0 = None
        for root, dirs, names in os.walk(emo_dir):
            for n in names:
                p = os.path.join(root, n)
                if os.path.getsize(p) >= 16:
                    c0 = open(p, "rb").read(16)
                    break
            if c0:
                break
        found = find_key_from_memory(c0, wxid) if c0 else None
        if not found:
            print("[!] Memory scan found no seed; run WeChat first or use --seed")
            return None
        seed, _ = found
        print(f"[+] HIT seed={seed}")
    v2_export(data_dir, out_dir, seed, wxid)
    print(f"[OK] Done in {time.time()-t0:.0f}s, output: {out_dir}")


def run_export(data_dir, wxid, emo_dir, out_dir="emoticon_export", key_hex=None,
               seed=None, db=None, no_cdn=False, no_wxgf=False, keep=False, notype=False):
    """表情包全通路导出 (Decrypting + 分割 + 命名 + CDN favorites + manifest)"""
    t0 = time.time()
    if not emo_dir or not os.path.isdir(emo_dir):
        print("[!] emoticon dir not found")
        return None
    # 取 C0 probe
    c0 = None
    for root, dirs, names in os.walk(emo_dir):
        for n in names:
            p = os.path.join(root, n)
            if os.path.getsize(p) >= 16:
                c0 = open(p, 'rb').read(16)
                break
        if c0:
            break
    if not c0:
        print("[!] no emoticon files")
        return None
    # 密钥
    if key_hex:
        key = bytes.fromhex(key_hex)
        print(f"[*] Using provided key: {key.hex()}")
    else:
        found = find_key_from_memory(c0, wxid) if not seed else None
        if not found:
            print("[!] Memory scan found no emoticon key")
            print("    Note: WeChat must be running; or use --key <hex> offline")
            return None
        seed, key = found
        print(f"\n[+] HIT! seed={seed}")
        print(f"[+] emoticon key = {key.hex()}")
        print(f"[+] md5 input = {seed}{wxid}EMOTICON")

    # 解密全部文件
    print(f'\n[*] {T("解密表情文件...", "Decrypting emoticon files...")}')
    dec_dir = os.path.join(out_dir, "_decrypted")
    decrypt_all(emo_dir, key, dec_dir)

    # 容器分割
    print(f'\n[*] {T("分割容器...", "Splitting PersistStore containers...")}')
    extracted = extract_store(dec_dir, out_dir)

    # db 匹配 + 命名
    print(f'\n[*] {T("DB 匹配与命名...", "Matching & naming from DB...")}')
    db_path = db
    tmp_db = None
    if not db_path:
        tmp_db = os.path.join(out_dir, "_emoticon_latest.db")
        db_path = decrypt_emoticon_db(data_dir, tmp_db)
        if not db_path:
            db_path = find_db()
    if db_path:
        print(f"[*] emoticon.db: {db_path}")
    result = match_and_name(dec_dir, extracted, db_path, out_dir, do_wxgf=not no_wxgf)

    # CDN favorites
    if not no_cdn and db_path:
        print(f'\n[*] {T("CDN 下载收藏...", "Downloading favorite stickers from CDN...")}')
        cdn_fill_favorites(db_path, os.path.join(out_dir, "favorite"), result["favorites"])

    # 清理 + 结构化 manifest
    if not keep:
        shutil.rmtree(dec_dir, ignore_errors=True)
        shutil.rmtree(os.path.join(out_dir, "store_extra"), ignore_errors=True)
        if tmp_db and os.path.isfile(tmp_db):
            os.remove(tmp_db)
    n_stickers = sum(len(p["stickers"]) for p in result["packs"].values())
    result["packs"] = {k: result["packs"][k] for k in sorted(result["packs"])}
    for pack in result["packs"].values():
        pack["stickers"].sort(key=lambda s: (s.get("sort") or 0, s.get("caption") or ""))
    result["favorites"].sort(key=lambda s: s.get("sort") or 0)
    result["unknown"].sort(key=lambda s: s.get("md5") or "")
    result["summary"] = {
        "packs": len(result["packs"]),
        "stickers": n_stickers,
        "favorites": len(result["favorites"]),
        "unknown": len(result["unknown"]),
        "total": n_stickers + len(result["favorites"]) + len(result["unknown"]),
    }
    json.dump(result, open(os.path.join(out_dir, "manifest.json"), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print(f"\n[*] manifest: {result['summary']}")

    # 可选: 全量平铺输出 (emoticon_export_all/)
    if notype:
        flat = os.path.join(os.path.dirname(os.path.abspath(out_dir)), "emoticon_export_all")
        os.makedirs(flat, exist_ok=True)
        clean_n = lambda s: re.sub(r'[\\/:*?"<>|\x00-\x1f]', '_', str(s)).strip() or 'untitled'
        used = set()
        n_flat = 0

        def uniq(base, ext):
            name = f"{base}.{ext}"
            k = 2
            while name in used:
                name = f"{base}_{k}.{ext}"
                k += 1
            used.add(name)
            return name

        for pname, pack in result["packs"].items():
            for s in pack["stickers"]:
                base = clean_n(f"{pname}_{s.get('caption') or s['md5']}")
                fn = uniq(base, s["ext"])
                shutil.copy2(os.path.join(out_dir, s["file"]), os.path.join(flat, fn))
                s["flat"] = fn
                n_flat += 1
        for f in result["favorites"]:
            base = f"favorite_{f['sort']:03d}" if f.get("sort") is not None else f"favorite_{f['md5']}"
            fn = uniq(base, f["ext"])
            shutil.copy2(os.path.join(out_dir, f["file"]), os.path.join(flat, fn))
            f["flat"] = fn
            n_flat += 1
        for i in result["unknown"]:
            fn = uniq(i["md5"], i["ext"])
            shutil.copy2(os.path.join(out_dir, i["file"]), os.path.join(flat, fn))
            i["flat"] = fn
            n_flat += 1
        json.dump(result, open(os.path.join(out_dir, "manifest.json"), 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
        # 只保留平铺output: manifest 移入 flat, 删除默认目录
        if os.path.isfile(os.path.join(out_dir, "manifest.json")):
            shutil.copy2(os.path.join(out_dir, "manifest.json"), os.path.join(flat, "manifest.json"))
        shutil.rmtree(out_dir, ignore_errors=True)
        print(f"[*] Flattened output (--notype): {n_flat} files -> {flat}")
    print(f"[OK] {T('完成', 'Done')} in {time.time()-t0:.0f}s, {T('输出', 'output')}: {out_dir if not notype else flat}")
    return result


# ==================== 工具型功能 ====================
def wcdb_decrypt_file(db_path, out_path, enc_keys):
    """用候选 keys 匹配并解密单个 SQLCipher4 db 文件"""
    sz = os.path.getsize(db_path)
    if sz < WCDB_PAGE:
        return False
    with open(db_path, "rb") as f:
        page1 = f.read(WCDB_PAGE)
    enc_key = next((ek for ek in enc_keys if wcdb_verify_key(ek, page1)), None)
    if not enc_key:
        return False
    total = (sz + WCDB_PAGE - 1) // WCDB_PAGE
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total + 1):
            page = fin.read(WCDB_PAGE)
            if len(page) < WCDB_PAGE:
                if not page:
                    break
                page = page + b"\x00" * (WCDB_PAGE - len(page))
            fout.write(wcdb_decrypt_page(enc_key, page, pgno))
    return True


def tool_decrypt_db(data_dir, out_dir="decrypted_db"):
    """Decrypting db_storage 下全部数据库到明文 (SQLCipher4 逐 pages)"""
    t0 = time.time()
    storage = os.path.join(data_dir, "db_storage")
    if not os.path.isdir(storage):
        print(f"[!] no db_storage dir: {storage}")
        return None
    # 收集所有 .db (含 -wal/-shm 忽略)
    db_files = []
    for root, dirs, names in os.walk(storage):
        for n in names:
            if n.endswith(".db") and not n.endswith("-wal") and not n.endswith("-shm"):
                db_files.append(os.path.join(root, n))
    if not db_files:
        print("[!] no database files found")
        return None
    # 微信需运行 (读进程内存)
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if not r.stdout.strip():
        print("[!] WeChat not running, cannot decrypt (needs process memory)")
        return None
    pids = []
    for line in r.stdout.strip().split("\n"):
        if not line.strip():
            continue
        p = line.strip('"').split('","')
        if len(p) >= 5:
            try:
                pids.append((int(p[1]), int(p[4].replace(",", "").replace(" K", "") or 0)))
            except ValueError:
                pass
    if not pids:
        return None
    pids.sort(key=lambda x: -x[1])
    pid = pids[0][0]
    print(f"[*] Scanning process memory for DB keys (pid={pid})...")
    enc_keys = wcdb_scan_candidate_keys(pid)
    print(f"[*] candidate enc_keys: {len(enc_keys)}")
    if not enc_keys:
        print("[!] No candidate keys found")
        return None
    ok = fail = 0
    os.makedirs(out_dir, exist_ok=True)
    for db_path in sorted(db_files):
        rel = os.path.relpath(db_path, storage)
        out_path = os.path.join(out_dir, rel)
        if wcdb_decrypt_file(db_path, out_path, enc_keys):
            ok += 1
            print(f"  [OK] {rel}")
        else:
            fail += 1
            print(f"  [!] {rel} decryption failed (key mismatch)")
    print(f"[+] Decryption done: {ok}/{len(db_files)} ok, {fail} failed ({time.time()-t0:.0f}s) -> {out_dir}")
    return out_dir


def tool_show_keys(data_dir, wxid, emo_dir):
    """提取并显示密钥: seed / emoticon key / V2 key"""
    t0 = time.time()
    c0 = None
    if emo_dir and os.path.isdir(emo_dir):
        for root, dirs, names in os.walk(emo_dir):
            for n in names:
                p = os.path.join(root, n)
                if os.path.getsize(p) >= 16:
                    c0 = open(p, "rb").read(16)
                    break
            if c0:
                break
    if not c0:
        print("[!] No emoticon file to verify against (WeChat must be running)")
        return None
    found = find_key_from_memory(c0, wxid)
    if not found:
        print("[!] Memory scan found no seed (WeChat must be running)")
        return None
    seed, key = found
    v2key = hashlib.md5(f"{seed}{wxid}".encode()).hexdigest()[:16]
    print(f"\n[+] seed        = {seed} (md5 input: {seed}{wxid}EMOTICON)")
    print(f"[+] emoticon key = {key.hex()} (AES-128-CBC key=IV)")
    print(f"[+] V2 image key = {v2key} (md5({seed}{wxid})[:16])")
    # 保存到 keys.txt
    with open("wechat_keys.txt", "w", encoding="utf-8") as f:
        f.write(f"seed = {seed}\n")
        f.write(f"wxid = {wxid}\n")
        f.write(f"emoticon_key = {key.hex()}\n")
        f.write(f"v2_image_key = {v2key}\n")
    print(f"[*] Saved wechat_keys.txt ({time.time()-t0:.0f}s)")
    return seed


# ==================== 交互式菜单 ====================
def interactive():
    print("=" * 56)
    print(T("微信数据解密工具", "WeChat Data Decryption Tool"))
    print("=" * 56)
    while True:
        print()
        print(T("请选择操作 (按 c 切换语言):", "Select an operation (press c for 中文):"))
        print(T("  [1] 表情包导出 (解密+分割+命名+CDN收藏)", "  [1] Export emoticons (decrypt+split+name+CDN favorites)"))
        print(T("  [2] V2 聊天图片解密 (msg/ 目录)", "  [2] Decrypt V2 chat images (msg/)"))
        print(T("  [3] 表情包导出 - 平铺模式 (emoticon_export_all/)", "  [3] Export emoticons - flatten mode (emoticon_export_all/)"))
        print(T("  [4] 解密全部数据库 (db_storage -> decrypted_db/)", "  [4] Decrypt ALL databases (db_storage -> decrypted_db/)"))
        print(T("  [5] 提取并显示密钥 (seed/key/V2 key)", "  [5] Extract & show keys (seed/emoticon-key/V2-key)"))
        print(T("  [0] 退出", "  [0] Exit"))
        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print(T("再见", "Bye"))
            break
        if choice.lower() == "c":
            LANG["cur"] = "zh" if LANG["cur"] == "en" else "en"
            if LANG["cur"] == "zh":
                print("[i] 已切换为中文")
            else:
                print("[i] Switched to English")
            continue
        if choice in ("", "0", "q", "Q", "quit"):
            print(T("再见", "Bye"))
            break
        if choice not in ("1", "2", "3", "4", "5"):
            print(T("[!] 无效选择", "[!] Invalid choice"))
            continue
        data_dir = find_data_dir()
        if not data_dir:
            print(T("[!] 未找到微信数据目录, 请用参数模式 --data-dir 指定",
                    "[!] WeChat data dir not found, use --data-dir in argument mode"))
            continue
        wxid = auto_wxid(data_dir)
        emo_dir = find_emoticon_dir(data_dir)
        print(f"[*] {T('数据目录', 'data dir')}: {data_dir}")
        print(f"[*] wxid: {wxid}")
        if choice == "1":
            run_export(data_dir, wxid, emo_dir)
        elif choice == "2":
            run_images(data_dir, wxid, emo_dir, "decoded_images")
        elif choice == "3":
            run_export(data_dir, wxid, emo_dir, notype=True)
        elif choice == "4":
            tool_decrypt_db(data_dir)
        elif choice == "5":
            tool_show_keys(data_dir, wxid, emo_dir)


def main():
    ap = argparse.ArgumentParser(description="WeChat Data Decryption Tool (无参数运行进入交互菜单; 可选参数用于离线/自定义)")
    ap.add_argument("--data-dir", help="WeChat data dir (xwechat_files/wxid_xxx_b487)")
    ap.add_argument("--db", help="path to a decrypted emoticon.db")
    ap.add_argument("--key", help="provide key (hex), skip memory scan")
    ap.add_argument("--out", default="emoticon_export", help="output directory")
    ap.add_argument("--no-wxgf", action="store_true", help="skip wxgf transcoding")
    ap.add_argument("--images", action="store_true", help="V2 chat image decryption mode (msg/)")
    ap.add_argument("--seed", type=int, help="provide account seed (skip memory scan)")
    ap.add_argument("--no-cdn", action="store_true", help="skip CDN favorites (default: download missing from CDN)")
    ap.add_argument("--notype", action="store_true",
                    help="flatten-only output to emoticon_export_all/: group_name / favorite_index")
    ap.add_argument("--keep-decrypted", action="store_true", help="keep intermediate decrypted files")
    args = ap.parse_args()

    # 无任何显式参数 -> 交互菜单
    explicit = (args.data_dir or args.db or args.key or args.seed or args.images
                or args.no_wxgf or args.no_cdn or args.notype or args.keep_decrypted
                or args.out != "emoticon_export")
    if not explicit:
        interactive()
        return

    # 参数模式 (离线 / 自定义)
    data_dir = args.data_dir or find_data_dir()
    if not data_dir:
        print("[!] WeChat data dir not found, use --data-dir")
        return
    wxid = auto_wxid(data_dir)
    emo_dir = find_emoticon_dir(data_dir)
    print(f"[*] {T('数据目录', 'data dir')}: {data_dir}")
    print(f"[*] wxid: {wxid}")
    print(f"[*] emoticon dir: {emo_dir}")
    if args.images:
        run_images(data_dir, wxid, emo_dir, args.out, args.seed)
    else:
        run_export(data_dir, wxid, emo_dir, args.out, args.key, args.seed,
                   args.db, args.no_cdn, args.no_wxgf, args.keep_decrypted, args.notype)


if __name__ == "__main__":
    main()
