# WeChat Decryptor

> 微信 4.1.x (Windows) 本地数据解密工具 —— 表情包导出与聊天图片解密

通过内存扫描与密钥派生，解密微信本地加密数据：表情包（含商店包标题命名）与 V2 格式聊天图片。

---

## 特性

- **表情包导出**：商店包按包名分组，文件仅标题命名（`拜拜啦.gif`）；收藏按收藏顺序命名（`favorite_001.gif`）；`--notype` 全量平铺到单一目录
- **一键全通路**：定位数据目录 → 内存扫 seed → 派生密钥 → 自包含 db 解密 → 文件解密 → 流式容器分割 → db 匹配命名 → CDN 收藏
- **数据库解密完全内置**：WCDB 密钥内存扫描（无需外部工具）
- **wxgf 动图支持**：HEVC 流提取 + 首帧转码（GIF/PNG/JPEG 直出）
- **聊天图片解密**：V2 格式 `.dat` 全量还原（`--images`）
- **结构化 manifest**：`{packs, favorites, unknown, summary}` 与目录树一一对应，已排序
- **轻依赖**：仅需 `pycryptodome`（转码可选 `imageio-ffmpeg`）

---

## 算法

### 1. 表情包文件加密（emoticon）

表情文件加密存储于 `business/emoticon/` 下 `Persist` / `PersistStore` / `Thumb` / `ThumbStore`
四个目录（文件名为内容 md5）。

```
算法: AES-128-CBC + PKCS7, key = IV
key = md5(f"{seed}{wxid}EMOTICON") hex 解码前 16 字节
```

| 参数 | 来源 |
|---|---|
| `seed` | 微信进程内存中的账号级常量（十进制数，内存扫描提取） |
| `wxid` | 数据目录名去掉 `_b487` 后缀 |

要点：

- 所有表情文件共用同一密钥（不同批次首块 C0 不同，只因明文头 wxgf 长度字段差异）
- `PersistStore` 容器文件 = 每包多表情按魔数（`GIF8`/`89PNG`/`FFD8FF`）连续拼接，
  **流式结构解析分割**（PNG→IEND、GIF→0x3B、JPEG→EOI），自动忽略压缩数据内部的魔数误匹配，不产生残缺切片
- `wxgf` 文件 = 魔数后为裸 H.265 流（从 `00 00 00 01 40 01` VPS 处截取），ffmpeg 提取首帧
- 密钥以二进制 16 字节存于主进程堆的账号会话 key 表（wxid 字符串旁）

### 2. 聊天图片加密（V2 .dat）

聊天图片存于 `msg/` 目录，格式：

```
[15B 头: 6B 签名 07 08 56 32 08 07 | aes_size(4) | xor_size(4) | pad(1)]
[AES-128-ECB 区段][raw 明文区][单字节 XOR 尾部]

key    = md5(f"{seed}{wxid}")[:16]   (16 字符字母数字 ASCII)
XOR key = seed & 0xFF（从 JPEG 尾部 FF D9 反推校验）
```

### 3. 数据库（WCDB）

微信 4.1+ 进程内存不再缓存明文密钥（仅留 passphrase）。脚本**完整内置**运行时解密：
内存扫描 `com.Tencent.WCDB.Config.Cipher` 对象 → XOR 反混淆 → 候选 key 提取 →
HMAC-SHA512 校验（SQLCipher4 规范）→ AES-256-CBC 逐页解密。`emoticon.db` 含表情全部元数据
（包、标题、排序、CDN 映射）。无需外部工具。

### 4. 通用密钥发现流程（内存扫描 → 派生 → 验证）

```
1. 候选提取   ReadProcessMemory 读取 Weixin.exe 主进程 → 正则提取数字串（seed 候选）
2. 派生       md5(f"{seed}{wxid}EMOTICON") 取前 16 字节
3. 验证       用任意 emoticon 文件首块（C0）AES-CBC(key=IV) 解密 → 魔数命中即确认
              （89504e47 / GIF8 / FFD8FF / wxgf）
```

该流程不依赖第三方工具，仅需微信运行中。

---

## 项目结构

```
wechat/
├── wechat_emoticon_export.py   统一工具：表情导出 + V2 图片解密 + key 扫描
├── README.md
└── README_CN.md
```

## 输出结构

```
emoticon_export/                  # 默认输出
├── store/<包名>/<标题>.gif        # 商店表情，标题命名（序号/md5 存 manifest）
├── favorite/001.gif              # 收藏表情，按收藏顺序命名（kFavEmoticonOrderTable）
├── unknown/<md5>.jpg             # 未匹配残留（仅完整文件）
└── manifest.json                 # 结构化：{packs, favorites, unknown, summary}

emoticon_export_all/              # --notype：全量平铺，命名 组名_表情名 / favorite_序号
decoded_images/                   # V2 聊天图片（菜单 [2] / --images）
decrypted_db/                     # 全部明文数据库（菜单 [4]）— contact/message/sns 等
wechat_keys.txt                   # 提取的密钥（菜单 [6]）
```

## 安装

```bash
pip install pycryptodome          # 必需
pip install imageio-ffmpeg        # 可选：wxgf/hevc 动图转码
```

## 使用

```bash
# 交互式菜单（无参数运行）:
#   [1] 表情包导出   [2] V2 聊天图片   [3] 平铺模式导出
#   [4] 解密全部数据库（db_storage → decrypted_db/）
#   [5] 提取并显示密钥
#   [0] 退出
python wechat_emoticon_export.py

# 参数模式（离线 / 自定义路径）
python wechat_emoticon_export.py --key <hex key>                      # 表情导出
python wechat_emoticon_export.py --images --seed <seed>               # V2 图片
python wechat_emoticon_export.py --data-dir <xwechat_files/wxid_xxx_b487> \
                                 --db <已解密 emoticon.db> --out <输出目录> --notype

# 选项
--no-cdn          跳过 CDN 收藏下载
--no-wxgf         跳过 wxgf/hevc 转码
--notype          平铺模式输出到 emoticon_export_all/（组名_表情名 / favorite_序号）
--keep-decrypted  保留中间解密文件与临时 db
```

---

## 致谢

本项目的密钥提取思路与内存扫描方法借鉴了以下开源项目，在此表示感谢：

- [TANGandXue/wcdb-key-tool](https://github.com/TANGandXue/wcdb-key-tool) — WCDB 数据库运行时扫描解密
- [LifeArchiveProject/WeChatDataAnalysis](https://github.com/LifeArchiveProject/WeChatDataAnalysis) — 密钥派生公式与候选验证方法
- [WeChatMsgDump](https://github.com/junuo-S/WeChatMsgDump) — 进程内存读取架构
- [93857536-pixel/WeChatExporter](https://github.com/93857536-pixel/WeChatExporter) — 表情 CDN 下载与 wxgf 解析逻辑
- [CipherTalk](https://github.com/CipherTalk/wechat-key-tool) — 账号 seed 提取方法

## License

MIT
