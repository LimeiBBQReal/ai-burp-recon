# AI-Burp Recon (云端采集层)

云端被动/主动信息采集，跑在 **GitHub Actions** 上，避免本地 TUN 劫持污染。

> **双层加密**: 明文 → AES-256-CBC → RSA-2048-OAEP 包装 AES key  
> 公开仓库只看到密文, 没有 RSA 私钥就无法解密

---

## 架构

```
┌─────────────────────────────────────────────────────────┐
│ 本地 (决策层)                                            │
│   recon_trigger.py  ──POST /dispatches──▶ GitHub       │
│   recon_decoder.py  ◀──pull .enc + .key.enc──  Repo     │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│ GitHub Actions (采集层, 公共仓库无限免费)                 │
│   ┌──────────────────────────────────────────────┐     │
│   │ subdomain_enum.py    DNS字典 + crt.sh        │     │
│   │ dns_enum.py          A/AAAA/MX/TXT/NS/CNAME  │     │
│   │ port_scan.py         TCP Connect 扫描        │     │
│   │ banner_grab.py       服务指纹                │     │
│   │ js_extract.py        JS/CSS URL 提取         │     │
│   │ dir_brute.py         目录穷举                │     │
│   │ param_brute.py       隐藏参数穷举            │     │
│   └──────────────────────────────────────────────┘     │
│                          │                              │
│                          ▼                              │
│   out/<task>.data.enc  (AES-256-CBC 密文)              │
│   out/<task>.key.enc   (RSA-2048-OAEP 包装的 AES key)   │
└─────────────────────────────────────────────────────────┘
```

---

## 加密流程 (双层)

```
明文 JSON
   │
   ├── AES-256-CBC 加密 (key = SHA256(PROXY_AES_KEY)[:32])
   │     ↓
   │  <name>.data.enc     # iv(16) + ciphertext
   │
   └── RSA-2048-OAEP 加密 AES key (pubkey = RECON_RSA_PUBLIC)
         ↓
        <name>.key.enc      # 256 字节 (2048 bit)

解密:  RSA 私钥解 .key.enc → AES key → 解密 .data.enc → 明文
```

**为什么需要双层?**  
- 单独 AES: 密钥会随密文入仓, 任何人 commit 历史都能解密  
- 单独 RSA: 2048-bit RSA 加密大文件极慢  
- AES+RSA: AES 加密数据快, RSA 只加密 32 字节 key, 私钥只在本地

---

## 部署步骤

### 1. 创建仓库 (用户操作)

GitHub 上创建公开仓库 `ai-burp-recon` (建议名字, 也可改名)

### 2. 生成 RSA 密钥对 (用户本地操作)

```bash
mkdir -p ~/.recon
openssl genrsa -out ~/.recon/recon_private.pem 2048
openssl rsa -in ~/.recon/recon_private.pem -pubout -out ~/.recon/recon_public.pem

# 把公钥转成 base64 (粘到 GitHub Secret, 不带 -----BEGIN----- 换行也可)
base64 -w0 ~/.recon/recon_public.pem > ~/.recon/recon_public_b64.txt
cat ~/.recon/recon_public_b64.txt
```

私钥 (`recon_private.pem`) **只在本地**, **绝不提交**.

### 3. 推送代码 (用户操作)

```bash
cd e:/CursorDEV/CKFinder/ai-burp/recon
git init
git remote add origin https://github.com/LimeiBBQReal/ai-burp-recon.git
git add .
git commit -m "init: recon cloud collector"
git push -u origin main
```

> `.gitignore` 已包含 `*.pem`, 私钥不会被 add.

### 4. 配置 GitHub Secrets (用户操作)

仓库 → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

| Secret 名 | 值 | 说明 |
|-----------|----|----|
| `PROXY_AES_KEY` | `ApOiDIzzSzdN6B4BGEWRjxfhGWU4I3o5` | 与 proxy-pool 同一个 AES 种子 |
| `RECON_RSA_PUBLIC` | (上面生成的 base64 字符串) | RSA 公钥, base64 编码的 PEM |

### 5. 测试 workflow

在仓库 Actions 页面, 选 "Recon - Subdomain Enum" → Run workflow  
输入 `example.com` (或任何合法域名) → 绿色按钮

跑完后会 commit `recon/out/subdomain.data.enc` + `subdomain.key.enc` 到仓库.

---

## 本地使用

### 触发采集

```bash
# 设置 GitHub PAT (有 repo + actions 权限)
setx GITHUB_TOKEN ghp_xxxxxxxxxxxx

# 触发单个
python -m aiburp.recon_trigger --target example.com --task subdomain

# 触发全套
python -m aiburp.recon_trigger --target example.com --all

# 触发 + 等结果 + 自动解密
python -m aiburp.recon_trigger --target example.com --all --wait --decode
```

### 解密结果

```bash
# 列仓库里有哪些 .enc
python -m aiburp.recon_decoder --list

# 解密单个
python -m aiburp.recon_decoder --task subdomain

# 批量
python -m aiburp.recon_decoder --tasks subdomain,dns,ports --out ./decrypted/

# 指定别的仓库
python -m aiburp.recon_decoder --repo yourname/yourrepo --task subdomain
```

明文输出到 `./recon_out/<target>/<task>.json` (默认), 可直接喂 LLM.

---

## 目录结构

```
recon/
├── .github/workflows/
│   ├── recon-subdomain.yml    ← 7 个 workflow_dispatch
│   ├── recon-dns.yml
│   ├── recon-portscan.yml
│   ├── recon-banner.yml
│   ├── recon-js.yml
│   ├── recon-dir.yml
│   └── recon-params.yml
├── wordlists/
│   ├── subdomains.txt         ← 通用字典 (无具体目标)
│   ├── dirs.txt
│   └── params.txt
├── _common.py                 ← 双层加密核心
├── subdomain_enum.py
├── dns_enum.py
├── port_scan.py
├── banner_grab.py
├── js_extract.py
├── dir_brute.py
├── param_brute.py
├── .gitignore                 ← 屏蔽 .pem / .key / out/*.enc
└── README.md

aiburp/                       ← 主项目, 本地工具
├── recon_decoder.py          ← 拉 .enc 解密
└── recon_trigger.py          ← POST /dispatches
```

---

## 已知限制

| 限制 | 影响 | 缓解 |
|------|------|------|
| Actions 单 job 6 小时上限 | 长任务会被砍 | timeout-minutes 已设 5~8, 单词扫描够用 |
| 公共仓库 2000 分钟/月 (私有) | 公共无限 | 已用公共仓库 |
| 单 workflow 排队延迟 1~5 分钟 | 多个 workflow 并发会排队 | 串行触发 |
| crt.sh 限速 | DNS 子域枚举偶尔超时 | 已有 4s timeout, 失败不阻塞 |
| GitHub raw 拉取限制 | 解密高频拉取可能被 403 | 默认 5 分钟内不重拉 |

---

## 端到端自检

跑过, 已通过 (见 `.pipeline_output/_e2e_crypto_test.py`):

```
[1] RSA-2048 生成 OK (451 字节 PEM)
[2] AES-256 key 派生 OK (32 字节)
[3] AES 加密 OK (112 字节 ciphertext)
[4] RSA-OAEP 加密 AES key OK (256 字节)
[5] RSA 解密 key 一致性 OK
[6] AES 解密 plaintext 一致性 OK
[7] recon_decoder._decrypt_data 调用 OK
[8] _common.write_encrypted OK: test_task.data.enc + test_task.key.enc
[9] _common → recon_decoder 端到端 OK: {'hello': 'world'}
========== 自检全部通过 ==========
```