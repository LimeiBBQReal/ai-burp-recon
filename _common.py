"""云端采集共享工具 (双层加密: AES-256-CBC + RSA-2048).

加密流程:
  明文 JSON
    → AES-256-CBC 加密 (key = 随机 32 字节)
    → RSA-2048 加密 AES key (pubkey = RECON_RSA_PUBLIC)

输出两个文件:
  out/<name>.data.enc  # AES 密文
  out/<name>.key.enc   # RSA 加密的 AES key (256 bytes)

解密需要 RSA 私钥 (RECON_RSA_PRIVATE 环境变量 或 ~/.recon/recon_private.pem).
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "out"
OUT_DIR.mkdir(exist_ok=True)

# 自动加载 .env
_ENV_LOADED = False


def _load_dotenv():
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    _ENV_LOADED = True
    # 查找 .env 文件: <同一目录>/.env.local (Git 忽略), ~/.env
    # .env / .env.local 都不进 Git
    candidates = [
        ROOT / ".env.local",
        ROOT.parent / ".env",
        ROOT / ".env",
        Path.home() / ".env",
    ]
    for env_path in candidates:
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("'\"")
                if key and val and key not in os.environ:
                    os.environ[key] = val
            break


_load_dotenv()


def _generate_aes_key() -> bytes:
    """每次调用生成一个随机 32 字节 AES 密钥"""
    return os.urandom(32)


def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv + ct


def rsa_encrypt_key(aes_key_bytes: bytes) -> bytes:
    pub_b64 = os.environ.get("RECON_RSA_PUBLIC", "")
    if not pub_b64:
        print("[FATAL] RECON_RSA_PUBLIC 未设置", file=sys.stderr)
        sys.exit(1)
    pub_pem = base64.b64decode(pub_b64)
    pub = serialization.load_pem_public_key(pub_pem)
    return pub.encrypt(
           aes_key_bytes,
           asym_padding.OAEP(
               mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
               algorithm=hashes.SHA256(),
               label=None,
           ),
       )


def write_encrypted(name: str, data: Any) -> tuple[Path, Path]:
    text = json.dumps(data, ensure_ascii=False, indent=2) if not isinstance(data, str) else data
    aes_key = _generate_aes_key()
    encrypted_data = aes_encrypt(text, aes_key)
    encrypted_key = rsa_encrypt_key(aes_key)

    data_path = OUT_DIR / f"{name}.data.enc"
    key_path = OUT_DIR / f"{name}.key.enc"
    data_path.write_bytes(encrypted_data)
    key_path.write_bytes(encrypted_key)
    print(f"  → {data_path.name}: {len(encrypted_data)} bytes", file=sys.stderr)
    print(f"  → {key_path.name}: {len(encrypted_key)} bytes", file=sys.stderr)
    return data_path, key_path


def get_target() -> str:
    target = os.environ.get("TARGET", "")
    if not target:
        print("[FATAL] TARGET 未设置", file=sys.stderr)
        sys.exit(1)
    return target


def http_get(url: str, timeout: int = 10, **kwargs) -> requests.Response | None:
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
    try:
        return requests.get(url, timeout=timeout, headers=headers, **kwargs)
    except Exception as e:
        print(f"  [ERR] {url}: {e}", file=sys.stderr)
        return None


def load_wordlist(name: str) -> list[str]:
    path = ROOT / "wordlists" / f"{name}.txt"
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _decrypt_aes(data_enc: bytes, key: bytes) -> str:
    iv = data_enc[:16]
    ct = data_enc[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    return plain.decode("utf-8")


def _find_private_key() -> bytes | None:
    priv_b64 = os.environ.get("RECON_RSA_PRIVATE", "")
    if priv_b64:
        return base64.b64decode(priv_b64)
    for p in (os.path.expanduser("~/.recon/recon_private.pem"),):
        if Path(p).exists():
            return Path(p).read_bytes()
    return None


def _decrypt_rsa(encrypted_key: bytes) -> bytes:
    priv_pem = _find_private_key()
    if not priv_pem:
        print("[FATAL] RSA 私钥未找到 (检查 RECON_RSA_PRIVATE 环境变量或 ~/.recon/recon_private.pem)", file=sys.stderr)
        sys.exit(1)
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    return priv.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _legacy_aes_key() -> bytes | None:
    """向后兼容: 从 PROXY_AES_KEY 派生密钥（旧加密方案）。
    仅用于过渡期读取旧加密文件。新文件走 RSA 解密路径。"""
    import hashlib
    raw = os.environ.get("PROXY_AES_KEY", "")
    if not raw:
        return None
    print("  [WARN] 使用 PROXY_AES_KEY 向后兼容解密（旧文件）", file=sys.stderr)
    return hashlib.sha256(raw.encode("utf-8")).digest()[:32]


def _read_encrypted(name: str) -> Any:
    data_path = OUT_DIR / f"{name}.data.enc"
    key_path = OUT_DIR / f"{name}.key.enc"
    if not data_path.exists() or not key_path.exists():
        print(f"[FATAL] {name}.data.enc 或 {name}.key.enc 不存在", file=sys.stderr)
        sys.exit(1)
    try:
        aes_key = _decrypt_rsa(key_path.read_bytes())
    except Exception as e:
        print(f"  [WARN] RSA 解密失败 ({e}), 尝试向后兼容...", file=sys.stderr)
        aes_key = _legacy_aes_key()
        if aes_key is None:
            print(f"[FATAL] 解密 {name} 失败: RSA 密钥不匹配且无 PROXY_AES_KEY 回退", file=sys.stderr)
            sys.exit(1)
    plain = _decrypt_aes(data_path.read_bytes(), aes_key)
    return json.loads(plain)