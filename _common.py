"""云端采集共享工具 (双层加密: AES-256-CBC + RSA-2048).

加密流程:
  明文 JSON
    → AES-256-CBC 加密 (key = sha256(PROXY_AES_KEY)[:32])
    → RSA-2048 加密 AES key (pubkey = RECON_RSA_PUBLIC)

输出两个文件:
  out/<name>.data.enc  # AES 密文
  out/<name>.key.enc   # RSA 加密的 AES key

只有同时持有 RSA 私钥 + PROXY_AES_KEY 才能解密.
PROXY_AES_KEY 单凭它解不开, 还得有 RSA 私钥.
"""
from __future__ import annotations

import base64
import hashlib
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


def _aes_key() -> bytes:
    raw = os.environ.get("PROXY_AES_KEY", "")
    if not raw:
        print("[FATAL] PROXY_AES_KEY 未设置", file=sys.stderr)
        sys.exit(1)
    return hashlib.sha256(raw.encode("utf-8")).digest()[:32]


def aes_encrypt(plaintext: str) -> bytes:
    key = _aes_key()
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
    encrypted_data = aes_encrypt(text)
    encrypted_key = rsa_encrypt_key(_aes_key())

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