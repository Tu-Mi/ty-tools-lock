#!/usr/bin/env python3
"""远程授权锁 · 离线管控工具（一个授权通吃所有设备）"""
import sys, json, time, base64, subprocess
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

BASE = Path(__file__).resolve().parent
PRIV = BASE / "private.pem"
PUB = BASE / "public.pem"
LIC = BASE / "license_x7m2k9q.json"


def gen_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIV.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    PUB.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    b64 = "".join(PUB.read_text().splitlines()[1:-1])
    print("已生成 private.pem / public.pem")
    print("=== App 内置公钥(BASE64) ===")
    print(b64)


def text_of(p):
    return f"{p['expiresAt']}|{1 if p['revoked'] else 0}|{p['serial']}"


def sign(key, p):
    return base64.b64encode(
        key.sign(text_of(p).encode(), padding.PKCS1v15(), hashes.SHA256())
    ).decode()


def load():
    key = serialization.load_pem_private_key(PRIV.read_bytes(), password=None)
    fallback = {"expiresAt": 0, "revoked": True, "serial": 0}
    if LIC.exists() and LIC.stat().st_size > 0:
        try:
            d = json.loads(LIC.read_text(encoding="utf-8"))
            return key, d["payload"]
        except Exception:
            print("警告：授权文件内容损坏，已按吊销状态处理")
    return key, fallback


def save_push(key, p):
    LIC.write_text(json.dumps({"payload": p, "sig": sign(key, p)}, indent=2),
                   encoding="utf-8")
    subprocess.run(["git", "add", LIC.name], cwd=BASE, check=True)
    subprocess.run(["git", "commit", "-m", f"license serial={p['serial']}"],
                   cwd=BASE, check=True)
    subprocess.run(["git", "push"], cwd=BASE, check=True)
    print("已签发并推送：", json.dumps(p))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "init":
        gen_keys(); return
    key, p = load()
    if cmd == "status":
        print(json.dumps(p, indent=2, ensure_ascii=False)); return
    if cmd in ("issue", "renew"):
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 365
        p["expiresAt"] = int(time.time()) + days * 86400
        p["revoked"] = False
        p["serial"] += 1
        save_push(key, p); return
    if cmd == "revoke":
        p["revoked"] = True; p["serial"] += 1; save_push(key, p); return
    if cmd == "restore":
        p["revoked"] = False; p["serial"] += 1; save_push(key, p); return
    print("未知命令：", cmd)


if __name__ == "__main__":
    main()
