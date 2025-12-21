#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from hashlib import pbkdf2_hmac
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

COMPONENT = bytes([49, 243, 9, 115, 214, 175, 91, 184, 211, 190, 177, 88, 101, 131, 192, 119])


def strip_json5(text: str) -> str:
    out = []
    in_str = None
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in ("\"", "'"):
            in_str = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < len(text) and text[i] not in ("\r", "\n"):
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
                continue
        out.append(ch)
        i += 1
    text = "".join(out)
    return re.sub(r",\s*([}\]])", r"\1", text)


def load_json5(path: Path) -> dict:
    data = path.read_text(encoding="utf-8")
    return json.loads(strip_json5(data))


def resolve_path(path_str: str, base_dir: Path) -> Path:
    p = Path(path_str)
    return p if p.is_absolute() else (base_dir / p).resolve()


def find_bundle_name_from_obj(obj):
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("bundleName"), str):
        return obj["bundleName"]
    if isinstance(obj.get("bundle-name"), str):
        return obj["bundle-name"]
    app = obj.get("app")
    if isinstance(app, dict):
        if isinstance(app.get("bundleName"), str):
            return app["bundleName"]
        if isinstance(app.get("bundle-name"), str):
            return app["bundle-name"]
    return None


def get_bundle_name_from_hap(hap_path: Path) -> str:
    with zipfile.ZipFile(hap_path, "r") as zf:
        names = zf.namelist()
        candidates = [
            n for n in names
            if n.endswith(("module.json", "module.json5", "config.json", "app.json", "app.json5"))
        ]
        for name in candidates:
            try:
                raw = zf.read(name).decode("utf-8", errors="replace")
                obj = json.loads(strip_json5(raw))
            except Exception:
                continue
            bundle = find_bundle_name_from_obj(obj)
            if bundle:
                return bundle
    raise SystemExit("Failed to find bundleName in HAP.")


def _read_single_file_bytes(dir_path: Path) -> bytes:
    files = [p for p in dir_path.iterdir() if p.name != ".DS_Store" and p.is_file()]
    if len(files) != 1:
        raise SystemExit(f"Expected exactly 1 file in {dir_path}, found {len(files)}.")
    return files[0].read_bytes()


def _decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) < 4 + 16:
        raise SystemExit("Encrypted material is too short.")
    r = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
    iv_len = len(data) - 4 - r
    iv = data[4:4 + iv_len]
    ct = data[4 + iv_len:-16]
    tag = data[-16:]
    return AESGCM(key).decrypt(iv, ct + tag, None)


def _get_key(material_root: Path) -> bytes:
    material_dir = material_root / "material"
    fd_dir = material_dir / "fd"
    ac_dir = material_dir / "ac"
    ce_dir = material_dir / "ce"

    if not fd_dir.is_dir() or not ac_dir.is_dir() or not ce_dir.is_dir():
        raise SystemExit(f"Missing signing material under {material_dir}.")

    fd_parts = []
    for name in os.listdir(fd_dir):
        if name == ".DS_Store":
            continue
        sub = fd_dir / name
        if not sub.is_dir():
            continue
        fd_parts.append(_read_single_file_bytes(sub))

    salt = _read_single_file_bytes(ac_dir)
    work = _read_single_file_bytes(ce_dir)

    if not fd_parts:
        raise SystemExit(f"No fd material found under {fd_dir}.")

    xor_bytes = bytearray(fd_parts[0])
    for comp in fd_parts[1:] + [COMPONENT]:
        if len(comp) != 16:
            raise SystemExit("Signing material component length mismatch.")
        for i in range(16):
            xor_bytes[i] ^= comp[i]

    # Node's Buffer.toString() uses UTF-8 with replacement for invalid bytes.
    pwd_str = bytes(xor_bytes).decode("utf-8", errors="replace")
    root_key = pbkdf2_hmac("sha256", pwd_str.encode("utf-8"), salt, 10000, dklen=16)
    return _decrypt(root_key, work)


def decrypt_pwd(material_root: Path, encrypted_hex: str) -> str:
    key = _get_key(material_root)
    data = bytes.fromhex(encrypted_hex)
    return _decrypt(key, data).decode("utf-8")


def find_deveco_home(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    candidates = [
        os.environ.get("DEVECO_STUDIO_HOME"),
        os.environ.get("DEVECO_HOME"),
        r"D:\Huawei\DevEco Studio",
        r"C:\Huawei\DevEco Studio",
        r"C:\Program Files\Huawei\DevEco Studio",
        r"C:\Program Files (x86)\Huawei\DevEco Studio",
    ]
    for c in candidates:
        if not c:
            continue
        p = Path(c)
        if p.exists():
            return p
    return None


def find_java(deveco_home: Path | None, explicit: str | None) -> str:
    if explicit:
        return explicit
    if deveco_home:
        java_path = deveco_home / "jbr" / "bin" / "java.exe"
        if java_path.exists():
            return str(java_path)
    return "java"


def find_sign_tool(deveco_home: Path | None, explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if p.exists():
            return p
        raise SystemExit(f"sign tool not found: {explicit}")
    if not deveco_home:
        raise SystemExit("DevEco Studio home not found; pass --deveco-home or --sign-tool.")
    p = deveco_home / "sdk" / "default" / "openharmony" / "toolchains" / "lib" / "hap-sign-tool.jar"
    if p.exists():
        return p
    raise SystemExit("hap-sign-tool.jar not found; pass --sign-tool.")


def get_bundle_name_from_p7b(java: str, sign_tool: Path, p7b_path: Path) -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        out_json = Path(tmpdir) / "signConfigCheckJson.json"
        cmd = [
            java,
            "-jar",
            str(sign_tool),
            "verify-profile",
            "-inFile",
            str(p7b_path),
            "-outFile",
            str(out_json),
        ]
        subprocess.run(cmd, check=True)
        data = json.loads(out_json.read_text(encoding="utf-8"))
        return data["content"]["bundle-info"]["bundle-name"]


def pick_signing_config(profile: dict, product: str | None, name: str | None) -> dict:
    app = profile.get("app", {})
    signing_configs = app.get("signingConfigs", [])
    by_name = {c.get("name"): c for c in signing_configs if c.get("name")}

    if name:
        if name not in by_name:
            raise SystemExit(f"Signing config not found: {name}")
        return by_name[name]

    products = app.get("products", [])
    if product:
        prod = next((p for p in products if p.get("name") == product), None)
    else:
        prod = products[0] if products else None
    if prod and prod.get("signingConfig") in by_name:
        return by_name[prod["signingConfig"]]

    if len(signing_configs) == 1:
        return signing_configs[0]

    raise SystemExit("Unable to choose a signing config; pass --signing-config.")


def has_signing_configs(profile: dict) -> bool:
    app = profile.get("app")
    if not isinstance(app, dict):
        return False
    signing_configs = app.get("signingConfigs")
    return isinstance(signing_configs, list) and len(signing_configs) > 0


def find_parent_app_build_profile(start: Path) -> Path | None:
    cur = start.resolve()
    while True:
        candidate = cur / "build-profile.json5"
        if candidate.exists():
            try:
                obj = load_json5(candidate)
            except Exception:
                obj = None
            if isinstance(obj, dict) and has_signing_configs(obj):
                return candidate
        if cur.parent == cur:
            return None
        cur = cur.parent


def build_sign_command(java: str, sign_tool: Path, material: dict, hap_path: Path, out_path: Path) -> list[str]:
    cmd = [
        java,
        "-jar",
        str(sign_tool),
        "sign-app",
        "-mode",
        "localSign",
        "-keyAlias",
        material["keyAlias"],
        "-keyPwd",
        material["keyPassword"],
        "-keystoreFile",
        str(material["storeFile"]),
        "-keystorePwd",
        material["storePassword"],
        "-appCertFile",
        str(material["certpath"]),
        "-profileFile",
        str(material["profile"]),
        "-profileSigned",
        "1",
    ]
    sign_alg = material.get("signAlg") or ""
    if sign_alg:
        cmd += ["-signAlg", sign_alg]
    cmd += [
        "-inFile",
        str(hap_path),
        "-outFile",
        str(out_path),
    ]
    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(description="Auto sign an unsigned HAP using DevEco signing config.")
    parser.add_argument("--hap", required=True, help="Path to the unsigned .hap file")
    parser.add_argument("--out", help="Output .hap path (default: add -signed)")
    parser.add_argument("--build-profile", help="Path to build-profile.json5 (default: ./build-profile.json5)")
    parser.add_argument("--product", help="Product name in build-profile (default: first)")
    parser.add_argument("--signing-config", help="Signing config name in build-profile")
    parser.add_argument("--deveco-home", help="DevEco Studio install dir")
    parser.add_argument("--java", help="Java executable path")
    parser.add_argument("--sign-tool", help="hap-sign-tool.jar path")
    parser.add_argument("--skip-bundle-check", action="store_true", help="Skip bundleName match check")
    args = parser.parse_args()

    hap_path = Path(args.hap).resolve()
    if not hap_path.exists():
        raise SystemExit(f"HAP not found: {hap_path}")

    profile_path = Path(args.build_profile or "build-profile.json5").resolve()
    if not profile_path.exists():
        raise SystemExit(f"build-profile.json5 not found: {profile_path}")

    profile = load_json5(profile_path)
    if not has_signing_configs(profile):
        parent_profile = find_parent_app_build_profile(profile_path.parent)
        if parent_profile and parent_profile != profile_path:
            print(
                f"Note: {profile_path} has no signingConfigs; using {parent_profile} instead.",
                file=sys.stderr,
            )
            profile_path = parent_profile
            profile = load_json5(profile_path)
    signing_config = pick_signing_config(profile, args.product, args.signing_config)

    material = dict(signing_config.get("material") or {})
    required = ["storeFile", "storePassword", "keyAlias", "keyPassword", "profile", "certpath"]
    missing = [k for k in required if not material.get(k)]
    if missing:
        raise SystemExit(f"Missing signing material fields: {', '.join(missing)}")

    base_dir = profile_path.parent
    material["storeFile"] = resolve_path(material["storeFile"], base_dir)
    material["profile"] = resolve_path(material["profile"], base_dir)
    material["certpath"] = resolve_path(material["certpath"], base_dir)

    if not material["storeFile"].exists():
        raise SystemExit(f"storeFile not found: {material['storeFile']}")
    if not material["profile"].exists():
        raise SystemExit(f"profile not found: {material['profile']}")
    if not material["certpath"].exists():
        raise SystemExit(f"certpath not found: {material['certpath']}")

    material_root = material["storeFile"].parent
    material["storePassword"] = decrypt_pwd(material_root, material["storePassword"])
    material["keyPassword"] = decrypt_pwd(material_root, material["keyPassword"])

    deveco_home = find_deveco_home(args.deveco_home)
    java = find_java(deveco_home, args.java)
    sign_tool = find_sign_tool(deveco_home, args.sign_tool)

    if not args.skip_bundle_check:
        bundle_hap = get_bundle_name_from_hap(hap_path)
        bundle_profile = get_bundle_name_from_p7b(java, sign_tool, material["profile"])
        if bundle_hap != bundle_profile:
            raise SystemExit(
                f"bundleName mismatch: hap={bundle_hap} profile={bundle_profile}. "
                "Use --skip-bundle-check to override."
            )

    out_path = Path(args.out).resolve() if args.out else hap_path.with_name(hap_path.stem + "-signed.hap")
    cmd = build_sign_command(java, sign_tool, material, hap_path, out_path)
    subprocess.run(cmd, check=True)
    print(f"Signed HAP: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
