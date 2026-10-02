# -*- coding: utf-8 -*-
"""Herramienta privada para emitir, revocar y firmar autorizaciones."""
import argparse
import base64
import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seguridad_licencia import hash_licencia, json_canonico


def ahora_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def cargar_json(ruta, defecto):
    try:
        return json.loads(Path(ruta).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return defecto


def guardar_json(ruta, datos):
    Path(ruta).write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")


def cargar_privada(ruta):
    clave = serialization.load_pem_private_key(Path(ruta).read_bytes(), password=None)
    if not isinstance(clave, Ed25519PrivateKey):
        raise ValueError("La clave privada no es Ed25519")
    return clave


def firmar(payload_path, output_path, private_path):
    payload = cargar_json(payload_path, {"schema": 1, "licenses": {}})
    payload["schema"] = 1
    payload["generated_at"] = ahora_iso()
    guardar_json(payload_path, payload)
    firma = cargar_privada(private_path).sign(json_canonico(payload))
    guardar_json(output_path, {
        "payload": payload,
        "signature": base64.b64encode(firma).decode("ascii"),
    })


def comando_init(args):
    privada = Ed25519PrivateKey.generate()
    Path(args.private_key).write_bytes(privada.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    Path(args.public_key).write_bytes(privada.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    guardar_json(args.payload, {"schema": 1, "generated_at": ahora_iso(), "licenses": {}})
    guardar_json(args.private_registry, {"licenses": {}})
    firmar(args.payload, args.output, args.private_key)
    print("Claves y manifiesto inicial creados. Protege la clave privada.")


def comando_autorizar(args):
    payload = cargar_json(args.payload, {"schema": 1, "licenses": {}})
    registro = cargar_json(args.private_registry, {"licenses": {}})
    license_id = args.license_id or secrets.token_urlsafe(24)
    clave_hash = hash_licencia(license_id)
    expira = datetime.now(timezone.utc) + timedelta(days=max(1, args.days))
    payload.setdefault("licenses", {})[clave_hash] = {
        "machine_hash": args.machine_hash.strip().lower(),
        "status": "ACTIVE",
        "expires_at": expira.isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    registro.setdefault("licenses", {})[clave_hash] = {
        "name": args.name,
        "license_id": license_id,
        "machine_hash": args.machine_hash.strip().lower(),
        "status": "ACTIVE",
    }
    guardar_json(args.payload, payload)
    guardar_json(args.private_registry, registro)
    firmar(args.payload, args.output, args.private_key)
    destino = Path(args.issued_dir)
    destino.mkdir(parents=True, exist_ok=True)
    seguro = re.sub(r"[^A-Za-z0-9_-]+", "_", args.name).strip("_") or "usuario"
    archivo = destino / f"licencia_{seguro}.json"
    guardar_json(archivo, {"license_id": license_id, "name": args.name})
    print(f"Licencia emitida: {archivo}")
    print(f"ID corto: {license_id[:8]}... | vence: {expira.date()}")


def comando_revocar(args):
    payload = cargar_json(args.payload, {"schema": 1, "licenses": {}})
    registro = cargar_json(args.private_registry, {"licenses": {}})
    clave_hash = hash_licencia(args.license_id)
    entrada = payload.setdefault("licenses", {}).get(clave_hash)
    if entrada is None:
        raise SystemExit("Licencia no encontrada")
    entrada["status"] = "REVOKED"
    if clave_hash in registro.get("licenses", {}):
        registro["licenses"][clave_hash]["status"] = "REVOKED"
    guardar_json(args.payload, payload)
    guardar_json(args.private_registry, registro)
    firmar(args.payload, args.output, args.private_key)
    print("Licencia revocada y manifiesto actualizado")


def argumentos():
    p = argparse.ArgumentParser(description="Administración privada de licencias")
    p.add_argument("--private-key", default="clave_privada.pem")
    p.add_argument("--public-key", default="clave_publica.pem")
    p.add_argument("--payload", default="autorizaciones_payload.json")
    p.add_argument("--output", default="autorizaciones.json")
    p.add_argument("--private-registry", default="registro_privado.json")
    p.add_argument("--issued-dir", default="licencias_emitidas")
    sub = p.add_subparsers(dest="comando", required=True)
    sub.add_parser("init")
    a = sub.add_parser("authorize")
    a.add_argument("--name", required=True)
    a.add_argument("--machine-hash", required=True)
    a.add_argument("--days", type=int, default=30)
    a.add_argument("--license-id")
    r = sub.add_parser("revoke")
    r.add_argument("--license-id", required=True)
    sub.add_parser("sign")
    return p.parse_args()


def main():
    args = argumentos()
    if args.comando == "init":
        comando_init(args)
    elif args.comando == "authorize":
        comando_autorizar(args)
    elif args.comando == "revoke":
        comando_revocar(args)
    else:
        firmar(args.payload, args.output, args.private_key)
        print("Manifiesto firmado")


if __name__ == "__main__":
    main()

