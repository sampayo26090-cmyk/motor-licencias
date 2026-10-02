# -*- coding: utf-8 -*-
"""Licencia obligatoria en línea con manifiesto Ed25519 firmado.

El cliente nunca contiene la clave privada ni credenciales de GitHub. Descarga
un manifiesto público, verifica su firma y compara licencia + equipo + estado.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION_SEGURIDAD = "R31-licencia-online-ed25519"


class LicenciaError(RuntimeError):
    pass


def directorio_aplicacion() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _machine_guid_windows() -> str:
    if os.name != "nt":
        return ""
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
        ) as clave:
            return str(winreg.QueryValueEx(clave, "MachineGuid")[0])
    except (OSError, AttributeError):
        return ""


def huella_equipo() -> str:
    """Huella estable; nunca envía los identificadores originales."""
    piezas = (
        _machine_guid_windows(),
        platform.node(),
        platform.machine(),
        str(uuid.getnode()),
    )
    material = "|".join(str(x).strip().upper() for x in piezas if str(x).strip())
    if not material:
        raise LicenciaError("No fue posible identificar esta computadora")
    return hashlib.sha256(("SPINS-R31|" + material).encode("utf-8")).hexdigest()


def hash_licencia(license_id: str) -> str:
    return hashlib.sha256(str(license_id).strip().encode("utf-8")).hexdigest()


def json_canonico(datos) -> bytes:
    return json.dumps(
        datos, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _parse_iso_utc(valor: str) -> datetime:
    texto = str(valor).strip().replace("Z", "+00:00")
    fecha = datetime.fromisoformat(texto)
    if fecha.tzinfo is None:
        fecha = fecha.replace(tzinfo=timezone.utc)
    return fecha.astimezone(timezone.utc)


class GestorLicenciaOnline:
    def __init__(self, config_path=None, licencia_path=None):
        base = directorio_aplicacion()
        self.config_path = Path(config_path or base / "licencia_config.json")
        self.licencia_path = Path(licencia_path or base / "licencia.json")
        try:
            self.config = json.loads(self.config_path.read_text(encoding="utf-8"))
            self.licencia = json.loads(self.licencia_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise LicenciaError(f"Falta archivo obligatorio: {Path(exc.filename).name}") from exc
        except (OSError, ValueError, TypeError) as exc:
            raise LicenciaError(f"Configuración de licencia inválida: {exc}") from exc

        self.endpoint = str(self.config.get("endpoint", "")).strip()
        clave_configurada = Path(str(
            self.config.get("public_key", "clave_publica.pem")
        ))
        self.public_key_path = (
            clave_configurada if clave_configurada.is_absolute()
            else self.config_path.resolve().parent / clave_configurada
        )
        self.intervalo = max(30, int(self.config.get("check_interval_seconds", 60)))
        self.gracia = max(0, int(self.config.get("network_grace_seconds", 120)))
        self.timeout = max(2, int(self.config.get("timeout_seconds", 8)))
        self.allow_http_localhost = self.config.get("allow_http_localhost", False) is True
        self.license_id = str(self.licencia.get("license_id", "")).strip()
        if not self.endpoint or not self.license_id:
            raise LicenciaError("Endpoint o license_id ausente")
        parsed = urllib.parse.urlparse(self.endpoint)
        if parsed.scheme != "https" and not (
            self.allow_http_localhost
            and parsed.scheme == "http"
            and parsed.hostname in ("127.0.0.1", "localhost")
        ):
            raise LicenciaError("El endpoint debe utilizar HTTPS")
        try:
            clave = serialization.load_pem_public_key(
                self.public_key_path.read_bytes()
            )
        except (OSError, ValueError, TypeError) as exc:
            raise LicenciaError("Clave pública ausente o inválida") from exc
        if not isinstance(clave, Ed25519PublicKey):
            raise LicenciaError("La clave pública no es Ed25519")
        self.public_key = clave
        self.machine_hash = huella_equipo()
        self._lock = threading.RLock()
        self._permitida = False
        self._motivo = "Licencia aún no verificada"
        self._ultimo_exito = None
        self._detener = threading.Event()
        self._hilo = None

    def _descargar(self):
        separador = "&" if "?" in self.endpoint else "?"
        url = f"{self.endpoint}{separador}nocache={int(time.time())}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SpinsMotorLicense/1.0",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as respuesta:
            cuerpo = respuesta.read(2_000_000)
            fecha_http = respuesta.headers.get("Date")
        try:
            ahora_servidor = parsedate_to_datetime(fecha_http).astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            ahora_servidor = datetime.now(timezone.utc)
        return json.loads(cuerpo.decode("utf-8-sig")), ahora_servidor

    def _validar_manifiesto(self, envoltura, ahora_servidor):
        if not isinstance(envoltura, dict):
            raise LicenciaError("Respuesta de autorización inválida")
        payload = envoltura.get("payload")
        firma_texto = envoltura.get("signature")
        if not isinstance(payload, dict) or not isinstance(firma_texto, str):
            raise LicenciaError("Manifiesto incompleto")
        try:
            firma = base64.b64decode(firma_texto, validate=True)
            self.public_key.verify(firma, json_canonico(payload))
        except (ValueError, InvalidSignature) as exc:
            raise LicenciaError("Firma de autorizaciones inválida") from exc
        if payload.get("schema") != 1:
            raise LicenciaError("Versión de autorizaciones no compatible")
        entradas = payload.get("licenses")
        if not isinstance(entradas, dict):
            raise LicenciaError("Lista de autorizaciones inválida")
        entrada = entradas.get(hash_licencia(self.license_id))
        if not isinstance(entrada, dict):
            raise LicenciaError("Licencia fuera de la lista autorizada")
        estado = str(entrada.get("status", "")).upper()
        if estado != "ACTIVE":
            raise LicenciaError(f"Licencia {estado or 'REVOCADA'}")
        if str(entrada.get("machine_hash", "")) != self.machine_hash:
            raise LicenciaError("Licencia registrada para otra computadora")
        vence = entrada.get("expires_at")
        if vence and ahora_servidor > _parse_iso_utc(vence):
            raise LicenciaError("Licencia vencida")
        return entrada

    def comprobar_ahora(self, inicial=False):
        try:
            manifiesto, fecha_servidor = self._descargar()
            entrada = self._validar_manifiesto(manifiesto, fecha_servidor)
        except Exception as exc:
            error = exc if isinstance(exc, LicenciaError) else LicenciaError(
                f"No fue posible consultar la autorización: {exc}"
            )
            with self._lock:
                # Revocación/firma/equipo incorrecto bloquean inmediatamente.
                es_red = not isinstance(exc, LicenciaError) or str(error).startswith(
                    "No fue posible consultar"
                )
                dentro_gracia = (
                    es_red and not inicial and self._ultimo_exito is not None
                    and time.monotonic() - self._ultimo_exito <= self.gracia
                )
                if dentro_gracia:
                    self._motivo = f"Conexión perdida; gracia temporal ({self.gracia}s)"
                    return True
                self._permitida = False
                self._motivo = str(error)
            if inicial:
                raise error
            return False
        with self._lock:
            self._permitida = True
            self._ultimo_exito = time.monotonic()
            self._motivo = (
                f"Licencia activa hasta {entrada.get('expires_at') or 'sin vencimiento'}"
            )
        return True

    def verificar_inicio(self):
        self.comprobar_ahora(inicial=True)
        return True

    def _monitor(self):
        while not self._detener.wait(self.intervalo):
            self.comprobar_ahora(inicial=False)

    def iniciar_monitor(self):
        if self._hilo and self._hilo.is_alive():
            return
        self._hilo = threading.Thread(
            target=self._monitor, name="licencia-online", daemon=True
        )
        self._hilo.start()

    def detener(self):
        self._detener.set()

    @property
    def permitida(self):
        with self._lock:
            return bool(self._permitida)

    @property
    def motivo(self):
        with self._lock:
            return str(self._motivo)


def seguridad_es_obligatoria(config_path=None):
    ruta = Path(config_path or directorio_aplicacion() / "licencia_config.json")
    return bool(getattr(sys, "frozen", False) or ruta.exists())


def iniciar_seguridad(config_path=None, licencia_path=None):
    if not seguridad_es_obligatoria(config_path):
        print(f"[SEGURIDAD] {VERSION_SEGURIDAD}: modo fuente del propietario")
        return None
    gestor = GestorLicenciaOnline(config_path, licencia_path)
    gestor.verificar_inicio()
    gestor.iniciar_monitor()
    print(f"[SEGURIDAD] {VERSION_SEGURIDAD}: {gestor.motivo}")
    return gestor
