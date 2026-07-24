#!/usr/bin/env python3
"""Small standard-library client used by automatic Remem Memory hooks."""

from __future__ import annotations

import ctypes
import json
import os
import ssl
import sys
import threading
from collections.abc import Callable, Mapping, MutableMapping
from contextlib import contextmanager
from typing import Any, Iterator, Optional, Protocol, Tuple
from urllib import parse as urllib_parse
from urllib import request as urllib_request

_DEFAULT_API_URL = "https://api.remem.io"
_PRODUCTION_API_HOST = "api.remem.io"
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
KEYCHAIN_SERVICE = "io.remem.memory"
KEYCHAIN_ACCOUNT = "default"
_ERR_SEC_ITEM_NOT_FOUND = -25300
_MAX_QUERY = 2000
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_CREDENTIAL_BYTES = 16 * 1024
_KEYCHAIN_INTERACTION_LOCK = threading.RLock()


class RememAPIError(RuntimeError):
    """Fixed, non-secret API failure safe for fail-open hook handling."""


class RememCredentialUnavailable(RememAPIError):
    """No supported Remem credential could be resolved."""


class RememKeychainError(RememAPIError):
    """A fixed, non-secret macOS Keychain failure."""


class Keychain(Protocol):
    """Minimal injectable credential adapter used by setup and runtime."""

    def read(self, service: str, account: Optional[str] = None) -> Optional[str]:
        ...

    def write(self, service: str, account: str, value: str) -> None:
        ...


class _NoRedirectHandler(urllib_request.HTTPRedirectHandler):
    """Reject redirects so credentials never cross an origin boundary."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _system_tls_context() -> ssl.SSLContext:
    """Build verified TLS from compiled system paths, never CA env overrides."""

    defaults = ssl.get_default_verify_paths()
    cafile = (
        defaults.openssl_cafile
        if defaults.openssl_cafile
        and os.path.isfile(defaults.openssl_cafile)
        else None
    )
    capath = (
        defaults.openssl_capath
        if defaults.openssl_capath
        and os.path.isdir(defaults.openssl_capath)
        else None
    )
    if cafile is None and capath is None:
        raise RememAPIError("System TLS trust store unavailable")
    try:
        return ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=cafile,
            capath=capath,
        )
    except Exception:
        raise RememAPIError("System TLS trust store unavailable") from None


def _enabled(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.strip().lower() in {"1", "true", "yes", "on"}
    )


def _has_explicit_credential(
    environment: Mapping[str, str],
) -> bool:
    explicit = environment.get("REMEM_API_KEY", "")
    return isinstance(explicit, str) and bool(explicit.strip())


def normalize_api_origin(
    value: str,
    *,
    allow_local_dev: bool = False,
) -> str:
    """Allow production, or an explicitly enabled loopback development origin."""

    try:
        parsed = urllib_parse.urlsplit(value.strip())
        hostname = parsed.hostname
        parsed.port
    except (TypeError, ValueError):
        raise RememAPIError("Invalid Remem API URL") from None
    common_invalid = (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or bool(parsed.query)
        or bool(parsed.fragment)
    )
    production = (
        parsed.scheme == "https"
        and hostname == _PRODUCTION_API_HOST
        and parsed.port is None
    )
    loopback = (
        allow_local_dev
        and hostname in _LOOPBACK_HOSTS
        and parsed.scheme in {"http", "https"}
    )
    if common_invalid or not (production or loopback):
        raise RememAPIError("Invalid Remem API URL")
    return value.strip().rstrip("/")


def normalize_api_origin_for_environment(
    value: str,
    environment: Optional[Mapping[str, str]] = None,
) -> str:
    """Apply the source-aware origin policy without reading a credential."""

    selected = os.environ if environment is None else environment
    allow_local_dev = (
        _has_explicit_credential(selected)
        and _enabled(selected.get("REMEM_MEMORY_ALLOW_LOCAL_DEV"))
    )
    return normalize_api_origin(
        value,
        allow_local_dev=allow_local_dev,
    )


# Private compatibility alias for older callers and focused tests.
_normalize_origin = normalize_api_origin


def _load_frameworks() -> Tuple[Any, Any]:
    """Load macOS frameworks only when a Keychain operation is requested."""

    if sys.platform != "darwin":
        raise RememKeychainError("Remem Keychain is unavailable")
    try:
        security = ctypes.CDLL(
            "/System/Library/Frameworks/Security.framework/Security"
        )
        core_foundation = ctypes.CDLL(
            (
                "/System/Library/Frameworks/CoreFoundation.framework/"
                "CoreFoundation"
            )
        )
    except Exception:
        raise RememKeychainError("Remem Keychain is unavailable") from None
    return security, core_foundation


class MacOSKeychain:
    """Lazy typed binding for macOS generic-password Keychain items."""

    def __init__(
        self,
        *,
        security: Optional[Any] = None,
        core_foundation: Optional[Any] = None,
        framework_loader: Optional[Callable[[], Tuple[Any, Any]]] = None,
    ) -> None:
        if (security is None) != (core_foundation is None):
            raise RememKeychainError("Remem Keychain is unavailable")
        self._security = security
        self._core_foundation = core_foundation
        self._framework_loader = framework_loader or _load_frameworks
        self._declared = False

    def read(
        self,
        service: str,
        account: Optional[str] = None,
    ) -> Optional[str]:
        """Read one generic password and release all returned allocations."""

        with self._without_user_interaction():
            try:
                status, length, password_data, item = self._find(
                    service,
                    account,
                )
            except RememKeychainError:
                raise
            except Exception:
                raise RememKeychainError(
                    "Remem credential lookup failed"
                ) from None
            try:
                if status == _ERR_SEC_ITEM_NOT_FOUND:
                    return None
                if status != 0:
                    raise RememKeychainError(
                        "Remem credential lookup failed"
                    )
                try:
                    raw_value = ctypes.string_at(password_data, length)
                    return raw_value.decode("utf-8")
                except Exception:
                    raise RememKeychainError(
                        "Remem credential lookup failed"
                    ) from None
            finally:
                self._cleanup(
                    password_data,
                    item,
                    "Remem credential lookup failed"
                )

    def write(self, service: str, account: str, value: str) -> None:
        """Add or update one generic password without invoking a subprocess."""

        with _KEYCHAIN_INTERACTION_LOCK:
            self._write_interactive(service, account, value)

    def _write_interactive(
        self,
        service: str,
        account: str,
        value: str,
    ) -> None:
        encoded_value = self._encode_secret(value)
        try:
            status, _length, password_data, item = self._find(
                service,
                account,
            )
        except RememKeychainError:
            raise RememKeychainError(
                "Remem credential storage failed"
            ) from None
        except Exception:
            raise RememKeychainError(
                "Remem credential storage failed"
            ) from None

        if status == _ERR_SEC_ITEM_NOT_FOUND:
            self._cleanup(
                password_data,
                item,
                "Remem credential storage failed",
            )
            self._add(service, account, encoded_value)
            return

        try:
            if status != 0:
                raise RememKeychainError(
                    "Remem credential storage failed"
                )
            security, _core_foundation = self._frameworks()
            modify_status = int(
                security.SecKeychainItemModifyContent(
                    item,
                    None,
                    len(encoded_value),
                    ctypes.c_char_p(encoded_value),
                )
            )
            if modify_status != 0:
                raise RememKeychainError(
                    "Remem credential storage failed"
                )
        except RememKeychainError:
            raise
        except Exception:
            raise RememKeychainError(
                "Remem credential storage failed"
            ) from None
        finally:
            self._cleanup(
                password_data,
                item,
                "Remem credential storage failed",
            )

    def _frameworks(self) -> Tuple[Any, Any]:
        if self._security is None or self._core_foundation is None:
            try:
                self._security, self._core_foundation = (
                    self._framework_loader()
                )
            except RememKeychainError:
                raise
            except Exception:
                raise RememKeychainError(
                    "Remem Keychain is unavailable"
                ) from None
        if not self._declared:
            try:
                self._declare_functions(
                    self._security,
                    self._core_foundation,
                )
            except Exception:
                raise RememKeychainError(
                    "Remem Keychain is unavailable"
                ) from None
            self._declared = True
        return self._security, self._core_foundation

    @staticmethod
    def _declare_functions(security: Any, core_foundation: Any) -> None:
        void_pointer = ctypes.c_void_p
        uint32 = ctypes.c_uint32
        boolean = ctypes.c_ubyte
        os_status = ctypes.c_int32

        security.SecKeychainGetUserInteractionAllowed.argtypes = [
            ctypes.POINTER(boolean),
        ]
        security.SecKeychainGetUserInteractionAllowed.restype = os_status

        security.SecKeychainSetUserInteractionAllowed.argtypes = [
            boolean,
        ]
        security.SecKeychainSetUserInteractionAllowed.restype = os_status

        security.SecKeychainFindGenericPassword.argtypes = [
            void_pointer,
            uint32,
            ctypes.c_char_p,
            uint32,
            ctypes.c_char_p,
            ctypes.POINTER(uint32),
            ctypes.POINTER(void_pointer),
            ctypes.POINTER(void_pointer),
        ]
        security.SecKeychainFindGenericPassword.restype = os_status

        security.SecKeychainAddGenericPassword.argtypes = [
            void_pointer,
            uint32,
            ctypes.c_char_p,
            uint32,
            ctypes.c_char_p,
            uint32,
            void_pointer,
            ctypes.POINTER(void_pointer),
        ]
        security.SecKeychainAddGenericPassword.restype = os_status

        security.SecKeychainItemModifyContent.argtypes = [
            void_pointer,
            void_pointer,
            uint32,
            void_pointer,
        ]
        security.SecKeychainItemModifyContent.restype = os_status

        security.SecKeychainItemFreeContent.argtypes = [
            void_pointer,
            void_pointer,
        ]
        security.SecKeychainItemFreeContent.restype = os_status

        core_foundation.CFRelease.argtypes = [void_pointer]
        core_foundation.CFRelease.restype = None

    @contextmanager
    def _without_user_interaction(self) -> Iterator[None]:
        security, _core_foundation = self._frameworks()
        previous = ctypes.c_ubyte()
        with _KEYCHAIN_INTERACTION_LOCK:
            try:
                get_status = int(
                    security.SecKeychainGetUserInteractionAllowed(
                        ctypes.byref(previous)
                    )
                )
            except Exception:
                raise RememKeychainError(
                    "Remem credential lookup failed"
                ) from None
            if get_status != 0:
                raise RememKeychainError(
                    "Remem credential lookup failed"
                )
            try:
                set_status = int(
                    security.SecKeychainSetUserInteractionAllowed(
                        ctypes.c_ubyte(0)
                    )
                )
            except Exception:
                raise RememKeychainError(
                    "Remem credential lookup failed"
                ) from None
            if set_status != 0:
                raise RememKeychainError(
                    "Remem credential lookup failed"
                )
            try:
                yield
            finally:
                try:
                    restore_status = int(
                        security.SecKeychainSetUserInteractionAllowed(
                            previous
                        )
                    )
                except Exception:
                    raise RememKeychainError(
                        "Remem credential lookup failed"
                    ) from None
                if restore_status != 0:
                    raise RememKeychainError(
                        "Remem credential lookup failed"
                    )

    @staticmethod
    def _encode_name(value: str, *, optional: bool = False) -> Optional[bytes]:
        if optional and value is None:
            return None
        if (
            not isinstance(value, str)
            or not value
            or "\x00" in value
        ):
            raise RememKeychainError("Remem Keychain is unavailable")
        try:
            return value.encode("utf-8")
        except UnicodeEncodeError:
            raise RememKeychainError(
                "Remem Keychain is unavailable"
            ) from None

    @staticmethod
    def _encode_secret(value: str) -> bytes:
        if (
            not isinstance(value, str)
            or not value
            or "\x00" in value
        ):
            raise RememKeychainError(
                "Remem credential storage failed"
            )
        try:
            return value.encode("utf-8")
        except UnicodeEncodeError:
            raise RememKeychainError(
                "Remem credential storage failed"
            ) from None

    def _find(
        self,
        service: str,
        account: Optional[str],
    ) -> Tuple[int, int, ctypes.c_void_p, ctypes.c_void_p]:
        security, _core_foundation = self._frameworks()
        service_bytes = self._encode_name(service)
        account_bytes = self._encode_name(account, optional=True)
        password_length = ctypes.c_uint32()
        password_data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = int(
            security.SecKeychainFindGenericPassword(
                None,
                len(service_bytes or b""),
                service_bytes,
                len(account_bytes or b""),
                account_bytes,
                ctypes.byref(password_length),
                ctypes.byref(password_data),
                ctypes.byref(item),
            )
        )
        return (
            status,
            int(password_length.value),
            password_data,
            item,
        )

    def _add(
        self,
        service: str,
        account: str,
        encoded_value: bytes,
    ) -> None:
        security, core_foundation = self._frameworks()
        service_bytes = self._encode_name(service)
        account_bytes = self._encode_name(account)
        item = ctypes.c_void_p()
        try:
            status = int(
                security.SecKeychainAddGenericPassword(
                    None,
                    len(service_bytes or b""),
                    service_bytes,
                    len(account_bytes or b""),
                    account_bytes,
                    len(encoded_value),
                    ctypes.c_char_p(encoded_value),
                    ctypes.byref(item),
                )
            )
            if status != 0:
                raise RememKeychainError(
                    "Remem credential storage failed"
                )
        except RememKeychainError:
            raise
        except Exception:
            raise RememKeychainError(
                "Remem credential storage failed"
            ) from None
        finally:
            if item.value:
                try:
                    core_foundation.CFRelease(item)
                except Exception:
                    raise RememKeychainError(
                        "Remem credential storage failed"
                    ) from None

    def _cleanup(
        self,
        password_data: ctypes.c_void_p,
        item: ctypes.c_void_p,
        error_message: str,
    ) -> None:
        security, core_foundation = self._frameworks()
        failed = False
        try:
            if password_data.value:
                try:
                    status = int(
                        security.SecKeychainItemFreeContent(
                            None,
                            password_data,
                        )
                    )
                    failed = status != 0
                except Exception:
                    failed = True
        finally:
            if item.value:
                try:
                    core_foundation.CFRelease(item)
                except Exception:
                    failed = True
        if failed:
            raise RememKeychainError(error_message)

    def __repr__(self) -> str:
        return "MacOSKeychain(service='io.remem.memory')"


def default_keychain() -> MacOSKeychain:
    """Return a lazy default adapter without touching Keychain at import time."""

    return MacOSKeychain()


def resolve_api_key(
    environment: Optional[Mapping[str, str]] = None,
    keychain: Optional[Keychain] = None,
) -> Optional[str]:
    """Resolve the one Remem key without logging or persisting its value."""

    selected_environment = os.environ if environment is None else environment
    explicit = consume_explicit_api_key(selected_environment)
    if explicit:
        return explicit

    selected_keychain = (
        keychain if keychain is not None else default_keychain()
    )
    try:
        current = selected_keychain.read(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
        )
        normalized = current.strip() if isinstance(current, str) else ""
        return normalized or None
    except Exception:
        return None


def consume_explicit_api_key(
    environment: Optional[Mapping[str, str]] = None,
) -> Optional[str]:
    """Consume an environment/anonymous-FD override without Keychain fallback."""

    selected = os.environ if environment is None else environment
    descriptor_value = selected.get("REMEM_API_KEY_FD", "")
    raw_explicit = selected.get("REMEM_API_KEY", "")
    if isinstance(selected, MutableMapping):
        selected.pop("REMEM_API_KEY_FD", None)
        selected.pop("REMEM_API_KEY", None)

    descriptor = -1
    if (
        isinstance(descriptor_value, str)
        and descriptor_value.strip().isdigit()
    ):
        descriptor = int(descriptor_value.strip())
    if descriptor >= 3:
        chunks: list[bytes] = []
        total = 0
        try:
            while total <= _MAX_CREDENTIAL_BYTES:
                chunk = os.read(
                    descriptor,
                    min(
                        4096,
                        _MAX_CREDENTIAL_BYTES + 1 - total,
                    ),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        except OSError:
            chunks = []
            total = 0
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raw = b"".join(chunks)
        if 0 < len(raw) <= _MAX_CREDENTIAL_BYTES and b"\x00" not in raw:
            try:
                credential = raw.decode("utf-8").strip()
            except UnicodeDecodeError:
                credential = ""
            if credential:
                return credential

    explicit = (
        raw_explicit.strip()
        if isinstance(raw_explicit, str)
        else ""
    )
    return explicit or None


def resolve_api_access(
    api_url: str,
    environment: Optional[Mapping[str, str]] = None,
    keychain: Optional[Keychain] = None,
) -> tuple[str, Optional[str]]:
    """Validate the destination before resolving any credential."""

    selected = os.environ if environment is None else environment
    normalized = normalize_api_origin(api_url, allow_local_dev=True)
    explicit = consume_explicit_api_key(selected)
    is_production = normalized == _DEFAULT_API_URL
    if not is_production:
        if not (
            explicit
            and _enabled(selected.get("REMEM_MEMORY_ALLOW_LOCAL_DEV"))
        ):
            raise RememAPIError("Invalid Remem API URL")
        return normalized, explicit
    if explicit:
        return normalized, explicit
    selected_keychain = keychain if keychain is not None else default_keychain()
    try:
        current = selected_keychain.read(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
        )
        normalized_key = (
            current.strip() if isinstance(current, str) else ""
        )
        return normalized, normalized_key or None
    except Exception:
        return normalized, None


def store_api_key(
    value: str,
    keychain: Optional[Keychain] = None,
) -> None:
    """Store the canonical Remem credential with fixed failure diagnostics."""

    normalized = value.strip() if isinstance(value, str) else ""
    if not normalized or "\x00" in normalized:
        raise RememKeychainError("Remem credential storage failed")
    selected_keychain = (
        keychain if keychain is not None else default_keychain()
    )
    try:
        selected_keychain.write(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
            normalized,
        )
    except Exception:
        raise RememKeychainError(
            "Remem credential storage failed"
        ) from None


class RememAPI:
    """A fixed-endpoint Remem API adapter for recall and durable capture."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        opener: Optional[Callable[..., Any]] = None,
        allow_local_dev: bool = False,
    ) -> None:
        selected_url = (
            api_url if isinstance(api_url, str) else os.getenv("REMEM_API_URL")
        )
        explicit_key = api_key.strip() if isinstance(api_key, str) else ""
        self.api_url = normalize_api_origin(
            selected_url or _DEFAULT_API_URL,
            allow_local_dev=bool(allow_local_dev and explicit_key),
        )
        self.api_key = explicit_key or resolve_api_key()
        self._opener = (
            opener
            if opener is not None
            else urllib_request.build_opener(
                urllib_request.ProxyHandler({}),
                urllib_request.HTTPSHandler(
                    context=_system_tls_context(),
                ),
                _NoRedirectHandler(),
            ).open
        )

    def query(
        self,
        prompt: str,
        namespaces: list[str],
        timeout: float,
    ) -> dict[str, Any]:
        """Query up to four fast results from the explicitly selected scope."""

        return self.query_payload(
            {
                "query": prompt[:_MAX_QUERY],
                "mode": "fast",
                "max_results": 4,
                "include_facts": True,
                "namespaces": list(namespaces),
            },
            timeout,
        )

    def query_payload(
        self,
        payload: dict[str, Any],
        timeout: float,
    ) -> dict[str, Any]:
        """Query with a complete caller-built payload."""

        return self._request(
            "/v1/query",
            dict(payload),
            timeout,
        )

    def ingest(
        self,
        payload: dict[str, Any],
        namespace: Optional[str],
        timeout: float,
    ) -> dict[str, Any]:
        """Ingest one document, adding a namespace only when explicitly set."""

        body = dict(payload)
        if isinstance(namespace, str) and namespace.strip():
            body["namespace"] = namespace.strip()
        return self._request("/v1/documents/ingest", body, timeout)

    def _request(
        self,
        path: str,
        payload: dict[str, Any],
        timeout: float,
    ) -> dict[str, Any]:
        if not self.api_key:
            raise RememCredentialUnavailable("Remem credential unavailable")
        request = urllib_request.Request(
            url=f"{self.api_url}{path}",
            data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
            },
        )
        try:
            with self._opener(request, timeout=timeout) as response:  # nosec B310
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise ValueError("response was too large")
            decoded = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(decoded, dict):
                raise ValueError("response was not an object")
            return decoded
        except RememAPIError:
            raise
        except Exception:
            raise RememAPIError("Remem request failed") from None


__all__ = [
    "KEYCHAIN_ACCOUNT",
    "KEYCHAIN_SERVICE",
    "Keychain",
    "MacOSKeychain",
    "RememAPI",
    "RememAPIError",
    "RememCredentialUnavailable",
    "RememKeychainError",
    "default_keychain",
    "consume_explicit_api_key",
    "normalize_api_origin",
    "normalize_api_origin_for_environment",
    "resolve_api_access",
    "resolve_api_key",
    "store_api_key",
]
