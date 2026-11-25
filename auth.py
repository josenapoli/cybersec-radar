#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auth.py - Módulo de autenticación para CyberSec Dashboard
Soporta: usuario local (bcrypt) + Active Directory (ldap3, opcional)
"""

import os
import json
import hashlib
import secrets
import re
import time
from functools import wraps
from flask import session, redirect, url_for, request, jsonify

# Intentar importar bcrypt (opcional - fallback a SHA256)
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("[Auth] bcrypt no disponible, usando SHA256. Instala bcrypt para mayor seguridad.")

# Intentar importar ldap3 (opcional - sólo si AD configurado)
try:
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SUBTREE
    from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPCommunicationError
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    print("[Auth] ldap3 no disponible. Autenticación AD desactivada.")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")

# ─────────────────────────── Hashing de contraseñas ───────────────────────────

def hash_password(password: str) -> str:
    """Genera hash seguro de contraseña."""
    if BCRYPT_AVAILABLE:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')
    else:
        salt = secrets.token_hex(16)
        hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
        return f"sha256:{salt}:{hashed}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verifica contraseña contra hash almacenado."""
    if not password or not stored_hash:
        return False
    try:
        if stored_hash.startswith("sha256:"):
            parts = stored_hash.split(":")
            if len(parts) != 3:
                return False
            _, salt, expected = parts
            actual = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
            return secrets.compare_digest(actual, expected)
        elif BCRYPT_AVAILABLE:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        else:
            return False
    except Exception as e:
        print(f"[Auth] Error verificando contraseña: {e}")
        return False

# ─────────────────────────── Gestión de usuarios locales ───────────────────────

def load_users() -> dict:
    """Carga usuarios del archivo JSON."""
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[Auth] Error cargando usuarios: {e}")
        return {}

def save_users(users: dict) -> bool:
    """Guarda usuarios al archivo JSON."""
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[Auth] Error guardando usuarios: {e}")
        return False

def create_default_admin(password: str = "Admin1234!") -> bool:
    """Crea usuario admin por defecto si no existe ningún usuario."""
    users = load_users()
    if users:
        return False  # Ya hay usuarios, no crear
    users["admin"] = {
        "username": "admin",
        "password_hash": hash_password(password),
        "role": "admin",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "auth_type": "local"
    }
    saved = save_users(users)
    if saved:
        print(f"[Auth] ✅ Usuario admin creado. Cambiar contraseña en primer uso.")
    return saved

def verify_local_user(username: str, password: str) -> dict | None:
    """Verifica usuario local. Retorna dict con info de usuario o None."""
    users = load_users()
    username_lower = username.strip().lower()
    # Buscar por username (case-insensitive)
    for uname, udata in users.items():
        if uname.lower() == username_lower:
            if verify_password(password, udata.get("password_hash", "")):
                return {
                    "username": uname,
                    "role": udata.get("role", "user"),
                    "auth_type": "local",
                    "display_name": udata.get("display_name", uname)
                }
    return None

# ─────────────────────────── Autenticación Active Directory ────────────────────

def get_ad_config(app_config: dict) -> dict:
    """Extrae configuración AD del config general."""
    return {
        "enabled": app_config.get("ad_enabled", False),
        "server": app_config.get("ad_server", ""),          # ej: "192.168.1.10" o "dc.empresa.com"
        "port": int(app_config.get("ad_port", 389)),         # 389 (LDAP) o 636 (LDAPS)
        "use_ssl": app_config.get("ad_use_ssl", False),      # True para LDAPS (puerto 636)
        "domain": app_config.get("ad_domain", ""),           # ej: "CORP" o "corp.empresa.com"
        "base_dn": app_config.get("ad_base_dn", ""),         # ej: "DC=corp,DC=empresa,DC=com"
        "bind_user": app_config.get("ad_bind_user", ""),     # Cuenta de servicio (opcional)
        "bind_password": app_config.get("ad_bind_password", ""),
        "group_required": app_config.get("ad_group_required", ""),  # Grupo AD requerido (opcional)
        "timeout": int(app_config.get("ad_timeout", 5)),
    }

def verify_ad_user(username: str, password: str, ad_config: dict) -> dict | None:
    """
    Autentica usuario contra Active Directory via LDAP/NTLM.
    Retorna dict con info de usuario o None si falla.
    """
    if not LDAP_AVAILABLE:
        print("[Auth] ldap3 no instalado. No se puede autenticar contra AD.")
        return None

    if not ad_config.get("enabled") or not ad_config.get("server") or not ad_config.get("domain"):
        return None

    server_addr = ad_config["server"]
    port = ad_config["port"]
    use_ssl = ad_config["use_ssl"]
    domain = ad_config["domain"].upper()
    base_dn = ad_config["base_dn"]
    timeout = ad_config["timeout"]

    # Formato de usuario: DOMAIN\username
    user_principal = f"{domain}\\{username.strip()}"

    try:
        server = Server(server_addr, port=port, use_ssl=use_ssl, connect_timeout=timeout, get_info=ALL)
        conn = Connection(
            server,
            user=user_principal,
            password=password,
            authentication=NTLM,
            raise_exceptions=True,
            receive_timeout=timeout
        )

        if not conn.bind():
            print(f"[Auth] AD bind fallido para usuario: {username}")
            return None

        # Verificar grupo requerido (opcional)
        group_required = ad_config.get("group_required", "").strip()
        display_name = username
        email = ""

        if base_dn:
            # Buscar atributos del usuario
            conn.search(
                search_base=base_dn,
                search_filter=f"(sAMAccountName={username})",
                search_scope=SUBTREE,
                attributes=["displayName", "mail", "memberOf", "cn"]
            )
            if conn.entries:
                entry = conn.entries[0]
                display_name = str(entry.displayName) if entry.displayName else username
                email = str(entry.mail) if entry.mail else ""

                # Verificar pertenencia al grupo
                if group_required:
                    member_of = [str(g).lower() for g in (entry.memberOf or [])]
                    group_match = any(group_required.lower() in g for g in member_of)
                    if not group_match:
                        print(f"[Auth] Usuario '{username}' no pertenece al grupo requerido: {group_required}")
                        conn.unbind()
                        return None

        conn.unbind()
        print(f"[Auth] ✅ AD autenticado: {username} ({display_name})")
        return {
            "username": username,
            "role": "user",
            "auth_type": "active_directory",
            "display_name": display_name,
            "email": email
        }

    except LDAPBindError:
        print(f"[Auth] AD: Credenciales inválidas para {username}")
        return None
    except LDAPCommunicationError as e:
        print(f"[Auth] AD: Error de comunicación con {server_addr}: {e}")
        return None
    except LDAPException as e:
        print(f"[Auth] AD: Error LDAP: {e}")
        return None
    except Exception as e:
        print(f"[Auth] AD: Error inesperado: {e}")
        return None

# ─────────────────────────── CAPTCHA matemático ────────────────────────────────

import random
import operator

CAPTCHA_OPS = [
    (operator.add, "+"),
    (operator.sub, "-"),
    (operator.mul, "×"),
]

def generate_captcha() -> dict:
    """Genera un CAPTCHA matemático simple."""
    op_func, op_symbol = random.choice(CAPTCHA_OPS)
    if op_symbol == "×":
        a = random.randint(2, 9)
        b = random.randint(2, 9)
    elif op_symbol == "-":
        a = random.randint(5, 20)
        b = random.randint(1, a)
    else:
        a = random.randint(1, 20)
        b = random.randint(1, 20)

    answer = op_func(a, b)
    question = f"¿Cuánto es {a} {op_symbol} {b}?"
    return {"question": question, "answer": str(answer)}

def verify_captcha(session_answer: str, user_answer: str) -> bool:
    """Verifica la respuesta del CAPTCHA."""
    if not session_answer or not user_answer:
        return False
    return str(session_answer).strip() == str(user_answer).strip()

# ─────────────────────────── Decorador login_required ─────────────────────────

def login_required(f):
    """Decorador que redirige al login si no hay sesión activa."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "No autenticado", "redirect": "/login"}), 401
            return redirect(url_for("login_page", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# ─────────────────────────── Rate limiting simple ─────────────────────────────

_failed_attempts = {}  # ip -> (count, first_fail_time)
MAX_ATTEMPTS = 10
LOCKOUT_SECONDS = 300  # 5 minutos

def check_rate_limit(ip: str) -> tuple[bool, int]:
    """
    Comprueba si la IP está bloqueada por intentos fallidos.
    Retorna (permitido, segundos_restantes).
    """
    now = time.time()
    if ip in _failed_attempts:
        count, first_fail = _failed_attempts[ip]
        elapsed = now - first_fail
        if count >= MAX_ATTEMPTS and elapsed < LOCKOUT_SECONDS:
            remaining = int(LOCKOUT_SECONDS - elapsed)
            return False, remaining
        elif elapsed >= LOCKOUT_SECONDS:
            del _failed_attempts[ip]
    return True, 0

def record_failed_attempt(ip: str):
    """Registra un intento fallido."""
    now = time.time()
    if ip in _failed_attempts:
        count, first_fail = _failed_attempts[ip]
        _failed_attempts[ip] = (count + 1, first_fail)
    else:
        _failed_attempts[ip] = (1, now)

def clear_failed_attempts(ip: str):
    """Limpia intentos fallidos (login exitoso)."""
    _failed_attempts.pop(ip, None)
