# CyberSec Radar – Panel de Control de Ciberseguridad & CVEs

---

## 📍 Acceso
- **URL:** `http://127.0.0.1:5000` (también disponible en `http://0.0.0.0:5000` para acceso desde la LAN).
- **Puerto:** `5000` (configurable en `dashboard_config.json` → `"port"`).

---

## 🚀 Inicio rápido
1. **Instalar dependencias** (solo una vez):
   ```bash
   cd "<ruta-al-proyecto>/Dashboard_de_ciberseguridad"
   pip install -r requirements.txt   # incluye Flask, feedparser, bcrypt, ldap3, etc.
   ```
2. **Iniciar el servidor**:
   ```bash
   ./iniciar_panel.bat   # o python app.py
   ```
3. Abre tu navegador en la URL anterior.

---

## 🔐 Autenticación
### 1. Usuario local (por defecto)
| Campo | Valor |
|-------|-------|
| **Usuario** | `admin` |
| **Contraseña** | `Admin123!` *(valor por defecto)* |
| **Rol** | `admin` |

- **Cambiar contraseña**:
  - **Desde la UI**: abre el modal *Cambiar contraseña* (ruta `/api/auth/change-password`) y proporciona la contraseña actual y la nueva.
  - **Desde la API**: envía una petición `POST` a `https://<host>/api/auth/change-password` con JSON `{ "old_password": "<actual>", "new_password": "<nueva>" }` (requiere estar autenticado).
- **Añadir usuarios locales**: editar `users.json` (formato: `{ "username": { "password_hash": "sha256:<salt>:<hash>", "role": "user", "auth_type": "local" } }`). Usa la función `hash_password()` del módulo `auth.py` para generar el hash.

### 2. Active Directory (opcional)
1. **Habilitar** editando `dashboard_config.json`:
   ```json
   "ad_enabled": true,
   "ad_server": "ad.tu-dominio.com",
   "ad_port": 389,               // 636 si usas LDAPS
   "ad_use_ssl": false,          // true para LDAPS
   "ad_domain": "TU-DOMINIO",
   "ad_base_dn": "DC=tu,DC=dominio,DC=com",
   "ad_bind_user": "svc_cybersec",   // opcional
   "ad_bind_password": "SuperSecreta123!",
   "ad_group_required": "CN=Ciberseguridad,OU=Grupos,DC=tu,DC=dominio,DC=com", // opcional
   "ad_timeout": 5
   ```
2. **Reiniciar** el servidor para que lea la nueva configuración.
3. En la pantalla de login ingresa tu **usuario del dominio** (sin el `DOMINIO\`), la contraseña de AD y la respuesta al CAPTCHA.
4. Si la autenticación AD falla, el sistema hace *fallback* a la autenticación local.

---

## 🛠️ Funcionalidades del panel
| Área | Descripción |
|------|-------------|
| **Noticias** | RSS de fuentes de seguridad (10+ fuentes configurables). Cada artículo muestra título, resumen, fuente y fecha. |
| **CVE Feed** | Consulta a la NVD (con o sin API‑key) y a la lista CISA KEV. Los CVEs se filtran por los *keywords* configurados en `keywords.json` y se ordenan por severidad (CRITICAL > HIGH > MEDIUM > LOW). |
| **Filtros** | - **Temas / Aplicaciones** (palabras clave incluidas/excluidas).<br>- **Severidad** (checkboxes).<br>- **Fecha** (últimos 7 días por defecto). |
| **Etiquetas visuales** | - Color por severidad.<br>- Badge *CISA KEV*.<br>- Icono *PoC* cuando la descripción contiene exploits conocidos. |
| **Actualización automática** | Cada `refresh_interval_minutes` (default 10 min) se ejecuta en background; también puedes forzar la actualización con el botón de “Actualizar”. |
| **Sonido** | Alertas sonoras para CVEs críticos (activables desde el icono de sonido). |
| **Panel de configuración** | Editar fuentes RSS y keywords mediante modal. Los cambios se guardan en `rss_sources.json` y `keywords.json`. |
| **Logout** | Botón “Cerrar sesión” en la barra superior que llama a `/logout` y destruye la cookie de sesión. |

---

## ⚙️ Configuración (`dashboard_config.json`)
```json
{
  "refresh_interval_minutes": 10,
  "nvd_api_key": "",
  "max_news_items": 100,
  "max_cves_items": 150,
  "min_severity": "ALL",
  "auto_open_browser": true,
  "port": 5000,

  "auth_enabled": true,
  "session_lifetime_hours": 1,
  "secret_key": "<generado‑automáticamente>",

  "ad_enabled": false,
  "ad_server": "",
  "ad_port": 389,
  "ad_use_ssl": false,
  "ad_domain": "",
  "ad_base_dn": "",
  "ad_bind_user": "",
  "ad_bind_password": "",
  "ad_group_required": "",
  "ad_timeout": 5
}
```
- **`session_lifetime_hours`** controla cuánto tiempo (en horas) la cookie de sesión permanece válida.
- Cambia `port` si necesitas otro puerto libre.
- Si tienes una **API‑key NVD** válida, colócala en `nvd_api_key` para aumentar el límite de 5 solicitudes/30 s a 50 solicitudes/30 s.

---

## 📦 Instalación de dependencias
El archivo `requirements.txt` ya incluye:
```
Flask>=2.3.0
feedparser>=6.0.0
requests>=2.28.0
bcrypt>=4.0.0
ldap3>=2.9.0
flask-login>=0.6.0
```
Ejecuta `pip install -r requirements.txt` en el directorio del proyecto.

---

## 📂 Estructura de carpetas (relevante)
```
Dashboard_de_ciberseguridad/
│   app.py               # backend Flask
│   dashboard_config.json
│   keywords.json        # include / exclude
│   rss_sources.json
│   users.json           # usuarios locales (hashes)
│   requirements.txt
│   iniciar_panel.bat    # script de arranque rápido
│
├──templates/
│   │   index.html      # UI principal
│   │   login.html      # página de login + CAPTCHA
│   │   ...
│
├──static/
│   │   favicon.ico
│   │   ...
```

---

## 📝 Uso cotidiano
1. **Abrir el panel** – `http://127.0.0.1:5000`.
2. **Login** – usuario/contraseña locales o AD + CAPTCHA.
3. **Explorar** – usa los filtros en la barra superior para refinar CVEs y noticias.
4. **Actualizar manualmente** – botón “Actualizar” (ícono de rotación).
5. **Cambiar configuración** – abre el modal de Configuración (icono de sliders) y editá fuentes o keywords.
6. **Cerrar sesión** – botón “Cerrar sesión” (icono de logout) en la barra superior.

---

## 🛡️ Seguridad
- La sesión usa **Flask secret key** generada automáticamente; puedes sobrescribirla en `dashboard_config.json` si lo deseas.
- **CAPTCHA matemático** protege contra ataques de fuerza bruta en la página de login.
- **Rate‑limiting**: máximo 10 intentos fallidos por IP en 5 min, bloqueando la IP por 5 min.
- **AD fallback**: si la autenticación AD falla, se verifica contra `users.json`.

---

## 📚 Otros recursos
- **Código fuente** – todo está bajo la carpeta del proyecto.
- **Documentación de Flask** – https://flask.palletsprojects.com/
- **ldap3** – https://ldap3.readthedocs.io/
- **bcrypt** – https://pypi.org/project/bcrypt/

---

## 👤 Autor
Jose Napoli – CiberSecurity Analyst.

---

*¡Disfruta de CyberSec Radar y mantén tus sistemas seguros!*