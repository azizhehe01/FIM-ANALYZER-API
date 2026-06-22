import os
import sqlite3
import requests
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from dotenv import load_dotenv

load_dotenv()

# ─── Konfigurasi ──────────────────────────────────────────────────────────────

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(_BASE_DIR, "data", "wordpress_plugins.db")

WP_PLUGIN_API_URL = "https://api.wordpress.org/plugins/info/1.2/"
WP_PLUGIN_CACHE_TTL_DAYS = int(os.getenv("WP_PLUGIN_CACHE_TTL_DAYS", "0"))
WP_PLUGIN_API_TIMEOUT = int(os.getenv("WP_PLUGIN_API_TIMEOUT", "10"))
WP_PLUGIN_CHECK_ENABLED = os.getenv("WP_PLUGIN_CHECK_ENABLED", "true").lower() == "true"

# ─── Inisialisasi Database ─────────────────────────────────────────────────────

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Membuat tabel wp_plugins jika belum ada.
    Dipanggil sekali saat modul pertama kali dimuat.
    """
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS wp_plugins (
                slug         TEXT PRIMARY KEY,
                name         TEXT,
                author       TEXT,
                version      TEXT,
                last_updated TEXT,
                found        INTEGER NOT NULL DEFAULT 0,
                fetched_at   TEXT NOT NULL
            )
        """)
        conn.commit()


# Inisialisasi DB otomatis saat modul diimpor
init_db()

# ─── Helper ────────────────────────────────────────────────────────────────────

def get_plugin_slug_from_path(file_path: str) -> Optional[str]:
    """
    Mengekstrak slug plugin WordPress dari file path.

    Contoh:
        /public_html/wp-content/plugins/elementor/elementor.php  → "elementor"
        /public_html/wp-content/plugins/woocommerce/includes/x.php → "woocommerce"
        /public_html/wp-content/plugins/hello.php → None (file di root plugins/)

    Return None jika file langsung berada di root /plugins/ tanpa subfolder plugin.
    """
    normalized = file_path.replace("\\", "/").lower()

    for marker in ["/wp-content/plugins/", "/wp_content/plugins/"]:
        if marker not in normalized:
            continue

        remainder = normalized.split(marker, 1)[1].strip("/")

        if "/" not in remainder:
            # File langsung di root /plugins/, bukan di subfolder plugin
            return None

        slug = remainder.split("/")[0]
        return slug if slug else None

    return None


def _is_cache_valid(fetched_at: str) -> bool:
    """
    Memeriksa apakah cache masih valid berdasarkan TTL yang dikonfigurasi.
    Jika WP_PLUGIN_CACHE_TTL_DAYS <= 0, cache dianggap valid selamanya (tidak pernah kedaluwarsa).
    """
    if WP_PLUGIN_CACHE_TTL_DAYS <= 0:
        return True
    try:
        fetched_time = datetime.fromisoformat(fetched_at)
        expiry = fetched_time + timedelta(days=WP_PLUGIN_CACHE_TTL_DAYS)
        return datetime.now(timezone.utc) < expiry
    except Exception:
        return False


def _get_from_cache(slug: str) -> Optional[Dict[str, Any]]:
    """
    Mengambil data plugin dari cache SQLite lokal.
    Return None jika tidak ada atau sudah expired.
    """
    try:
        with _get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM wp_plugins WHERE slug = ?",
                (slug,)
            ).fetchone()

        if row is None:
            return None

        if not _is_cache_valid(row["fetched_at"]):
            return None

        return dict(row)
    except Exception:
        return None


def _save_to_cache(slug: str, found: bool, data: Dict[str, Any]) -> None:
    """
    Menyimpan hasil pengecekan plugin ke cache SQLite.
    """
    try:
        fetched_at = datetime.now(timezone.utc).isoformat()

        with _get_connection() as conn:
            conn.execute("""
                INSERT INTO wp_plugins (slug, name, author, version, last_updated, found, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slug) DO UPDATE SET
                    name         = excluded.name,
                    author       = excluded.author,
                    version      = excluded.version,
                    last_updated = excluded.last_updated,
                    found        = excluded.found,
                    fetched_at   = excluded.fetched_at
            """, (
                slug,
                data.get("name"),
                data.get("author"),
                data.get("version"),
                data.get("last_updated"),
                1 if found else 0,
                fetched_at
            ))
            conn.commit()
    except Exception:
        pass


def _fetch_from_wordpress_api(slug: str) -> Dict[str, Any]:
    """
    Memanggil WordPress.org Plugin API untuk mengecek keberadaan plugin.

    Response positif: dict berisi name, version, author, dll.
    Response negatif: {"error": "Plugin not found."} atau response body "false"
    """
    try:
        response = requests.get(
            WP_PLUGIN_API_URL,
            params={
                "action": "plugin_information",
                "request[slug]": slug,
                "request[fields][sections]": "false",
                "request[fields][reviews]": "false",
                "request[fields][screenshots]": "false",
                "request[fields][banners]": "false",
            },
            timeout=WP_PLUGIN_API_TIMEOUT
        )

        response.raise_for_status()
        data = response.json()

        # WordPress API mengembalikan False (bool) atau dict dengan "error" jika tidak ditemukan
        if data is False or not isinstance(data, dict):
            return {"found": False}

        if "error" in data:
            return {"found": False}

        return {
            "found": True,
            "name": data.get("name"),
            "author": _strip_html(str(data.get("author", ""))),
            "version": data.get("version"),
            "last_updated": data.get("last_updated"),
        }

    except Exception:
        # Jika API tidak bisa diakses, return None sebagai sinyal fallback
        return {"found": None, "api_error": True}


def _strip_html(text: str) -> str:
    """Menghapus tag HTML sederhana dari string."""
    import re
    return re.sub(r"<[^>]+>", "", text).strip()


# ─── Fungsi Utama ──────────────────────────────────────────────────────────────

def check_plugin_on_wordpress_org(slug: str) -> Dict[str, Any]:
    """
    Memeriksa apakah plugin dengan slug tertentu terdaftar di WordPress.org.

    Alur:
    1. Cek cache SQLite lokal (jika masih valid / dalam TTL)
    2. Jika tidak ada atau expired → request ke WordPress.org API
    3. Simpan hasil ke cache

    Return:
    {
        "found": True/False/None,   # None = error API, tidak bisa ditentukan
        "slug": "elementor",
        "name": "Elementor Website Builder",
        "source": "cache"/"api"/"api_error"
    }
    """
    if not WP_PLUGIN_CHECK_ENABLED:
        return {"found": None, "slug": slug, "source": "disabled"}

    # Cek cache lokal terlebih dahulu
    cached = _get_from_cache(slug)
    if cached is not None:
        return {
            "found": bool(cached["found"]),
            "slug": slug,
            "name": cached.get("name"),
            "author": cached.get("author"),
            "version": cached.get("version"),
            "source": "cache"
        }

    # Request ke WordPress.org API
    api_result = _fetch_from_wordpress_api(slug)

    if api_result.get("api_error"):
        # API tidak bisa diakses, jangan cache, kembalikan sebagai unknown
        return {"found": None, "slug": slug, "source": "api_error"}

    found = bool(api_result.get("found"))
    _save_to_cache(slug, found, api_result)

    return {
        "found": found,
        "slug": slug,
        "name": api_result.get("name"),
        "author": api_result.get("author"),
        "version": api_result.get("version"),
        "source": "api"
    }
