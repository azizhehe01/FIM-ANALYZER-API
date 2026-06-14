import os
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Tuple

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_INDEXER_USERNAME = os.getenv("WAZUH_INDEXER_USERNAME")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD")
VERIFY_SSL = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "false").lower() == "true"

WAZUH_ALERT_INDEX = os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts-*")

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _validate_env() -> None:
    """
    Memastikan konfigurasi koneksi Wazuh Indexer sudah tersedia.
    """

    missing_configs = []

    if not WAZUH_INDEXER_URL:
        missing_configs.append("WAZUH_INDEXER_URL")

    if not WAZUH_INDEXER_USERNAME:
        missing_configs.append("WAZUH_INDEXER_USERNAME")

    if not WAZUH_INDEXER_PASSWORD:
        missing_configs.append("WAZUH_INDEXER_PASSWORD")

    if missing_configs:
        raise ValueError(
            f"Konfigurasi .env belum lengkap: {', '.join(missing_configs)}"
        )


def _get_search_url() -> str:
    """
    Membentuk URL endpoint search Wazuh Indexer.
    """

    _validate_env()

    base_url = WAZUH_INDEXER_URL.rstrip("/")
    return f"{base_url}/{WAZUH_ALERT_INDEX}/_search"


def get_yesterday_date() -> str:
    """
    Mengambil tanggal kemarin dalam format YYYY-MM-DD berdasarkan UTC.

    Catatan:
    Query Wazuh yang dipakai menggunakan format Z/UTC.
    """

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    return yesterday.strftime("%Y-%m-%d")


def build_date_range(date: str) -> Tuple[str, str]:
    """
    Membuat rentang waktu satu hari penuh berdasarkan tanggal tertentu.

    Format input:
    YYYY-MM-DD

    Output:
    2026-05-31T00:00:00.000Z
    2026-05-31T23:59:59.999Z
    """

    start_time = f"{date}T00:00:00.000Z"
    end_time = f"{date}T23:59:59.999Z"

    return start_time, end_time


def search_fim_events_by_date(
    date: Optional[str] = None,
    size: int = 1000
) -> List[Dict]:
    """
    Mengambil event File Integrity Monitoring dari Wazuh Indexer
    berdasarkan tanggal tertentu.

    Jika date tidak dikirim, sistem otomatis mengambil tanggal kemarin.

    Contoh:
    search_fim_events_by_date("2026-05-31")
    search_fim_events_by_date()
    """

    if date is None:
        date = get_yesterday_date()

    start_time, end_time = build_date_range(date)

    url = _get_search_url()

    query = {
        "size": size,
        "sort": [
            {
                "timestamp": {
                    "order": "asc"
                }
            }
        ],
        "_source": [
            "@timestamp",
            "timestamp",
            "id",
            "agent",
            "manager",
            "rule",
            "decoder",
            "syscheck",
            "location",
            "full_log"
        ],
        "query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "rule.groups": "syscheck"
                        }
                    },
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ]
            }
        }
    }

    response = requests.post(
        url,
        auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
        json=query,
        verify=VERIFY_SSL,
        timeout=60
    )

    response.raise_for_status()

    data = response.json()

    return data.get("hits", {}).get("hits", [])


def count_fim_events_by_date(date: Optional[str] = None) -> int:
    """
    Menghitung jumlah event FIM berdasarkan tanggal tertentu.
    Fungsi ini berguna untuk statistik awal sebelum data dianalisis.

    Jika date tidak dikirim, sistem otomatis menghitung event tanggal kemarin.
    """

    if date is None:
        date = get_yesterday_date()

    start_time, end_time = build_date_range(date)

    _validate_env()

    base_url = WAZUH_INDEXER_URL.rstrip("/")
    url = f"{base_url}/{WAZUH_ALERT_INDEX}/_count"

    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "rule.groups": "syscheck"
                        }
                    },
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ]
            }
        }
    }

    response = requests.post(
        url,
        auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
        json=query,
        verify=VERIFY_SSL,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    return data.get("count", 0)


def search_latest_fim_events(size: int = 10) -> List[Dict]:
    """
    Mengambil event FIM terbaru.
    Fungsi ini hanya untuk testing/debug, bukan flow final harian.
    """

    url = _get_search_url()

    query = {
        "size": size,
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],
        "_source": [
            "@timestamp",
            "timestamp",
            "id",
            "agent",
            "manager",
            "rule",
            "decoder",
            "syscheck",
            "location",
            "full_log"
        ],
        "query": {
            "bool": {
                "must": [
                    {
                        "match": {
                            "rule.groups": "syscheck"
                        }
                    }
                ]
            }
        }
    }

    response = requests.post(
        url,
        auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
        json=query,
        verify=VERIFY_SSL,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    return data.get("hits", {}).get("hits", [])