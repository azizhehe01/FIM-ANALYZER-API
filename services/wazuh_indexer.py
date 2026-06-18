import os
from datetime import datetime, timedelta, timezone
from typing import Iterator, List, Dict, Optional, Tuple

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_INDEXER_USERNAME = os.getenv("WAZUH_INDEXER_USERNAME")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD")
VERIFY_SSL = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "false").lower() == "true"

WAZUH_ALERT_INDEX = os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts-*")
CUSTOM_PHP_RULE_GROUP = os.getenv("WAZUH_CUSTOM_PHP_RULE_GROUP", "custom_php_protection")
CUSTOM_PHP_RULE_IDS = [100200, 100201, 100202]

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


def _get_scroll_url() -> str:
    _validate_env()

    base_url = WAZUH_INDEXER_URL.rstrip("/")
    return f"{base_url}/_search/scroll"


def _build_fim_source_fields() -> List[str]:
    return [
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
    ]


def _build_custom_php_query(start_time: str, end_time: str) -> Dict:
    """
    Query dibuat dalam filter context karena tidak butuh scoring.
    Rule custom PHP dibatasi ke rule id yang memang dipakai oleh Wazuh.
    """

    return {
        "bool": {
            "filter": [
                {
                    "match": {
                        "rule.groups": CUSTOM_PHP_RULE_GROUP
                    }
                },
                {
                    "terms": {
                        "rule.id": CUSTOM_PHP_RULE_IDS
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
        "track_total_hits": True,
        "sort": [
            {
                "timestamp": {
                    "order": "asc"
                }
            }
        ],
        "_source": _build_fim_source_fields(),
        "query": _build_custom_php_query(start_time, end_time)
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


def iter_fim_events_by_date(
    date: Optional[str] = None,
    page_size: int = 1000,
    scroll_ttl: str = "2m",
    max_events: Optional[int] = None
) -> Iterator[List[Dict]]:
    """
    Mengambil event FIM custom PHP secara bertahap menggunakan scroll.
    Ini dipakai oleh job harian agar volume besar tidak harus dimuat sekaligus.
    """

    if date is None:
        date = get_yesterday_date()

    start_time, end_time = build_date_range(date)

    url = _get_search_url()

    query = {
        "size": page_size,
        "track_total_hits": True,
        "sort": [
            {
                "timestamp": {
                    "order": "asc"
                }
            }
        ],
        "_source": _build_fim_source_fields(),
        "query": _build_custom_php_query(start_time, end_time)
    }

    response = requests.post(
        url,
        auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
        params={"scroll": scroll_ttl},
        json=query,
        verify=VERIFY_SSL,
        timeout=60
    )

    response.raise_for_status()

    data = response.json()
    scroll_id = data.get("_scroll_id")
    emitted_count = 0

    try:
        while True:
            hits = data.get("hits", {}).get("hits", [])

            if not hits:
                break

            if max_events is not None:
                remaining = max_events - emitted_count

                if remaining <= 0:
                    break

                hits = hits[:remaining]

            emitted_count += len(hits)
            yield hits

            if max_events is not None and emitted_count >= max_events:
                break

            if not scroll_id:
                break

            response = requests.post(
                _get_scroll_url(),
                auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
                json={
                    "scroll": scroll_ttl,
                    "scroll_id": scroll_id
                },
                verify=VERIFY_SSL,
                timeout=60
            )

            response.raise_for_status()
            data = response.json()
            scroll_id = data.get("_scroll_id", scroll_id)
    finally:
        if scroll_id:
            try:
                requests.delete(
                    _get_scroll_url(),
                    auth=(WAZUH_INDEXER_USERNAME, WAZUH_INDEXER_PASSWORD),
                    json={
                        "scroll_id": [scroll_id]
                    },
                    verify=VERIFY_SSL,
                    timeout=10
                )
            except Exception:
                pass


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
        "query": _build_custom_php_query(start_time, end_time)
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
        "track_total_hits": True,
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],
        "_source": _build_fim_source_fields(),
        "query": {
            "bool": {
                "filter": [
                    {
                        "match": {
                            "rule.groups": CUSTOM_PHP_RULE_GROUP
                        }
                    },
                    {
                        "terms": {
                            "rule.id": CUSTOM_PHP_RULE_IDS
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
