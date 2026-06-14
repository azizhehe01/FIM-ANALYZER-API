import os
import requests
from dotenv import load_dotenv

load_dotenv()

LARAVEL_API_URL = os.getenv("LARAVEL_API_URL")
LARAVEL_API_TOKEN = os.getenv("LARAVEL_API_TOKEN")


def send_analysis_to_laravel(event: dict) -> dict:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    if LARAVEL_API_TOKEN:
        headers["Authorization"] = f"Bearer {LARAVEL_API_TOKEN}"

    response = requests.post(
        LARAVEL_API_URL,
        json=event,
        headers=headers,
        timeout=30
    )

    response.raise_for_status()
    return response.json()