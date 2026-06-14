import os
import json
import requests
from dotenv import load_dotenv
from services.fim_normalizer import build_llm_event_payload

load_dotenv()

LLM_API_URL = os.getenv("LLM_API_URL")
LLM_MODEL = os.getenv("LLM_MODEL")
LLM_BATCH_MAX_TOKENS = int(os.getenv("LLM_BATCH_MAX_TOKENS", "1024"))


def normalize_llm_result(result: dict) -> dict:
    """
    Fungsi pembantu untuk menormalisasi output dari LLM 
    agar classification dan risk_score seragam dan valid.
    """
    classification = result.get("classification", "mencurigakan")

    if classification not in ["aman", "mencurigakan", "berbahaya"]:
        classification = "mencurigakan"

    risk_score = result.get("risk_score", 50)

    try:
        risk_score = int(risk_score)
    except Exception:
        risk_score = 50

    risk_score = max(0, min(100, risk_score))

    if classification == "aman" and risk_score > 39:
        risk_score = 30
    elif classification == "mencurigakan" and risk_score < 40:
        risk_score = 50
    elif classification == "berbahaya" and risk_score < 70:
        risk_score = 80

    return {
        "classification": classification,
        "risk_score": risk_score,
        "reason": result.get("reason", ""),
        "recommendation": result.get("recommendation", "")
    }


def _try_extract_json_array(text: str):
    """
    Try to recover a JSON array from `text` by locating the first '[' and last ']' or
    removing common code fences. Returns parsed object or raises JSONDecodeError.
    """
    import json

    # Quick attempt: find first [ and last ] and parse substring
    start = text.find("[")
    end = text.rfind("]")

    if start != -1 and end != -1 and end > start:
        candidate = text[start:end + 1]
        try:
            return json.loads(candidate)
        except Exception:
            pass

    # Remove common markdown/code fences and try again
    cleaned = text.replace("```json", "").replace("```", "").strip()

    try:
        return json.loads(cleaned)
    except Exception:
        # Let caller handle JSONDecodeError
        raise


def _is_context_length_error(error: requests.HTTPError) -> bool:
    response = error.response

    if response is None or response.status_code != 400:
        return False

    error_body = response.text.lower()

    return (
        "maximum context length" in error_body
        or "input_tokens" in error_body
        or "context" in error_body
    )


def _analyze_events_with_smaller_batches(events: list[dict]) -> list[dict]:
    if len(events) == 1:
        return [analyze_fim_event_with_llm(events[0])]

    middle_index = max(1, len(events) // 2)

    return (
        analyze_fim_events_batch_with_llm(events[:middle_index])
        + analyze_fim_events_batch_with_llm(events[middle_index:])
    )


def _batch_fallback_results(
    events: list[dict],
    reason: str,
    recommendation: str
) -> list[dict]:
    return [
        {
            "classification": "mencurigakan",
            "risk_score": 50,
            "reason": reason,
            "recommendation": recommendation
        }
        for _ in events
    ]


# 1. FUNGSI LAMA (Tetap dipertahankan, disesuaikan sedikit agar rapi)
def analyze_fim_event_with_llm(event: dict) -> dict:
    """
    Mengirim satu event FIM ke LLM dan meminta klasifikasi risiko.
    Output wajib JSON.
    """

    system_prompt = """
Anda adalah analis keamanan SIEM.
Tugas Anda adalah menganalisis event File Integrity Monitoring dari Wazuh.

Klasifikasikan event menjadi salah satu:
- aman
- mencurigakan
- berbahaya

Pertimbangkan:
1. Path file yang berubah
2. Jenis perubahan file
3. User yang melakukan perubahan
4. Process yang digunakan
5. Rule level Wazuh
6. Petunjuk risiko awal
7. Dampak keamanan terhadap sistem

Jawab hanya dalam JSON valid.
Jangan gunakan markdown.
Jangan menambahkan teks di luar JSON.

Format output:
{
  "classification": "aman/mencurigakan/berbahaya",
  "risk_score": 0,
  "reason": "alasan singkat",
  "recommendation": "rekomendasi singkat"
}
"""

    user_prompt = f"""
Analisis event FIM berikut:

{json.dumps(event, ensure_ascii=False, indent=2)}
"""

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "temperature": 0.2,
        "max_tokens": 512
    }

    response = requests.post(
        LLM_API_URL,
        json=payload,
        timeout=120
    )

    response.raise_for_status()
    result = response.json()

    content = result["choices"][0]["message"]["content"]

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = {
            "classification": "mencurigakan",
            "risk_score": 50,
            "reason": "LLM tidak mengembalikan JSON valid, sehingga event ditandai mencurigakan untuk ditinjau manual.",
            "recommendation": "Periksa event secara manual dan validasi konfigurasi prompt LLM."
        }

    # Menggunakan fungsi pembantu normalize_llm_result agar logika pembersihan datanya sama
    normalized = normalize_llm_result(parsed)
    normalized["raw_llm_response"] = content # Tetap menyertakan raw response sesuai kode lama
    
    return normalized


# 2. FUNGSI  (Batch Analyzer)
def analyze_fim_events_batch_with_llm(events: list[dict]) -> list[dict]:
    """
    Menganalisis beberapa event FIM dalam satu request LLM.
    Input: list event hasil normalisasi/reducer.
    Output: list hasil analisis dengan urutan yang sama.
    """

    events_for_llm = []

    for index, event in enumerate(events):
        payload = build_llm_event_payload(event)
        payload["batch_index"] = index
        events_for_llm.append(payload)

    system_prompt = """
Anda adalah analis keamanan SIEM.
Tugas Anda adalah menganalisis event File Integrity Monitoring dari Wazuh.

Klasifikasikan setiap event menjadi salah satu:
- aman
- mencurigakan
- berbahaya

Pertimbangkan:
1. Path file yang berubah
2. Jenis perubahan file
3. User yang melakukan perubahan
4. Process yang digunakan
5. Rule level Wazuh
6. Risk hints
7. Occurrence count
8. Dampak keamanan terhadap sistem

Aturan output:
- Jawab hanya JSON valid.
- Jangan gunakan markdown.
- Jangan menambahkan teks di luar JSON.
- Output harus berupa array JSON.
- Jumlah item output harus sama dengan jumlah event input.
- Setiap item wajib memiliki batch_index yang sama dengan input.

Format output:
[
  {
    "batch_index": 0,
    "classification": "aman/mencurigakan/berbahaya",
    "risk_score": 0,
    "reason": "alasan singkat",
    "recommendation": "rekomendasi singkat"
  }
]
"""

    user_prompt = f"""
Analisis daftar event FIM berikut:

{json.dumps(events_for_llm, ensure_ascii=False, indent=2)}
"""

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "temperature": 0.2,
        "max_tokens": LLM_BATCH_MAX_TOKENS
    }

    try:
        response = requests.post(
            LLM_API_URL,
            json=payload,
            timeout=180
        )

        response.raise_for_status()
    except requests.HTTPError as error:
        if _is_context_length_error(error):
            return _analyze_events_with_smaller_batches(events)

        raise

    result = response.json()

    content = result["choices"][0]["message"]["content"]

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        try:
            parsed = _try_extract_json_array(content)
        except Exception:
            if len(events) > 1:
                return _analyze_events_with_smaller_batches(events)

            return _batch_fallback_results(
                events,
                reason="LLM tidak mengembalikan JSON valid pada batch analysis.",
                recommendation="Periksa event secara manual dan validasi prompt batch LLM."
            )

    if not isinstance(parsed, list):
        if len(events) > 1:
            return _analyze_events_with_smaller_batches(events)

        return _batch_fallback_results(
            events,
            reason="LLM tidak mengembalikan array JSON sesuai format batch.",
            recommendation="Periksa event secara manual dan validasi prompt batch LLM."
        )

    results_by_index = {}

    for item in parsed:
        try:
            batch_index = int(item.get("batch_index"))
            normalized = normalize_llm_result(item)
            # Sertakan raw LLM response agar memudahkan debugging
            normalized["raw_llm_response"] = content
            results_by_index[batch_index] = normalized
        except Exception:
            continue

    final_results = []

    if len(results_by_index) != len(events) and len(events) > 1:
        return _analyze_events_with_smaller_batches(events)

    for index, _event in enumerate(events):
        if index in results_by_index:
            final_results.append(results_by_index[index])
        else:
            final_results.append({
                "classification": "mencurigakan",
                "risk_score": 50,
                "reason": "LLM tidak mengembalikan hasil untuk event ini.",
                "recommendation": "Periksa event secara manual."
            })

    return final_results
