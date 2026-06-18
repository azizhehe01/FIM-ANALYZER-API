from typing import Optional, List, Any
from fastapi import FastAPI, Query
from services.wazuh_indexer import (
    search_latest_fim_events,
    search_fim_events_by_date,
    iter_fim_events_by_date,
    count_fim_events_by_date,
    get_yesterday_date
)
from services.fim_reducer import (
    deduplicate_fim_events,
    split_events_for_analysis,
    summarize_analysis_results
)
from services.fim_normalizer import normalize_fim_event, add_risk_hint
from services.llm_analyzer import (
    analyze_fim_event_with_llm,
    analyze_fim_events_batch_with_llm
)
from services.laravel_client import send_analysis_to_laravel

import time

app = FastAPI(
    title="FIM Analyzer API",
    description="API untuk mengambil data File Integrity Monitoring dari Wazuh dan menganalisisnya menggunakan LLM",
    version="1.0.0"
)

def chunk_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
    return [
        items[index:index + chunk_size]
        for index in range(0, len(items), chunk_size)
    ]

def analyze_llm_candidates_in_batches(
    llm_candidates: list[dict],
    batch_size: int = 5,
    sleep_seconds: int = 2
) -> list[dict]:
    """
    Menganalisis kandidat LLM secara batch agar tidak membebani vLLM.
    """

    llm_results = []

    batches = chunk_list(llm_candidates, batch_size)

    for batch_number, batch in enumerate(batches, start=1):
        try:
            batch_analysis_results = analyze_fim_events_batch_with_llm(batch)
        except Exception as error:
            batch_analysis_results = [
                {
                    "classification": "mencurigakan",
                    "risk_score": 50,
                    "reason": f"Analisis LLM gagal untuk batch ini: {str(error)}",
                    "recommendation": "Periksa event secara manual dan cek koneksi/kapasitas layanan LLM."
                }
                for _event in batch
            ]

        for event, llm_result in zip(batch, batch_analysis_results):
            analyzed_event = {
                **event,
                "classification": llm_result["classification"],
                "risk_score": llm_result["risk_score"],
                "reason": llm_result["reason"],
                "recommendation": llm_result["recommendation"],
                "analysis_source": "llm",
                "llm_batch_number": batch_number
            }

            llm_results.append(analyzed_event)

        if sleep_seconds > 0 and batch_number < len(batches):
            time.sleep(sleep_seconds)

    return llm_results


def prepare_fim_event(hit: dict) -> dict:
    """
    Normalisasi event FIM dan tambahkan risk hint.
    """
    event = normalize_fim_event(hit)
    event = add_risk_hint(event)

    return event


def attach_llm_analysis(event: dict) -> dict:
    """
    Mengirim event ke LLM lalu menggabungkan hasil analisis ke event.
    """
    llm_result = analyze_fim_event_with_llm(event)

    return {
        **event,
        "classification": llm_result["classification"],
        "risk_score": llm_result["risk_score"],
        "reason": llm_result["reason"],
        "recommendation": llm_result["recommendation"],
        "analysis_source": "llm"
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "FIM Analyzer API"
    }


@app.get("/fim/events")
def get_latest_fim_events(size: int = Query(default=2, ge=1, le=10)):
    """
    Mengambil event FIM terbaru.
    Endpoint ini hanya untuk testing/debug.
    """
    raw_events = search_latest_fim_events(size=size)

    normalized_events = [
        prepare_fim_event(hit)
        for hit in raw_events
    ]

    return {
        "mode": "latest",
        "total": len(normalized_events),
        "events": normalized_events
    }


@app.get("/fim/events/daily")
def get_daily_fim_events(
    date: Optional[str] = Query(default=None, description="Format: YYYY-MM-DD. Jika kosong, otomatis tanggal kemarin."),
    size: int = Query(default=1000, ge=1, le=5000)
):
    """
    Mengambil event FIM berdasarkan tanggal.
    Jika date kosong, otomatis mengambil event tanggal kemarin.
    """
    selected_date = date or get_yesterday_date()

    raw_count = count_fim_events_by_date(date=selected_date)
    raw_events = search_fim_events_by_date(date=selected_date, size=size)

    normalized_events = [
        prepare_fim_event(hit)
        for hit in raw_events
    ]

    return {
        "mode": "daily",
        "date": selected_date,
        "raw_event_count": raw_count,
        "fetched_event_count": len(raw_events),
        "normalized_event_count": len(normalized_events),
        "events": normalized_events
    }


@app.post("/fim/analyze")
def analyze_latest_fim_events(size: int = Query(default=1, ge=1, le=5)):
    """
    Menganalisis event FIM terbaru menggunakan LLM.
    Endpoint ini hanya untuk testing/debug.
    """
    raw_events = search_latest_fim_events(size=size)

    analyzed_events = []

    for hit in raw_events:
        event = prepare_fim_event(hit)
        analyzed_event = attach_llm_analysis(event)
        analyzed_events.append(analyzed_event)

    return {
        "mode": "latest_analyze",
        "total": len(analyzed_events),
        "events": analyzed_events
    }


@app.post("/fim/daily/analyze")
def analyze_daily_fim_events(
    date: Optional[str] = Query(default=None, description="Format: YYYY-MM-DD. Jika kosong, otomatis tanggal kemarin."),
    size: int = Query(default=1000, ge=1, le=5000),
    batch_size: int = Query(default=5, ge=1, le=20),
    sleep_seconds: int = Query(default=2, ge=0, le=10)
):
    selected_date = date or get_yesterday_date()

    raw_count = count_fim_events_by_date(date=selected_date)
    raw_events = search_fim_events_by_date(date=selected_date, size=size)

    normalized_events = [
        prepare_fim_event(hit)
        for hit in raw_events
    ]

    deduplicated_events = deduplicate_fim_events(normalized_events)

    llm_candidates, rule_based_results = split_events_for_analysis(deduplicated_events)

    llm_results = analyze_llm_candidates_in_batches(
        llm_candidates=llm_candidates,
        batch_size=batch_size,
        sleep_seconds=sleep_seconds
    )

    final_results = rule_based_results + llm_results

    return {
        "mode": "daily_analyze",
        "date": selected_date,
        "raw_event_count": raw_count,
        "fetched_event_count": len(raw_events),
        "normalized_event_count": len(normalized_events),
        "deduplicated_event_count": len(deduplicated_events),
        "llm_candidate_count": len(llm_candidates),
        "rule_based_count": len(rule_based_results),
        "llm_batch_size": batch_size,
        "llm_batch_count": len(chunk_list(llm_candidates, batch_size)),
        "sleep_seconds_between_batches": sleep_seconds,
        "analyzed_event_count": len(final_results),
        "summary": summarize_analysis_results(final_results),
        "events": final_results
    }


@app.post("/fim/daily/analyze-and-send")
def analyze_daily_and_send_fim_events_batch(
    date: Optional[str] = Query(default=None, description="Format: YYYY-MM-DD. Jika kosong, otomatis tanggal kemarin."),
    size: Optional[int] = Query(default=None, ge=1, le=100000, description="Legacy alias untuk max_events."),
    max_events: Optional[int] = Query(default=None, ge=1, le=100000, description="Batas maksimal event yang diproses. Kosong berarti proses semua hasil query."),
    page_size: int = Query(default=1000, ge=100, le=5000, description="Jumlah dokumen Wazuh per scroll page."),
    batch_size: int = Query(default=5, ge=1, le=20),
    sleep_seconds: int = Query(default=2, ge=0, le=10),
    include_results: bool = Query(default=False, description="Jika true, response menyertakan detail event dan response Laravel.")
):
    selected_date = date or get_yesterday_date()
    effective_max_events = max_events or size

    raw_count = count_fim_events_by_date(date=selected_date)

    page_count = 0
    fetched_event_count = 0
    normalized_event_count = 0
    sent_count = 0
    failed_send_count = 0
    sent_results = []
    error_samples = []
    page_deduplicated_events = []

    for page_count, raw_events in enumerate(
        iter_fim_events_by_date(
            date=selected_date,
            page_size=page_size,
            max_events=effective_max_events
        ),
        start=1
    ):
        fetched_event_count += len(raw_events)

        normalized_events = [
            prepare_fim_event(hit)
            for hit in raw_events
        ]
        normalized_event_count += len(normalized_events)

        page_deduplicated_events.extend(
            deduplicate_fim_events(normalized_events)
        )

    deduplicated_events = deduplicate_fim_events(page_deduplicated_events)

    llm_candidates, rule_based_results = split_events_for_analysis(deduplicated_events)

    llm_results = analyze_llm_candidates_in_batches(
        llm_candidates=llm_candidates,
        batch_size=batch_size,
        sleep_seconds=sleep_seconds
    )

    final_results = rule_based_results + llm_results
    summary = summarize_analysis_results(final_results)

    for event in final_results:
        try:
            laravel_response = send_analysis_to_laravel(event)
            sent_count += 1

            if include_results:
                sent_results.append({
                    "event": event,
                    "laravel_response": laravel_response
                })
        except Exception as error:
            failed_send_count += 1

            if len(error_samples) < 10:
                error_samples.append({
                    "wazuh_alert_id": event.get("wazuh_alert_id"),
                    "indexer_doc_id": event.get("indexer_doc_id"),
                    "file_path": event.get("file_path"),
                    "error": str(error)
                })

    response = {
        "mode": "daily_analyze_and_send",
        "date": selected_date,
        "raw_event_count": raw_count,
        "max_events": effective_max_events,
        "page_size": page_size,
        "page_count": page_count,
        "fetched_event_count": fetched_event_count,
        "normalized_event_count": normalized_event_count,
        "deduplicated_event_count": len(deduplicated_events),
        "llm_candidate_count": len(llm_candidates),
        "rule_based_count": len(rule_based_results),
        "llm_batch_size": batch_size,
        "sleep_seconds_between_batches": sleep_seconds,
        "analyzed_event_count": len(final_results),
        "sent_count": sent_count,
        "failed_send_count": failed_send_count,
        "summary": summary,
        "send_error_samples": error_samples
    }

    if include_results:
        response["results"] = sent_results

    return response


@app.post("/fim/analyze-and-send/daily")
def analyze_daily_and_send_fim_events_single(
    date: Optional[str] = Query(default=None, description="Format: YYYY-MM-DD. Jika kosong, otomatis tanggal kemarin."),
    size: int = Query(default=1000, ge=1, le=5000)
):
    """
    Menganalisis event FIM berdasarkan tanggal lalu mengirim hasilnya ke Laravel.
    Flow:
    raw event -> normalisasi -> deduplicate -> rule-based filter -> LLM candidates -> send to Laravel.
    """

    selected_date = date or get_yesterday_date()

    raw_count = count_fim_events_by_date(date=selected_date)
    raw_events = search_fim_events_by_date(date=selected_date, size=size)

    normalized_events = [
        prepare_fim_event(hit)
        for hit in raw_events
    ]

    deduplicated_events = deduplicate_fim_events(normalized_events)

    llm_candidates, rule_based_results = split_events_for_analysis(deduplicated_events)

    llm_results = []

    for event in llm_candidates:
        analyzed_event = attach_llm_analysis(event)
        llm_results.append(analyzed_event)

    final_results = rule_based_results + llm_results

    sent_results = []

    for event in final_results:
        laravel_response = send_analysis_to_laravel(event)

        sent_results.append({
            "event": event,
            "laravel_response": laravel_response
        })

    return {
        "mode": "daily_analyze_and_send",
        "date": selected_date,
        "raw_event_count": raw_count,
        "fetched_event_count": len(raw_events),
        "normalized_event_count": len(normalized_events),
        "deduplicated_event_count": len(deduplicated_events),
        "llm_candidate_count": len(llm_candidates),
        "rule_based_count": len(rule_based_results),
        "sent_count": len(sent_results),
        "summary": summarize_analysis_results(final_results),
        "results": sent_results
    }
