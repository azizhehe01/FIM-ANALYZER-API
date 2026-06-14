from typing import Any, Dict, List, Tuple


def safe_int(value: Any, default: int = 0) -> int:
    """
    Mengubah value menjadi integer dengan aman.
    """

    try:
        if value is None:
            return default

        return int(value)

    except Exception:
        return default


def deduplicate_fim_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Menggabungkan event FIM yang mirip agar tidak dianalisis berulang oleh LLM.

    Key pengelompokan:
    - agent_id
    - file_path
    - event_type
    - rule_id

    Contoh:
    Jika file yang sama berubah 10 kali dalam satu hari,
    maka cukup jadi 1 record dengan occurrence_count = 10.
    """

    grouped_events = {}

    for event in events:
        key = (
            event.get("agent_id"),
            event.get("file_path"),
            event.get("event_type"),
            event.get("rule_id")
        )

        if key not in grouped_events:
            grouped_events[key] = {
                **event,
                "occurrence_count": 1,
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp")
            }
        else:
            grouped_events[key]["occurrence_count"] += 1
            grouped_events[key]["last_seen"] = event.get("timestamp")

            # Simpan rule level paling tinggi kalau ada event serupa
            current_level = safe_int(grouped_events[key].get("rule_level"))
            new_level = safe_int(event.get("rule_level"))

            if new_level > current_level:
                grouped_events[key]["rule_level"] = new_level
                grouped_events[key]["rule_description"] = event.get("rule_description")

            # Gabungkan risk_hints
            old_hints = grouped_events[key].get("risk_hints", [])
            new_hints = event.get("risk_hints", [])

            merged_hints = list(dict.fromkeys(old_hints + new_hints))
            grouped_events[key]["risk_hints"] = merged_hints

            if merged_hints:
                grouped_events[key]["risk_hint"] = merged_hints[0]

    return list(grouped_events.values())


def is_high_risk_candidate(event: Dict[str, Any]) -> bool:
    """
    Menentukan apakah event perlu dikirim ke LLM.
    """

    file_path = (event.get("file_path") or "").lower()
    event_type = (event.get("event_type") or "").lower()
    file_extension = (event.get("file_extension") or "").lower()
    risk_hints = [hint.lower() for hint in event.get("risk_hints", [])]
    changed_attributes = [
        attr.lower()
        for attr in event.get("changed_attributes", [])
    ]

    rule_level = safe_int(event.get("rule_level"))
    occurrence_count = safe_int(event.get("occurrence_count"), default=1)

    high_risk_hints = [
        "critical_system_file_changed",
        "sensitive_config_file_changed",
        "startup_or_persistence_file_changed",
        "suspicious_filename_or_path",
        "executable_or_script_file_changed",
        "file_deleted",
        "file_became_empty",
        "permission_changed",
        "ownership_changed",
        "high_wazuh_rule_level"
    ]

    medium_risk_hints = [
        "web_file_changed",
        "upload_directory_file_changed",
        "medium_wazuh_rule_level"
    ]

    high_risk_keywords = [
        ".env",
        ".htaccess",
        "wp-config.php",
        "index.php",
        "functions.php",
        "configuration.php",
        "config.php",
        "database.php",
        "authorized_keys",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "sshd_config",
        "nginx.conf",
        "apache2.conf",
        "httpd.conf",
        "php.ini",
        "shell",
        "webshell",
        "backdoor",
        "eval",
        "base64",
        "cmd",
        "payload",
        "privkey.pem",
        "fullchain.pem",
        "cert.pem",
        "chain.pem",
        "/etc/letsencrypt/",
        "/etc/postfix/",
        "vmail_ssl.map.db"
    ]

    executable_extensions = [
        ".php",
        ".sh",
        ".py",
        ".pl",
        ".cgi",
        ".js"
    ]

    static_extensions = [
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".svg",
        ".css",
        ".map",
        ".txt",
        ".html"
    ]

    only_mtime_changed = changed_attributes == ["mtime"]
    # 0. File statis yang hanya berubah mtime dianggap tidak perlu LLM,
    # kecuali file menjadi kosong.
    if file_extension in static_extensions and only_mtime_changed and not event.get("is_empty_file"):
        return False

    # 1. Hint risiko tinggi langsung masuk LLM
    if any(hint in risk_hints for hint in high_risk_hints):
        return True

    # 2. File/path sensitif langsung masuk LLM
    if any(keyword in file_path for keyword in high_risk_keywords):
        return True

    # 3. Script/executable langsung masuk LLM
    if file_extension in executable_extensions:
        return True

    # 4. Event delete perlu dianalisis
    if "delete" in event_type or "deleted" in event_type:
        return True

    # 5. Rule level tinggi perlu dianalisis
    if rule_level >= 10:
        return True

    # 6. File web berubah berulang kali dalam sehari perlu dianalisis
    if "web_file_changed" in risk_hints and occurrence_count >= 5:
        return True

    # 7. Upload directory berubah berulang kali perlu dianalisis
    if "upload_directory_file_changed" in risk_hints and occurrence_count >= 5:
        return True

    # 8. File web level 7 tidak otomatis masuk LLM,
    # kecuali punya indikator tambahan yang lebih berisiko.
    if rule_level >= 7 and any(hint in risk_hints for hint in medium_risk_hints):
        if event.get("is_empty_file"):
            return True

        if occurrence_count >= 5:
            return True

        if file_extension in executable_extensions:
            return True

        if any(keyword in file_path for keyword in high_risk_keywords):
            return True

    return False


def is_low_risk_event(event: Dict[str, Any]) -> bool:
    """
    Menentukan apakah event kemungkinan rendah risiko.
    """

    file_path = (event.get("file_path") or "").lower()
    file_extension = (event.get("file_extension") or "").lower()
    changed_attributes = [
        attr.lower()
        for attr in event.get("changed_attributes", [])
    ]

    low_risk_paths = [
        "/cache/",
        "/logs/",
        "/tmp/",
        "/temp/",
        "/sessions/",
        "/node_modules/",
        "/vendor/composer/"
    ]

    low_risk_extensions = [
        ".log",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".svg",
        ".css",
        ".map",
        ".txt"
    ]

    only_mtime_changed = changed_attributes == ["mtime"]

    if any(path in file_path for path in low_risk_paths):
        return True

    if file_extension in low_risk_extensions and only_mtime_changed:
        return True

    if only_mtime_changed:
        return True

    return False


def apply_rule_based_classification(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Memberi klasifikasi otomatis untuk event yang tidak dikirim ke LLM.
    """

    file_path = (event.get("file_path") or "").lower()
    file_extension = (event.get("file_extension") or "").lower()
    risk_hints = [hint.lower() for hint in event.get("risk_hints", [])]
    rule_level = safe_int(event.get("rule_level"))

    classification = "aman"
    risk_score = 10
    reason = "Event tidak memenuhi kriteria risiko tinggi berdasarkan rule-based filtering."
    recommendation = "Tidak diperlukan tindakan khusus, namun event tetap disimpan sebagai catatan monitoring."

    # Kalau event web tapi tidak cukup berisiko untuk LLM, jadikan aman dengan catatan.
    if "web_file_changed" in risk_hints or "upload_directory_file_changed" in risk_hints:
        classification = "aman"
        risk_score = 25
        reason = "Event berada pada direktori web, tetapi tidak memenuhi indikator risiko tinggi seperti file konfigurasi, script, penghapusan file, atau perubahan berulang yang signifikan."
        recommendation = "Tetap lakukan pemantauan berkala terhadap perubahan file web."

    # Kalau rule level cukup sedang tapi tidak masuk LLM, beri skor sedikit lebih tinggi.
    if rule_level >= 7:
        risk_score = max(risk_score, 30)

    # File statis umum lebih rendah risiko.
    if file_extension in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".css", ".log"]:
        risk_score = min(risk_score, 15)

    # Jika hanya mtime berubah, catatan khusus.
    if "only_mtime_changed" in risk_hints:
        classification = "aman"
        risk_score = min(risk_score, 15)
        reason = "Event hanya menunjukkan perubahan waktu modifikasi file tanpa perubahan atribut berisiko lainnya."
        recommendation = "Tidak diperlukan tindakan khusus kecuali terdapat pola perubahan berulang yang tidak wajar."

    return {
        **event,
        "classification": classification,
        "risk_score": risk_score,
        "reason": reason,
        "recommendation": recommendation,
        "analysis_source": "rule_based"
    }


def split_events_for_analysis(
    events: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Memisahkan event menjadi:
    1. kandidat LLM
    2. hasil rule-based

    Return:
    llm_candidates, rule_based_results
    """

    llm_candidates = []
    rule_based_results = []

    for event in events:
        if is_high_risk_candidate(event):
            llm_candidates.append(event)
        else:
            rule_based_results.append(
                apply_rule_based_classification(event)
            )

    return llm_candidates, rule_based_results


def summarize_analysis_results(events: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Membuat ringkasan jumlah hasil klasifikasi.
    """

    summary = {
        "aman": 0,
        "mencurigakan": 0,
        "berbahaya": 0,
        "unknown": 0
    }

    for event in events:
        classification = event.get("classification")

        if classification in summary:
            summary[classification] += 1
        else:
            summary["unknown"] += 1

    return summary