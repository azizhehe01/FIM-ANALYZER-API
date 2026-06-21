from typing import Any, Dict, List, Tuple

PHP_FILE_ADDED_RULE_ID = "100200"
PHP_FILE_MODIFIED_RULE_ID = "100201"
PHP_FILE_DELETED_RULE_ID = "100202"
CUSTOM_PHP_RULE_IDS = {
    PHP_FILE_ADDED_RULE_ID,
    PHP_FILE_MODIFIED_RULE_ID,
    PHP_FILE_DELETED_RULE_ID
}


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


def is_custom_php_event(event: Dict[str, Any]) -> bool:
    rule_id = str(event.get("rule_id") or "")
    file_extension = (event.get("file_extension") or "").lower()

    return rule_id in CUSTOM_PHP_RULE_IDS or file_extension == ".php"


# Berkas PHP/non-PHP yang diketahui normal ada di folder wflogs Wordfence.
# Referensi: https://www.wordfence.com/help/firewall/
WORDFENCE_WFLOGS_KNOWN_FILES = {
    ".htaccess",
    "attack-data.php",
    "config.php",
    "config-livewaf.php",
    "config-synced.php",
    "config-transient.php",
    "config-array.php",
    "config-plugins.php",
    "config-waf.php",
    "ips.php",
    "rules.php",
    "template.php",
    "wordfence-waf.php",
    "wfBrowscapCache.php",
    "GeoLite2-Country.mmdb",
}


def has_any_keyword(text: str, keywords: List[str]) -> bool:
    return any(keyword in text for keyword in keywords)


def get_file_name(file_path: str) -> str:
    normalized_path = file_path.replace("\\", "/")
    return normalized_path.rsplit("/", 1)[-1]


def get_php_file_stem(file_path: str) -> str:
    file_name = get_file_name(file_path)

    if not file_name.lower().endswith(".php"):
        return file_name

    return file_name[:-4]


def is_directly_under_path(file_path: str, directory_marker: str) -> bool:
    normalized_path = file_path.replace("\\", "/")

    if directory_marker not in normalized_path:
        return False

    remainder = normalized_path.split(directory_marker, 1)[1]

    return "/" not in remainder.strip("/")


def is_wordpress_plugin_or_theme_path(file_path: str) -> bool:
    normalized_path = file_path.replace("\\", "/").lower()

    wordpress_code_paths = [
        "/wp-content/plugins/",
        "/wp_content/plugins/",
        "/wp-content/themes/",
        "/wp_content/themes/"
    ]

    return has_any_keyword(normalized_path, wordpress_code_paths)


def is_normal_wordpress_plugin_or_theme_file(file_path: str) -> bool:
    """
    File normal plugin/theme biasanya berada di bawah folder slug plugin/theme,
    bukan langsung di root wp-content/plugins atau wp-content/themes.
    """

    normalized_path = file_path.replace("\\", "/").lower()

    if not is_wordpress_plugin_or_theme_path(normalized_path):
        return False

    return not (
        is_directly_under_path(normalized_path, "/wp-content/plugins/")
        or is_directly_under_path(normalized_path, "/wp_content/plugins/")
        or is_directly_under_path(normalized_path, "/wp-content/themes/")
        or is_directly_under_path(normalized_path, "/wp_content/themes/")
    )


def is_random_like_php_filename(file_path: str) -> bool:
    """
    Mendeteksi nama file PHP yang terlihat acak/obfuscated seperti oML9G.php.
    Heuristic ini sengaja konservatif dan dipakai sebagai sinyal untuk LLM,
    bukan langsung memutuskan event berbahaya.
    """

    stem = get_php_file_stem(file_path)
    lower_stem = stem.lower()

    common_php_names = {
        "index",
        "functions",
        "config",
        "wp-config",
        "autoload",
        "composer",
        "install",
        "uninstall",
        "upgrade",
        "admin",
        "init",
        "ajax",
        "api",
        "router",
        "helper",
        "helpers"
    }

    if lower_stem in common_php_names:
        return False

    if len(stem) < 5 or len(stem) > 16:
        return False

    if not stem.isalnum():
        return False

    has_lowercase = any(char.islower() for char in stem)
    has_uppercase = any(char.isupper() for char in stem)
    has_digit = any(char.isdigit() for char in stem)

    if has_digit and has_lowercase and has_uppercase:
        return True

    if has_digit and sum(char.isdigit() for char in stem) >= 2:
        return True

    return False


def is_php_event_llm_candidate(event: Dict[str, Any]) -> bool:
    """
    Menentukan event PHP mana yang benar-benar perlu dikirim ke LLM.
    Event PHP yang tidak lolos tetap dikirim ke Laravel sebagai rule_based,
    sehingga volume LLM bisa ditekan tanpa kehilangan visibilitas.
    """

    rule_id = str(event.get("rule_id") or "")
    file_path = (event.get("file_path") or "").lower()
    event_type = (event.get("event_type") or "").lower()
    risk_hints = [hint.lower() for hint in event.get("risk_hints", [])]
    changed_attributes = [
        attr.lower()
        for attr in event.get("changed_attributes", [])
    ]

    occurrence_count = safe_int(event.get("occurrence_count"), default=1)
    diff_text = str(event.get("diff") or event.get("full_log") or "").lower()

    sensitive_php_files = [
        ".env",
        ".htaccess",
        "wp-config.php",
        "configuration.php",
        "config.php",
        "database.php",
        "index.php",
        "functions.php",
        "php.ini",
        ".user.ini"
    ]

    risky_write_paths = [
        "/uploads/",
        "/wp-content/uploads/",
        "/wp_content/uploads/",
        "/cache/",
        "/tmp/",
        "/temp/",
        "/sessions/"
    ]

    suspicious_path_keywords = [
        "shell",
        "webshell",
        "backdoor",
        "payload",
        "cmd",
        "bypass",
        "mailer",
        "priv8",
        "wso",
        "c99",
        "r57"
    ]

    suspicious_php_content = [
        "eval(",
        "base64_decode",
        "gzinflate",
        "str_rot13",
        "shell_exec",
        "passthru",
        "system(",
        "exec(",
        "assert(",
        "popen(",
        "proc_open",
        "$_post",
        "$_get",
        "$_request",
        "move_uploaded_file",
        "chmod(",
        "curl_exec"
    ]

    is_added = rule_id == PHP_FILE_ADDED_RULE_ID or "added" in event_type or "created" in event_type
    is_modified = rule_id == PHP_FILE_MODIFIED_RULE_ID or "modified" in event_type
    is_deleted = rule_id == PHP_FILE_DELETED_RULE_ID or "delete" in event_type or "deleted" in event_type

    is_sensitive_file = has_any_keyword(file_path, sensitive_php_files)
    is_risky_write_path = has_any_keyword(file_path, risky_write_paths)
    is_wordpress_code_path = is_wordpress_plugin_or_theme_path(file_path)
    is_direct_wordpress_code_file = (
        is_directly_under_path(file_path, "/wp-content/plugins/")
        or is_directly_under_path(file_path, "/wp_content/plugins/")
        or is_directly_under_path(file_path, "/wp-content/themes/")
        or is_directly_under_path(file_path, "/wp_content/themes/")
    )
    has_random_like_name = is_random_like_php_filename(file_path)
    has_suspicious_path = has_any_keyword(file_path, suspicious_path_keywords)
    has_suspicious_content = has_any_keyword(diff_text, suspicious_php_content)

    if event.get("is_empty_file"):
        return True

    if "permission_changed" in risk_hints or "ownership_changed" in risk_hints:
        return True

    if "perm" in changed_attributes or "permission" in changed_attributes:
        return True

    if "uid" in changed_attributes or "gid" in changed_attributes:
        return True

    if has_suspicious_path or has_suspicious_content:
        return True

    if is_risky_write_path:
        return True

    if is_wordpress_code_path and (has_random_like_name or is_direct_wordpress_code_file):
        return True

    if is_added:
        return is_sensitive_file or has_random_like_name or occurrence_count >= 3

    if is_modified:
        return is_sensitive_file or has_random_like_name or occurrence_count >= 10

    if is_deleted:
        return is_sensitive_file or has_random_like_name or occurrence_count >= 5

    return False


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


def is_wordfence_logs_path(file_path: str) -> bool:
    """
    Mendeteksi apakah path berkas berada di dalam folder wflogs Wordfence.
    """
    return "wp-content/wflogs" in file_path or "wp_content/wflogs" in file_path


def is_known_wordfence_file(file_path: str) -> bool:
    """
    Mendeteksi apakah berkas termasuk dalam daftar berkas resmi Wordfence.
    Perbandingan dilakukan berdasarkan nama berkas (case-insensitive).
    """
    file_name = get_file_name(file_path).lower()
    known_files_lower = {f.lower() for f in WORDFENCE_WFLOGS_KNOWN_FILES}
    return file_name in known_files_lower


def is_high_risk_candidate(event: Dict[str, Any]) -> bool:
    """
    Menentukan apakah event perlu dikirim ke LLM.
    """

    file_path = (event.get("file_path") or "").lower()

    # Berkas di dalam direktori WordPress upgrade diabaikan dari analisis LLM
    if "wp-content/upgrade" in file_path or "wp_content/upgrade" in file_path:
        return False

    # Berkas di dalam wflogs Wordfence:
    # - Jika berkas dikenal (normal) -> tidak perlu LLM
    # - Jika berkas tidak dikenal (anomali) -> bypass LLM, langsung berbahaya via rule-based
    if is_wordfence_logs_path(file_path):
        return False
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

    if is_custom_php_event(event):
        return is_php_event_llm_candidate(event)

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

    # Berkas di dalam direktori WordPress upgrade langsung diklasifikasikan sebagai aman
    if "wp-content/upgrade" in file_path or "wp_content/upgrade" in file_path:
        return {
            **event,
            "classification": "aman",
            "risk_score": 15,
            "reason": "Event terjadi di dalam direktori upgrade WordPress sementara selama proses instalasi/pembaruan resmi.",
            "recommendation": "Tidak diperlukan tindakan khusus. Berkas ini bersifat sementara dan biasanya dihapus otomatis oleh WordPress.",
            "analysis_source": "rule_based"
        }

    # Berkas di dalam folder wflogs Wordfence
    if is_wordfence_logs_path(file_path):
        if is_known_wordfence_file(file_path):
            return {
                **event,
                "classification": "aman",
                "risk_score": 10,
                "reason": "Event berasal dari berkas internal Wordfence yang dikenal di dalam folder wflogs. Perubahan pada berkas ini adalah perilaku normal plugin keamanan Wordfence saat memperbarui konfigurasi WAF, data serangan, atau aturan firewall.",
                "recommendation": "Tidak diperlukan tindakan khusus. Pantau jika terjadi perubahan di luar jadwal pembaruan Wordfence yang normal.",
                "analysis_source": "rule_based"
            }
        else:
            # Berkas tidak dikenal ditemukan di dalam folder wflogs -> sangat mencurigakan
            # Penyerang bisa menyembunyikan webshell di dalam folder plugin keamanan
            return {
                **event,
                "classification": "berbahaya",
                "risk_score": 90,
                "reason": "Berkas yang tidak dikenal ditemukan di dalam folder wflogs Wordfence. Folder ini seharusnya hanya berisi berkas internal resmi Wordfence. Keberadaan berkas asing di sini merupakan indikator kuat adanya webshell atau backdoor yang sengaja disembunyikan di dalam folder plugin keamanan.",
                "recommendation": "Segera periksa berkas ini secara manual. Hapus berkas jika tidak terkait dengan Wordfence dan lakukan pemindaian malware menyeluruh pada server.",
                "analysis_source": "rule_based"
            }
    file_extension = (event.get("file_extension") or "").lower()
    risk_hints = [hint.lower() for hint in event.get("risk_hints", [])]
    rule_level = safe_int(event.get("rule_level"))
    rule_id = str(event.get("rule_id") or "")

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

    if rule_id in CUSTOM_PHP_RULE_IDS or file_extension == ".php":
        classification = "mencurigakan"
        risk_score = max(risk_score, 35)
        reason = "Event PHP custom tidak memenuhi kriteria prioritas LLM, tetapi tetap perlu dicatat karena terkait perubahan file PHP."
        recommendation = "Pantau pola perubahan file PHP dan review manual jika berasal dari direktori upload, cache, atau terjadi berulang."

        if is_normal_wordpress_plugin_or_theme_file(file_path):
            classification = "aman"
            risk_score = 25
            reason = "Event berada di struktur normal plugin/theme WordPress dan tidak memenuhi indikator prioritas seperti nama acak, path upload/cache/tmp, file sensitif, konten mencurigakan, atau perubahan berulang."
            recommendation = "Anggap sebagai perubahan plugin/theme yang wajar jika sesuai jadwal update atau maintenance WordPress."

            if rule_id == PHP_FILE_ADDED_RULE_ID:
                risk_score = 30
                reason = "Terdapat penambahan file PHP di struktur normal plugin/theme WordPress tanpa indikator mencurigakan prioritas."
            elif rule_id == PHP_FILE_DELETED_RULE_ID:
                risk_score = 30
                reason = "Terdapat penghapusan file PHP di struktur normal plugin/theme WordPress tanpa indikator mencurigakan prioritas."
        elif rule_id == PHP_FILE_ADDED_RULE_ID:
            risk_score = max(risk_score, 45)
            reason = "Terdapat penambahan file PHP, namun tidak ditemukan indikator kuat seperti path upload, nama mencurigakan, konten berbahaya, atau perubahan berulang."
            recommendation = "Validasi apakah file PHP baru berasal dari deployment resmi."
        elif rule_id == PHP_FILE_MODIFIED_RULE_ID:
            risk_score = max(risk_score, 40)
            reason = "Terdapat modifikasi file PHP, namun tidak memenuhi indikator prioritas untuk analisis LLM."
            recommendation = "Cocokkan perubahan dengan aktivitas deployment atau update aplikasi."
        elif rule_id == PHP_FILE_DELETED_RULE_ID:
            risk_score = max(risk_score, 40)
            reason = "Terdapat penghapusan file PHP, namun file tidak termasuk path sensitif atau pola berulang prioritas LLM."
            recommendation = "Pastikan penghapusan file PHP sesuai aktivitas maintenance atau deployment."

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
