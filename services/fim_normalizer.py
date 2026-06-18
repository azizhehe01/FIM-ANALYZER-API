import os
from typing import Any, Dict, List, Optional


EMPTY_FILE_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_FILE_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


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


def safe_list(value: Any) -> List[str]:
    """
    Memastikan value menjadi list string.
    """

    if value is None:
        return []

    if isinstance(value, list):
        return [str(item) for item in value]

    return [str(value)]


def truncate_text(value: Any, max_length: int = 1000) -> Optional[str]:
    """
    Memotong teks panjang agar payload LLM batch tidak melewati context limit.
    """

    if value is None:
        return None

    text = str(value)

    if len(text) <= max_length:
        return text

    return text[:max_length] + "...[truncated]"


def get_file_extension(file_path: Optional[str]) -> Optional[str]:
    """
    Mengambil ekstensi file dari path.
    """

    if not file_path:
        return None

    _, extension = os.path.splitext(file_path.lower())

    if not extension:
        return None

    return extension


def is_empty_file_event(event: Dict[str, Any]) -> bool:
    """
    Mendeteksi apakah event menunjukkan file kosong.
    Berdasarkan size_after atau hash umum file kosong.
    """

    size_after = safe_int(event.get("size_after"), default=-1)

    if size_after == 0:
        return True

    if event.get("new_md5") == EMPTY_FILE_MD5:
        return True

    if event.get("new_sha1") == EMPTY_FILE_SHA1:
        return True

    if event.get("new_sha256") == EMPTY_FILE_SHA256:
        return True

    return False


def normalize_fim_event(hit: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mengubah data mentah Wazuh menjadi format ringkas.
    Format ini dipakai untuk preprocessing, filtering, penyimpanan database,
    dan sebagian field-nya dikirim ke LLM.
    """

    source = hit.get("_source", {})

    syscheck = source.get("syscheck", {})
    agent = source.get("agent", {})
    rule = source.get("rule", {})
    data = source.get("data", {})

    indexer_doc_id = hit.get("_id")
    wazuh_alert_id = source.get("id")
    timestamp = source.get("@timestamp") or source.get("timestamp")

    file_path = (
        syscheck.get("path")
        or syscheck.get("file")
        or source.get("full_log")
    )

    event_type = (
        syscheck.get("event")
        or syscheck.get("mode")
        or rule.get("description")
    )

    user_name = (
        syscheck.get("audit", {}).get("login_user", {}).get("name")
        or syscheck.get("audit", {}).get("effective_user", {}).get("name")
        or syscheck.get("uname_after")
        or syscheck.get("uname_before")
        or data.get("dstuser")
    )

    process_name = (
        syscheck.get("audit", {}).get("process", {}).get("name")
        or syscheck.get("audit", {}).get("process", {}).get("path")
    )

    changed_attributes = safe_list(syscheck.get("changed_attributes"))

    normalized_event = {
        "wazuh_alert_id": wazuh_alert_id,
        "indexer_doc_id": indexer_doc_id,
        "timestamp": timestamp,

        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "agent_id": agent.get("id"),

        "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
        "rule_level": safe_int(rule.get("level")),
        "rule_description": rule.get("description"),
        "rule_groups": safe_list(rule.get("groups")),

        "mitre_ids": safe_list(rule.get("mitre", {}).get("id")),
        "mitre_tactics": safe_list(rule.get("mitre", {}).get("tactic")),
        "mitre_techniques": safe_list(rule.get("mitre", {}).get("technique")),

        "decoder_name": source.get("decoder", {}).get("name"),
        "location": source.get("location"),

        "file_path": file_path,
        "file_extension": get_file_extension(file_path),
        "event_type": event_type,
        "changed_attributes": changed_attributes,

        "user_name": user_name,
        "process_name": process_name,

        "size_before": syscheck.get("size_before"),
        "size_after": syscheck.get("size_after"),

        "perm_before": syscheck.get("perm_before"),
        "perm_after": syscheck.get("perm_after"),

        "uid_before": syscheck.get("uid_before"),
        "uid_after": syscheck.get("uid_after"),
        "gid_before": syscheck.get("gid_before"),
        "gid_after": syscheck.get("gid_after"),

        "uname_before": syscheck.get("uname_before"),
        "uname_after": syscheck.get("uname_after"),
        "gname_before": syscheck.get("gname_before"),
        "gname_after": syscheck.get("gname_after"),

        "mtime_before": syscheck.get("mtime_before"),
        "mtime_after": syscheck.get("mtime_after"),

        "old_md5": syscheck.get("md5_before"),
        "new_md5": syscheck.get("md5_after"),
        "old_sha1": syscheck.get("sha1_before"),
        "new_sha1": syscheck.get("sha1_after"),
        "old_sha256": syscheck.get("sha256_before"),
        "new_sha256": syscheck.get("sha256_after"),

        "diff": syscheck.get("diff"),
        "full_log": source.get("full_log"),

        "raw_event": source
    }

    normalized_event["is_empty_file"] = is_empty_file_event(normalized_event)

    return normalized_event


def add_risk_hint(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Memberi petunjuk awal sebelum dianalisis LLM.
    Risk hint bukan keputusan final, tapi dipakai untuk filtering dan konteks LLM.
    """

    file_path = (event.get("file_path") or "").lower()
    event_type = (event.get("event_type") or "").lower()
    rule_level = safe_int(event.get("rule_level"))
    changed_attributes = [attr.lower() for attr in event.get("changed_attributes", [])]
    file_extension = (event.get("file_extension") or "").lower()

    risk_hints = []

    critical_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/root/.ssh/authorized_keys",
        "authorized_keys",
        "c:\\windows\\system32"
    ]

    sensitive_config_files = [
        ".env",
        ".htaccess",
        "wp-config.php",
        "nginx.conf",
        "apache2.conf",
        "httpd.conf",
        "my.cnf",
        "php.ini"
    ]

    web_paths = [
        "/var/www",
        "/public_html",
        "/wp-content",
        "/wp-admin",
        "/wp-includes"
    ]

    upload_paths = [
        "/uploads/",
        "/wp-content/uploads/"
    ]

    startup_or_persistence_paths = [
        "startup",
        "/etc/cron",
        "/var/spool/cron",
        "/etc/systemd/system",
        "/etc/init.d"
    ]

    suspicious_keywords = [
        "shell",
        "backdoor",
        "webshell",
        "eval",
        "base64",
        "cmd",
        "payload"
    ]

    executable_extensions = [
        ".php",
        ".sh",
        ".py",
        ".pl",
        ".cgi",
        ".js"
    ]

    low_risk_paths = [
        "/cache/",
        "/logs/",
        "/tmp/",
        "/temp/"
    ]

    low_risk_extensions = [
        ".log",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".svg",
        ".css"
    ]

    if any(item in file_path for item in critical_files):
        risk_hints.append("critical_system_file_changed")

    if any(item in file_path for item in sensitive_config_files):
        risk_hints.append("sensitive_config_file_changed")

    if any(item in file_path for item in startup_or_persistence_paths):
        risk_hints.append("startup_or_persistence_file_changed")

    if any(item in file_path for item in web_paths):
        risk_hints.append("web_file_changed")

    if any(item in file_path for item in upload_paths):
        risk_hints.append("upload_directory_file_changed")

    if any(item in file_path for item in suspicious_keywords):
        risk_hints.append("suspicious_filename_or_path")

    if file_extension in executable_extensions:
        risk_hints.append("executable_or_script_file_changed")

    if "deleted" in event_type or "delete" in event_type:
        risk_hints.append("file_deleted")

    if event.get("is_empty_file"):
        risk_hints.append("file_became_empty")

    if rule_level >= 10:
        risk_hints.append("high_wazuh_rule_level")
    elif rule_level >= 7:
        risk_hints.append("medium_wazuh_rule_level")

    if "perm" in changed_attributes or "permission" in changed_attributes:
        risk_hints.append("permission_changed")

    if "uid" in changed_attributes or "gid" in changed_attributes:
        risk_hints.append("ownership_changed")

    only_mtime_changed = changed_attributes == ["mtime"]

    is_low_risk_path = any(item in file_path for item in low_risk_paths)
    is_low_risk_extension = file_extension in low_risk_extensions

    if not risk_hints:
        if only_mtime_changed:
            risk_hints.append("only_mtime_changed")
        elif is_low_risk_path or is_low_risk_extension:
            risk_hints.append("low_risk_file_changed")
        else:
            risk_hints.append("normal_change")

    event["risk_hints"] = risk_hints
    event["risk_hint"] = risk_hints[0]

    return event


def build_llm_event_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Membuat payload ringkas untuk dikirim ke LLM.
    raw_event tidak dikirim supaya prompt tidak membengkak.
    """

    return {
        "wazuh_alert_id": event.get("wazuh_alert_id"),
        "indexer_doc_id": event.get("indexer_doc_id"),
        "timestamp": event.get("timestamp"),

        "agent_name": event.get("agent_name"),
        "agent_ip": event.get("agent_ip"),
        "agent_id": event.get("agent_id"),

        "rule_id": event.get("rule_id"),
        "rule_level": event.get("rule_level"),
        "rule_description": event.get("rule_description"),
        "rule_groups": event.get("rule_groups"),

        "mitre_ids": event.get("mitre_ids"),
        "mitre_tactics": event.get("mitre_tactics"),
        "mitre_techniques": event.get("mitre_techniques"),

        "file_path": event.get("file_path"),
        "file_extension": event.get("file_extension"),
        "event_type": event.get("event_type"),
        "changed_attributes": event.get("changed_attributes"),

        "user_name": event.get("user_name"),
        "process_name": event.get("process_name"),

        "size_before": event.get("size_before"),
        "size_after": event.get("size_after"),
        "perm_before": event.get("perm_before"),
        "perm_after": event.get("perm_after"),
        "uid_before": event.get("uid_before"),
        "uid_after": event.get("uid_after"),
        "gid_before": event.get("gid_before"),
        "gid_after": event.get("gid_after"),

        "old_md5": event.get("old_md5"),
        "new_md5": event.get("new_md5"),
        "old_sha1": event.get("old_sha1"),
        "new_sha1": event.get("new_sha1"),
        "old_sha256": event.get("old_sha256"),
        "new_sha256": event.get("new_sha256"),

        "is_empty_file": event.get("is_empty_file"),
        "risk_hint": event.get("risk_hint"),
        "risk_hints": event.get("risk_hints"),
        "occurrence_count": event.get("occurrence_count"),
        "first_seen": event.get("first_seen"),
        "last_seen": event.get("last_seen"),
        "diff": truncate_text(event.get("diff"), max_length=1200),
        "full_log": truncate_text(event.get("full_log"), max_length=800)
    }
