"""Custom render views for Censys SOAR action widgets."""

from __future__ import annotations

from typing import Any


def _safe_get(d: dict[str, Any], dotpath: str, default: Any = None) -> Any:
    """Nested dict access via dot-separated path."""
    current: Any = d
    for key in dotpath.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def _ensure_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _extract_cert_fields(cert: dict[str, Any]) -> dict[str, Any]:
    """Extract cert fields from canonical Censys cert schema."""
    parsed = cert.get("parsed", {})
    common_names = _ensure_list(_safe_get(parsed, "subject.common_name", []))
    common_names = [str(name) for name in common_names if name is not None]

    return {
        "fingerprint_sha256": cert.get("fingerprint_sha256"),
        "subject_dn": _safe_get(parsed, "subject_dn"),
        "issuer_dn": _safe_get(parsed, "issuer_dn"),
        "common_names": common_names,
        "valid_from": _safe_get(parsed, "validity_period.not_before"),
        "valid_to": _safe_get(parsed, "validity_period.not_after"),
        "self_signed": _safe_get(parsed, "signature.self_signed"),
    }


def display_host(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for _summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            if not data or not isinstance(data[0], dict):
                continue

            d = data[0]
            services = _ensure_list(d.get("services"))

            service_rows = []
            service_labels = []
            service_threat_names = []
            service_vulns = []
            service_scan_times = []

            for svc in services:
                if not isinstance(svc, dict):
                    continue

                service_rows.append(
                    {
                        "port": svc.get("port"),
                        "protocol": svc.get("protocol"),
                        "transport_protocol": svc.get("transport_protocol"),
                        "scan_time": svc.get("scan_time"),
                    }
                )

                if svc.get("scan_time") is not None:
                    service_scan_times.append(str(svc.get("scan_time")))

                for label in _ensure_list(svc.get("labels")):
                    if isinstance(label, dict) and label.get("value") is not None:
                        value = str(label.get("value"))
                        if value not in service_labels:
                            service_labels.append(value)

                for threat in _ensure_list(svc.get("threats")):
                    if isinstance(threat, dict) and threat.get("name") is not None:
                        name = str(threat.get("name"))
                        if name not in service_threat_names:
                            service_threat_names.append(name)

                for vuln in _ensure_list(svc.get("vulns")):
                    if vuln is None:
                        continue
                    vuln_value = str(vuln)
                    if vuln_value not in service_vulns:
                        service_vulns.append(vuln_value)

            host_labels = []
            for label in _ensure_list(d.get("labels")):
                if isinstance(label, dict) and label.get("value") is not None:
                    host_labels.append(str(label.get("value")))

            dns_names = [str(name) for name in _ensure_list(_safe_get(d, "dns.names", [])) if name is not None]

            forward_dns_names = []
            for fdns in _ensure_list(_safe_get(d, "dns.forward_dns", [])):
                if isinstance(fdns, dict):
                    names = _ensure_list(fdns.get("names"))
                    for name in names:
                        if name is not None:
                            forward_dns_names.append(str(name))

            reverse_dns_names = [
                str(name)
                for name in _ensure_list(_safe_get(d, "dns.reverse_dns.names", []))
                if name is not None
            ]

            location = d.get("location") if isinstance(d.get("location"), dict) else {}
            coordinates = location.get("coordinates") if isinstance(location.get("coordinates"), dict) else {}

            results.append(
                {
                    "ip": d.get("ip"),
                    "service_count": d.get("service_count"),
                    "services": service_rows,
                    "service_scan_times": service_scan_times,
                    "host_labels": host_labels,
                    "service_labels": service_labels,
                    "service_threat_names": service_threat_names,
                    "service_vulns": service_vulns,
                    "dns_names": dns_names,
                    "forward_dns_names": forward_dns_names,
                    "reverse_dns_names": reverse_dns_names,
                    "whois_network_name": _safe_get(d, "whois.network.name"),
                    "whois_network_cidrs": _ensure_list(_safe_get(d, "whois.network.cidrs", [])),
                    "autonomous_system_name": _safe_get(d, "autonomous_system.name"),
                    "autonomous_system_asn": _safe_get(d, "autonomous_system.asn"),
                    "location": {
                        "city": location.get("city"),
                        "province": location.get("province"),
                        "postal_code": location.get("postal_code"),
                        "country": location.get("country"),
                        "country_code": location.get("country_code"),
                        "continent": location.get("continent"),
                        "latitude": coordinates.get("latitude"),
                        "longitude": coordinates.get("longitude"),
                    },
                }
            )

    return "views/lookup_host.html"


def display_cert(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for _summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            if not data or not isinstance(data[0], dict):
                continue
            results.append(_extract_cert_fields(data[0]))

    return "views/lookup_cert.html"


def display_web_property(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for _summary, action_results in all_app_runs:
        for result in action_results:
            data = result.get_data()
            if not data or not isinstance(data[0], dict):
                continue

            d = data[0]

            endpoints = []
            for endpoint in _ensure_list(d.get("endpoints")):
                if isinstance(endpoint, dict):
                    endpoints.append(
                        {
                            "endpoint_type": endpoint.get("endpoint_type"),
                            "path": endpoint.get("path"),
                        }
                    )

            software = []
            for sw in _ensure_list(d.get("software")):
                if isinstance(sw, dict):
                    software.append(
                        {
                            "vendor": sw.get("vendor"),
                            "product": sw.get("product"),
                            "version": sw.get("version"),
                        }
                    )

            labels = [str(v) for v in _ensure_list(d.get("labels")) if v is not None]
            threats = [str(v) for v in _ensure_list(d.get("threats")) if v is not None]
            vulns = [str(v) for v in _ensure_list(d.get("vulns")) if v is not None]

            cert = d.get("cert") if isinstance(d.get("cert"), dict) else {}

            results.append(
                {
                    "hostname": d.get("hostname"),
                    "port": d.get("port"),
                    "scan_time": d.get("scan_time"),
                    "endpoints": endpoints,
                    "labels": labels,
                    "threats": threats,
                    "vulns": vulns,
                    "software": software,
                    "cert": _extract_cert_fields(cert) if cert else {},
                }
            )

    return "views/lookup_web_property.html"
