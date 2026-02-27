# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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


def _to_display_string(value: Any, preferred_keys: tuple[str, ...] = ()) -> str | None:
    """Normalize mixed scalar/dict values into widget-friendly strings."""
    if value is None:
        return None

    if isinstance(value, dict):
        for key in preferred_keys:
            candidate = value.get(key)
            if candidate is None or isinstance(candidate, (dict, list)):
                continue
            return str(candidate)

        for key in ("value", "name", "id", "cve_id", "cidr"):
            if key in preferred_keys:
                continue
            candidate = value.get(key)
            if candidate is None or isinstance(candidate, (dict, list)):
                continue
            return str(candidate)

        return None

    if isinstance(value, (list, tuple, set)):
        return None

    return str(value)


def _normalize_display_list(values: Any, preferred_keys: tuple[str, ...] = ()) -> list[str]:
    """Return displayable string values preserving input order."""
    normalized: list[str] = []
    for item in _ensure_list(values):
        display_value = _to_display_string(item, preferred_keys)
        if display_value is None:
            continue
        normalized.append(display_value)
    return normalized


def _iter_action_results(all_app_runs: Any):
    """Yield action result objects from SOAR all_app_runs safely."""
    if all_app_runs is None:
        return

    try:
        iterator = iter(all_app_runs)
    except TypeError:
        return

    for app_run in iterator:
        action_results = None

        if isinstance(app_run, dict):
            action_results = app_run.get("action_results")
            if action_results is None:
                action_results = app_run.get("results")
        else:
            try:
                _summary, action_results = app_run
            except Exception:
                continue

        if action_results is None:
            continue

        if isinstance(action_results, (list, tuple)):
            yield from action_results
        else:
            yield action_results


def _first_data_dict(result: Any) -> dict[str, Any] | None:
    """Return first action_result.data object if it is a dict."""
    if result is None or not hasattr(result, "get_data"):
        return None
    try:
        data = result.get_data()
    except Exception:
        return None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    return None


def _extract_cert_fields(cert: dict[str, Any]) -> dict[str, Any]:
    """Extract cert fields from canonical Censys cert schema."""
    parsed = cert.get("parsed", {})
    common_names = _normalize_display_list(_safe_get(parsed, "subject.common_name", []), ("name", "value"))

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

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue

        try:
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

                service_labels.extend(_normalize_display_list(svc.get("labels"), ("value", "name", "label")))
                service_threat_names.extend(_normalize_display_list(svc.get("threats"), ("name", "value", "id")))
                service_vulns.extend(_normalize_display_list(svc.get("vulns"), ("id", "name", "cve_id")))

            host_labels = _normalize_display_list(d.get("labels"), ("value", "name", "label"))

            dns_names = _normalize_display_list(_safe_get(d, "dns.names", []), ("name", "value"))

            forward_dns_names = []
            for fdns in _ensure_list(_safe_get(d, "dns.forward_dns", [])):
                if isinstance(fdns, dict):
                    forward_dns_names.extend(_normalize_display_list(fdns.get("names"), ("name", "value")))

            reverse_dns_names = _normalize_display_list(_safe_get(d, "dns.reverse_dns.names", []), ("name", "value"))

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
                    "whois_network_cidrs": _normalize_display_list(_safe_get(d, "whois.network.cidrs", []), ("cidr", "value", "name", "id")),
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
        except Exception:
            continue

    return "views/lookup_host.html"


def display_cert(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue
        try:
            results.append(_extract_cert_fields(d))
        except Exception:
            continue

    return "views/lookup_cert.html"


def display_web_property(provides, all_app_runs, context):
    _ = provides
    context["results"] = results = []

    for result in _iter_action_results(all_app_runs):
        d = _first_data_dict(result)
        if not isinstance(d, dict):
            continue

        try:
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

            labels = _normalize_display_list(d.get("labels"), ("value", "name", "label"))
            threats = _normalize_display_list(d.get("threats"), ("name", "value", "id"))
            vulns = _normalize_display_list(d.get("vulns"), ("id", "name", "cve_id"))

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
        except Exception:
            continue

    return "views/lookup_web_property.html"
