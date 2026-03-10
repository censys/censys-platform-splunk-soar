# File: censysplatform_connector.py
#
# Copyright (c) 2025-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import datetime
import ipaddress
import re
import time
import uuid
from typing import Any
from urllib.parse import quote_plus

import phantom.app as phantom
from censys_platform import SDK, models
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from censysplatform_consts import (
    ACTION_ID_FIND_RELATED_ASSETS_FROM_HOST,
    ACTION_ID_FIND_RELATED_ASSETS_FROM_WEB,
    ACTION_ID_GET_HOST_EVENT_HISTORY,
    ACTION_ID_GET_HOST_SERVICE_HISTORY,
    ACTION_ID_LIVE_RESCAN,
    ACTION_ID_LOOKUP_CERT,
    ACTION_ID_LOOKUP_HOST,
    ACTION_ID_LOOKUP_WEB_PROPERTY,
    ACTION_ID_SEARCH,
    ACTION_ID_TEST_CONNECTIVITY,
    CENSYSPLATFORM_DEFAULT_BASE_URL,
    CENSYSPLATFORM_DEFAULT_UI_URL,
    CENSYSPLATFORM_ERR_CONNECTIVITY_TEST,
    CENSYSPLATFORM_SUCC_CONNECTIVITY_TEST,
)


class CensysplatformConnector(BaseConnector):
    """Connector implementation for Censys Platform."""

    def __init__(self):
        super().__init__()
        self._base_url = CENSYSPLATFORM_DEFAULT_BASE_URL
        self._api_token = None
        self._organization_id = None

    def _create_sdk(self) -> SDK:
        return SDK(
            organization_id=self._organization_id or None,
            personal_access_token=self._api_token,
            server_url=self._base_url,
        )

    def _serialize(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, dict):
            return {k: self._serialize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._serialize(item) for item in value]
        if isinstance(value, datetime.datetime):
            return value.isoformat()
        if isinstance(value, datetime.date):
            return value.isoformat()
        if hasattr(value, "value"):
            return self._serialize(value.value)
        if hasattr(value, "model_dump"):
            return self._serialize(value.model_dump(mode="json"))
        if hasattr(value, "__dict__"):
            output = {}
            for key, item in vars(value).items():
                if not key.startswith("_"):
                    output[key] = self._serialize(item)
            return output
        return str(value)

    def _validate_at_time(self, at_time: str) -> bool:
        if not at_time:
            return True
        try:
            datetime.datetime.fromisoformat(at_time.replace("Z", "+00:00"))
            return True
        except ValueError:
            return False

    def _validate_hostname(self, hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            parts = hostname.split(".")
            return len(parts) > 1 and all(part for part in parts)

    def _validate_uuid4(self, value: str) -> bool:
        try:
            parsed = uuid.UUID(value)
            return parsed.version == 4
        except ValueError:
            return False

    def _parse_iso8601(self, value: str) -> datetime.datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed
        except ValueError:
            return None

    def _parse_iso8601_param(
        self,
        value: str,
        field_name: str,
        *,
        required: bool = False,
    ) -> tuple[datetime.datetime | None, str | None]:
        cleaned = (value or "").strip()
        if not cleaned:
            if required:
                return None, f"Please provide a valid ISO 8601 timestamp in '{field_name}'"
            return None, None
        parsed = self._parse_iso8601(cleaned)
        if parsed is None:
            return None, f"Please provide a valid ISO 8601 timestamp in '{field_name}'"
        return parsed, None

    def _coerce_int_param(self, value: Any, field_name: str) -> tuple[int | None, str | None]:
        try:
            return int(value), None
        except (TypeError, ValueError):
            return None, f"Please provide a valid numeric value in '{field_name}'"

    def _unique_strings(self, values: list[Any]) -> list[str]:
        unique: list[str] = []
        for value in values:
            if value is None:
                continue
            string_value = str(value).strip()
            if not string_value or string_value in unique:
                continue
            unique.append(string_value)
        return unique

    def _extract_dict_list(self, value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        output: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                output.append(item)
        return output

    def _extract_services_on_host_data(self, result_data: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
        ranges = result_data.get("ranges")
        if not isinstance(ranges, list):
            ranges = result_data.get("Ranges")
        normalized_ranges = self._extract_dict_list(ranges)

        next_page_token = result_data.get("next_page_token")
        if not isinstance(next_page_token, str):
            next_page_token = result_data.get("NextPageToken", "")
        if not isinstance(next_page_token, str):
            next_page_token = ""
        return normalized_ranges, next_page_token

    def _task_status_counts(self, tracked_scan_data: dict[str, Any]) -> dict[str, int]:
        counts: dict[str, int] = {}
        tasks = tracked_scan_data.get("tasks")
        if not isinstance(tasks, list):
            return counts
        for task in tasks:
            if not isinstance(task, dict):
                continue
            status = task.get("status")
            if status is None:
                continue
            status_value = str(status)
            counts[status_value] = counts.get(status_value, 0) + 1
        return counts

    def _latest_task_status(self, tracked_scan_data: dict[str, Any]) -> str:
        tasks = tracked_scan_data.get("tasks")
        if not isinstance(tasks, list) or not tasks:
            return "unknown"

        latest_status = "unknown"
        latest_update = ""
        for task in tasks:
            if not isinstance(task, dict):
                continue
            status = task.get("status")
            if status is None:
                continue
            update_time = str(task.get("update_time") or "")
            if update_time and update_time >= latest_update:
                latest_update = update_time
                latest_status = str(status)

        if latest_status != "unknown":
            return latest_status

        for task in reversed(tasks):
            if isinstance(task, dict) and task.get("status") is not None:
                return str(task.get("status"))
        return "unknown"

    def _quote_cenql(self, value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def _or_equals(self, field_name: str, values: list[Any], *, numeric: bool = False) -> str:
        terms: list[str] = []
        for value in values:
            if value is None:
                continue
            if numeric:
                terms.append(f"{field_name}={int(value)}")
            else:
                string_value = str(value).strip()
                if not string_value:
                    continue
                terms.append(f"{field_name}={self._quote_cenql(string_value)}")
        return " OR ".join(terms)

    def _build_related_assets_query_from_host(self, host_data: dict[str, Any], seed_ip: str) -> str:
        dns = host_data.get("dns") if isinstance(host_data.get("dns"), dict) else {}
        dns_names = dns.get("names") if isinstance(dns, dict) else []

        hostname_terms = [host_data.get("ip") or seed_ip]
        if isinstance(dns_names, list):
            hostname_terms.extend(dns_names)
        hostname_terms = self._unique_strings(hostname_terms)

        service_ports: list[int] = []
        services = self._extract_dict_list(host_data.get("services"))
        for service in services:
            port = service.get("port")
            try:
                port_value = int(port)
            except (TypeError, ValueError):
                continue
            if 1 <= port_value <= 65535 and port_value not in service_ports:
                service_ports.append(port_value)

        hostname_query = self._or_equals("web.hostname", hostname_terms)
        web_port_query = self._or_equals("web.port", service_ports, numeric=True)
        endpoint_port_query = self._or_equals("port", service_ports, numeric=True)
        ip_value = str(host_data.get("ip") or seed_ip)

        combined_parts: list[str] = []
        if hostname_query and web_port_query:
            combined_parts.append(f"(({hostname_query}) AND ({web_port_query}))")
        elif hostname_query:
            combined_parts.append(f"({hostname_query})")

        if ip_value and endpoint_port_query:
            combined_parts.append(f"web.endpoints:(ip={self._quote_cenql(ip_value)} AND ({endpoint_port_query}))")

        return " OR ".join(combined_parts)

    def _build_related_assets_query_from_web(
        self,
        web_data: dict[str, Any],
        hostname: str,
        port: int,
    ) -> str:
        hostnames = self._unique_strings([hostname, web_data.get("hostname")])
        endpoint_ips: list[str] = []
        endpoint_hostnames: list[str] = []

        for endpoint in self._extract_dict_list(web_data.get("endpoints")):
            endpoint_ip = endpoint.get("ip")
            if endpoint_ip is not None:
                endpoint_ips.append(str(endpoint_ip))
            endpoint_hostname = endpoint.get("hostname")
            if endpoint_hostname is not None:
                endpoint_hostnames.append(str(endpoint_hostname))

        cert = web_data.get("cert") if isinstance(web_data.get("cert"), dict) else {}
        parsed = cert.get("parsed") if isinstance(cert.get("parsed"), dict) else {}
        subject = parsed.get("subject") if isinstance(parsed.get("subject"), dict) else {}
        common_names = subject.get("common_name") if isinstance(subject.get("common_name"), list) else []
        hostnames.extend(endpoint_hostnames)
        hostnames.extend(common_names if isinstance(common_names, list) else [])
        hostnames = self._unique_strings(hostnames)
        endpoint_ips = self._unique_strings(endpoint_ips)

        identity_terms: list[str] = []
        for ip_value in endpoint_ips:
            identity_terms.append(f"host.ip={self._quote_cenql(ip_value)}")
        for host_value in hostnames:
            quoted = self._quote_cenql(host_value)
            identity_terms.append(f"host.dns.names={quoted}")
            identity_terms.append(f"host.dns.reverse_dns.names={quoted}")

        port_query = f"host.services.port={port}"
        if not identity_terms:
            return port_query
        return f"{port_query} AND ({' OR '.join(identity_terms)})"

    def _build_rescan_body(
        self,
        param: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any] | None, str | None, str | None]:
        target_type = (param.get("target_type", "") or "").strip().lower()
        ip = (param.get("ip", "") or "").strip()
        hostname = (param.get("hostname", "") or "").strip()

        if not target_type:
            if ip and not hostname:
                target_type = "service_id"
            elif hostname and not ip:
                target_type = "web_origin"
            elif ip and hostname:
                return (
                    None,
                    None,
                    None,
                    "Provide only one target: either 'ip' (service target) or 'hostname' (web target), or specify 'target_type'",
                )
            else:
                target_type = "service_id"

        port, port_error = self._coerce_int_param(param.get("port"), "port")
        if port_error is not None:
            return None, None, None, port_error
        if port is None or not 1 <= port <= 65535:
            return None, None, None, "'port' must be between 1 and 65535"

        if target_type in {"service_id", "service", "host_service"}:
            protocol = (param.get("protocol", "") or "").strip()
            transport_protocol = (param.get("transport_protocol", "tcp") or "").strip().lower()

            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return None, None, None, "Please provide a valid IPv4 or IPv6 value in 'ip'"

            if not protocol:
                return None, None, None, "Please provide a non-empty value in 'protocol'"

            if transport_protocol not in {"unknown", "tcp", "udp", "icmp", "quic"}:
                return (
                    None,
                    None,
                    None,
                    "'transport_protocol' must be one of: unknown, tcp, udp, icmp, quic",
                )

            body = {
                "target": {
                    "service_id": {
                        "ip": ip,
                        "port": port,
                        "protocol": protocol,
                        "transport_protocol": transport_protocol,
                    }
                }
            }
            descriptor = f"{ip}:{port}/{protocol}/{transport_protocol}"
            return "service_id", body, descriptor, None

        if target_type in {"web_origin", "web", "webproperty"}:
            if not self._validate_hostname(hostname):
                return None, None, None, "Please provide a valid domain or IP value in 'hostname'"

            body = {"target": {"web_origin": {"hostname": hostname, "port": port}}}
            descriptor = f"{hostname}:{port}"
            return "web_origin", body, descriptor, None

        return (
            None,
            None,
            None,
            "'target_type' must be either 'service_id' or 'web_origin'",
        )

    def _start_tracked_scan(self, scans_rescan_input_body: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
        try:
            with self._create_sdk() as sdk:
                response = sdk.global_data.create_tracked_scan(
                    scans_rescan_input_body=scans_rescan_input_body,
                    organization_id=self._organization_id,
                )
                tracked_scan = response.result.result
        except models.SDKBaseError as err:
            return None, f"Failed to start live rescan (status code: {err.status_code})"
        except Exception as err:
            return None, f"Failed to start live rescan: {err!s}"

        tracked_scan_data = self._serialize(tracked_scan)
        if isinstance(tracked_scan_data, dict):
            return tracked_scan_data, None
        return {"tracked_scan": tracked_scan_data}, None

    def _fetch_tracked_scan(self, scan_id: str) -> tuple[dict[str, Any] | None, str | None]:
        try:
            with self._create_sdk() as sdk:
                response = sdk.global_data.get_tracked_scan(
                    scan_id=scan_id,
                    organization_id=self._organization_id,
                )
                tracked_scan = response.result.result
        except models.SDKBaseError as err:
            return None, f"Failed to retrieve live scan status (status code: {err.status_code})"
        except Exception as err:
            return None, f"Failed to retrieve live scan status: {err!s}"

        tracked_scan_data = self._serialize(tracked_scan)
        if isinstance(tracked_scan_data, dict):
            return tracked_scan_data, None
        return {"tracked_scan": tracked_scan_data}, None

    def _summarize_diff_value(self, value: Any, max_chars: int = 180) -> str:
        if isinstance(value, (dict, list)):
            serialized = self._serialize(value)
            text = str(serialized)
        else:
            text = str(value)
        if len(text) <= max_chars:
            return text
        return f"{text[: max_chars - 3]}..."

    def _compute_snapshot_diff(
        self,
        before: Any,
        after: Any,
        *,
        path: str = "",
        max_entries: int = 200,
    ) -> tuple[list[dict[str, str]], bool]:
        entries: list[dict[str, str]] = []
        truncated = False

        def _append(change_type: str, change_path: str, before_value: Any, after_value: Any) -> None:
            nonlocal truncated
            if len(entries) >= max_entries:
                truncated = True
                return
            entries.append(
                {
                    "change_type": change_type,
                    "path": change_path or "$",
                    "before": self._summarize_diff_value(before_value),
                    "after": self._summarize_diff_value(after_value),
                }
            )

        def _walk(lhs: Any, rhs: Any, current_path: str) -> None:
            nonlocal truncated
            if truncated:
                return

            if isinstance(lhs, dict) and isinstance(rhs, dict):
                all_keys = sorted(set(lhs.keys()) | set(rhs.keys()))
                for key in all_keys:
                    child_path = f"{current_path}.{key}" if current_path else key
                    if key not in lhs:
                        _append("added", child_path, None, rhs.get(key))
                        continue
                    if key not in rhs:
                        _append("removed", child_path, lhs.get(key), None)
                        continue
                    _walk(lhs.get(key), rhs.get(key), child_path)
                return

            if isinstance(lhs, list) and isinstance(rhs, list):
                max_len = max(len(lhs), len(rhs))
                for idx in range(max_len):
                    child_path = f"{current_path}[{idx}]" if current_path else f"[{idx}]"
                    if idx >= len(lhs):
                        _append("added", child_path, None, rhs[idx])
                        continue
                    if idx >= len(rhs):
                        _append("removed", child_path, lhs[idx], None)
                        continue
                    _walk(lhs[idx], rhs[idx], child_path)
                return

            if lhs != rhs:
                _append("modified", current_path or "$", lhs, rhs)

        _walk(before, after, path)
        return entries, truncated

    def _handle_test_connectivity(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to Censys Platform...")

        try:
            with self._create_sdk() as sdk:
                sdk.global_data.get_host(
                    host_id="8.8.8.8",
                    organization_id=self._organization_id,
                )
        except models.SDKBaseError as err:
            self.save_progress(CENSYSPLATFORM_ERR_CONNECTIVITY_TEST)
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Connectivity test failed (status code: {err.status_code})",
            )
        except Exception as err:
            self.save_progress(CENSYSPLATFORM_ERR_CONNECTIVITY_TEST)
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Connectivity test failed: {err!s}",
            )

        self.save_progress(CENSYSPLATFORM_SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_lookup_host(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        ip = param.get("ip", "")
        at_time = (param.get("at_time", "") or "").strip()

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid IPv4 or IPv6 value in 'ip'")

        if at_time and not self._validate_at_time(at_time):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid ISO 8601 timestamp in 'at_time' or leave it empty",
            )

        try:
            with self._create_sdk() as sdk:
                response = sdk.global_data.get_host(
                    host_id=ip,
                    at_time=at_time or None,
                    organization_id=self._organization_id,
                )
                host = response.result.result.resource
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to retrieve host (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to retrieve host: {err!s}")

        services_raw = getattr(host, "services", []) or []
        is_truncated_host = any(getattr(service, "representative_info", None) is not None for service in services_raw)
        host_data = self._serialize(host)
        services = host_data.get("services", []) if isinstance(host_data, dict) else []
        ports = sorted({service.get("port") for service in services if isinstance(service, dict) and service.get("port") is not None})
        scan_times = [service.get("scan_time") for service in services if isinstance(service, dict) and service.get("scan_time")]
        latest_scan = max(scan_times) if scan_times else "N/A"
        service_count = host_data.get("service_count") if isinstance(host_data, dict) else None
        if service_count is None:
            service_count = len(services)

        if isinstance(host_data, dict):
            host_data["is_truncated_host"] = is_truncated_host

        action_result.add_data(host_data if isinstance(host_data, dict) else {"host": host_data})
        action_result.update_summary(
            {
                "ip": host_data.get("ip", ip) if isinstance(host_data, dict) else ip,
                "service_count": service_count,
                "ports": ports,
                "scan_time": latest_scan,
            }
        )
        message = f"Host '{ip}' retrieved successfully"
        if is_truncated_host:
            message = f"Host '{ip}' has many visible services and results are truncated"
        return action_result.set_status(
            phantom.APP_SUCCESS,
            message,
        )

    def _handle_lookup_cert(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        fingerprint = (param.get("fingerprint_sha256", "") or "").strip()

        if not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid 64-character SHA256 hex value in 'fingerprint_sha256'",
            )

        try:
            with self._create_sdk() as sdk:
                response = sdk.global_data.get_certificate(
                    certificate_id=fingerprint,
                    organization_id=self._organization_id,
                )
                cert = response.result.result.resource
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to retrieve certificate (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to retrieve certificate: {err!s}")

        cert_data = self._serialize(cert)
        display_name = fingerprint
        if isinstance(cert_data, dict):
            display_name = cert_data.get("name") or cert_data.get("subject_dn") or cert_data.get("fingerprint_sha256") or fingerprint

        action_result.add_data(cert_data if isinstance(cert_data, dict) else {"cert": cert_data})
        action_result.update_summary(
            {
                "display_name": display_name,
                "fingerprint_sha256": fingerprint,
            }
        )
        parsed = cert_data.get("parsed", {}) if isinstance(cert_data, dict) else {}
        validity_period = parsed.get("validity_period", {})
        not_before = validity_period.get("not_before")
        not_after = validity_period.get("not_after")
        validity_text = "validity period unavailable"
        if not_before and not_after:
            validity_text = f"validity [{not_before} - {not_after}]"
        signature = parsed.get("signature", {})
        self_signed = signature.get("self_signed")
        if self_signed is True:
            signing_text = "self-signed"
        elif self_signed is False:
            signing_text = "not self-signed"
        else:
            signing_text = "self-sign status unavailable"
        return action_result.set_status(
            phantom.APP_SUCCESS,
            (f"Certificate '{display_name}' retrieved successfully ({signing_text}, {validity_text})"),
        )

    def _handle_lookup_web_property(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = (param.get("hostname", "") or "").strip()
        port = param.get("port")
        at_time = (param.get("at_time", "") or "").strip()

        if not self._validate_hostname(hostname):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid domain or IP value in 'hostname'",
            )

        try:
            port = int(port)
        except (TypeError, ValueError):
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid numeric value in 'port'")

        if port < 1 or port > 65535:
            return action_result.set_status(phantom.APP_ERROR, "'port' must be between 1 and 65535")

        if at_time and not self._validate_at_time(at_time):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid ISO 8601 timestamp in 'at_time' or leave it empty",
            )

        web_property_id = f"{hostname}:{port}"
        try:
            with self._create_sdk() as sdk:
                response = sdk.global_data.get_web_property(
                    webproperty_id=web_property_id,
                    at_time=at_time or None,
                    organization_id=self._organization_id,
                )
                web_property = response.result.result.resource
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to retrieve web property (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to retrieve web property: {err!s}")

        web_data = self._serialize(web_property)
        endpoints = []
        if isinstance(web_data, dict):
            endpoints = web_data.get("endpoints", [])

        action_result.add_data(web_data if isinstance(web_data, dict) else {"web_property": web_data})
        action_result.update_summary(
            {
                "hostname": hostname,
                "port": port,
                "endpoint_count": len(endpoints) if isinstance(endpoints, list) else 0,
                "endpoints": [endpoint.get("path") for endpoint in endpoints if isinstance(endpoint, dict) and endpoint.get("path")]
                if isinstance(endpoints, list)
                else [],
                "scan_time": web_data.get("scan_time", "N/A") if isinstance(web_data, dict) else "N/A",
            }
        )
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Web property '{web_property_id}' retrieved successfully",
        )

    def _handle_search(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        query = (param.get("query", "") or "").strip()
        page_size = param.get("page_size", 100)

        if not query:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a non-empty value in 'query'")

        try:
            page_size = int(page_size)
        except (TypeError, ValueError):
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid numeric value in 'page_size'")

        if page_size < 1:
            return action_result.set_status(phantom.APP_ERROR, "'page_size' must be greater than 0")

        try:
            with self._create_sdk() as sdk:
                response = sdk.global_data.search(
                    search_query_input_body=models.SearchQueryInputBody(
                        query=query,
                        page_size=page_size,
                    ),
                    organization_id=self._organization_id,
                )
                result = response.result.result
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to execute search (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to execute search: {err!s}")

        result_data = self._serialize(result)
        if isinstance(result_data, dict):
            platform_search_url = f"{CENSYSPLATFORM_DEFAULT_UI_URL}/search?q={quote_plus(query)}"
            if self._organization_id:
                platform_search_url = f"{platform_search_url}&org={quote_plus(self._organization_id)}"
            result_data["platform_search_url"] = platform_search_url
            action_result.add_data(result_data)
            query_duration_millis = result_data.get("query_duration_millis")
            total_hits = result_data.get("total_hits")
            hits = result_data.get("hits", [])
            action_result.update_summary(
                {
                    "query_duration_millis": query_duration_millis,
                    "total_hits": total_hits,
                    "hit_count": len(hits) if isinstance(hits, list) else 0,
                }
            )
        else:
            action_result.add_data({"result": result_data})
            query_duration_millis = None
            total_hits = None
        duration_seconds = float(query_duration_millis) / 1000 if query_duration_millis is not None else 0
        return action_result.set_status(
            phantom.APP_SUCCESS,
            (f"Search completed successfully (took {duration_seconds:.2f}s, found {int(total_hits or 0):,} result(s))"),
        )

    def _handle_get_host_event_history(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        host_id = (param.get("host_id", "") or "").strip()
        start_time_raw = (param.get("start_time", "") or "").strip()
        end_time_raw = (param.get("end_time", "") or "").strip()

        try:
            ipaddress.ip_address(host_id)
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid IPv4 or IPv6 value in 'host_id'")

        start_time, start_error = self._parse_iso8601_param(start_time_raw, "start_time", required=True)
        if start_error is not None:
            return action_result.set_status(phantom.APP_ERROR, start_error)

        end_time, end_error = self._parse_iso8601_param(end_time_raw, "end_time", required=True)
        if end_error is not None:
            return action_result.set_status(phantom.APP_ERROR, end_error)

        if start_time is None or end_time is None:
            return action_result.set_status(phantom.APP_ERROR, "Both 'start_time' and 'end_time' are required")
        if start_time < end_time:
            return action_result.set_status(phantom.APP_ERROR, "'start_time' must be greater than or equal to 'end_time'")

        try:
            with self._create_sdk() as sdk:
                response = sdk.global_data.get_host_timeline(
                    host_id=host_id,
                    start_time=start_time,
                    end_time=end_time,
                    organization_id=self._organization_id,
                )
                timeline = response.result.result
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to retrieve host event history (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to retrieve host event history: {err!s}")

        timeline_data = self._serialize(timeline)
        if not isinstance(timeline_data, dict):
            timeline_data = {"result": timeline_data}

        events = self._extract_dict_list(timeline_data.get("events"))
        event_timestamps: list[str] = []
        has_service_scanned = False
        has_endpoint_scanned = False
        has_dns_updates = False
        for event in events:
            resource = event.get("resource")
            event_payload = resource if isinstance(resource, dict) else event
            event_time = event_payload.get("event_time")
            if event_time is not None:
                event_timestamps.append(str(event_time))
            has_service_scanned = has_service_scanned or bool(event_payload.get("service_scanned"))
            has_endpoint_scanned = has_endpoint_scanned or bool(event_payload.get("endpoint_scanned"))
            has_dns_updates = has_dns_updates or bool(event_payload.get("forward_dns_resolved") or event_payload.get("reverse_dns_resolved"))

        first_event_time = min(event_timestamps) if event_timestamps else "N/A"
        last_event_time = max(event_timestamps) if event_timestamps else "N/A"
        timeline_data["request"] = {
            "host_id": host_id,
            "start_time": start_time_raw,
            "end_time": end_time_raw,
        }
        action_result.add_data(timeline_data)
        action_result.update_summary(
            {
                "host_id": host_id,
                "event_count": len(events),
                "first_event_time": first_event_time,
                "last_event_time": last_event_time,
                "has_service_scanned": int(has_service_scanned),
                "has_endpoint_scanned": int(has_endpoint_scanned),
                "has_dns_updates": int(has_dns_updates),
            }
        )
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Retrieved {len(events)} host event history entries for '{host_id}'",
        )

    def _handle_get_host_service_history(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        host_id = (param.get("host_id", "") or "").strip()
        start_time_raw = (param.get("start_time", "") or "").strip()
        end_time_raw = (param.get("end_time", "") or "").strip()
        page_token = (param.get("page_token", "") or "").strip()
        protocol = (param.get("protocol", "") or "").strip()
        transport_protocol = (param.get("transport_protocol", "") or "").strip().lower()
        order_by_raw = (param.get("order_by", "") or "").strip()

        try:
            ipaddress.ip_address(host_id)
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid IPv4 or IPv6 value in 'host_id'")

        page_size, page_size_error = self._coerce_int_param(param.get("page_size", 100), "page_size")
        if page_size_error is not None:
            return action_result.set_status(phantom.APP_ERROR, page_size_error)
        if page_size is None or not 1 <= page_size <= 100:
            return action_result.set_status(phantom.APP_ERROR, "'page_size' must be between 1 and 100")

        start_time, start_error = self._parse_iso8601_param(start_time_raw, "start_time")
        if start_error is not None:
            return action_result.set_status(phantom.APP_ERROR, start_error)

        end_time, end_error = self._parse_iso8601_param(end_time_raw, "end_time")
        if end_error is not None:
            return action_result.set_status(phantom.APP_ERROR, end_error)

        if start_time is not None and end_time is not None and start_time > end_time:
            return action_result.set_status(phantom.APP_ERROR, "'start_time' must be less than or equal to 'end_time'")

        port = None
        if param.get("port") not in (None, ""):
            port, port_error = self._coerce_int_param(param.get("port"), "port")
            if port_error is not None:
                return action_result.set_status(phantom.APP_ERROR, port_error)
            if port is None or not 1 <= port <= 65535:
                return action_result.set_status(phantom.APP_ERROR, "'port' must be between 1 and 65535")

        if transport_protocol and transport_protocol not in {"tcp", "udp", "quic"}:
            return action_result.set_status(phantom.APP_ERROR, "'transport_protocol' must be one of: tcp, udp, quic")

        order_by = []
        if order_by_raw:
            allowed_order = {
                "port ASC",
                "port DESC",
                "protocol ASC",
                "protocol DESC",
                "transport_protocol ASC",
                "transport_protocol DESC",
            }
            order_by = [part.strip() for part in order_by_raw.split(",") if part.strip()]
            invalid_order = [part for part in order_by if part not in allowed_order]
            if invalid_order:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Invalid 'order_by' value. Allowed values: port ASC, port DESC, protocol ASC, protocol DESC, transport_protocol ASC, transport_protocol DESC",
                )

        request: dict[str, Any] = {
            "host_id": host_id,
            "organization_id": self._organization_id,
            "page_size": page_size,
        }
        if start_time is not None:
            request["start_time"] = start_time
        if end_time is not None:
            request["end_time"] = end_time
        if page_token:
            request["page_token"] = page_token
        if port is not None:
            request["port"] = port
        if protocol:
            request["protocol"] = protocol
        if transport_protocol:
            request["transport_protocol"] = transport_protocol
        if order_by:
            request["order_by"] = order_by

        try:
            with self._create_sdk() as sdk:
                response = sdk.global_data.list_services_on_host(request=request)
                result = response.result.result
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to retrieve host service history (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to retrieve host service history: {err!s}")

        result_data = self._serialize(result)
        if not isinstance(result_data, dict):
            result_data = {"result": result_data}

        ranges, next_page_token = self._extract_services_on_host_data(result_data)
        range_ports = sorted({int(r.get("port")) for r in ranges if r.get("port") not in (None, "")})
        range_protocols = sorted({str(r.get("protocol")) for r in ranges if r.get("protocol") not in (None, "")})
        range_transport_protocols = sorted({str(r.get("transport_protocol")) for r in ranges if r.get("transport_protocol") not in (None, "")})
        start_times = [str(r.get("start_time")) for r in ranges if r.get("start_time")]
        end_times = [str(r.get("end_time")) for r in ranges if r.get("end_time")]

        payload = {
            "host_id": host_id,
            "ranges": ranges,
            "next_page_token": next_page_token,
            "request": {
                "start_time": start_time_raw or None,
                "end_time": end_time_raw or None,
                "page_size": page_size,
                "page_token": page_token or None,
                "port": port,
                "protocol": protocol or None,
                "transport_protocol": transport_protocol or None,
                "order_by": order_by,
            },
        }
        action_result.add_data(payload)
        action_result.update_summary(
            {
                "host_id": host_id,
                "range_count": len(ranges),
                "next_page_token_present": int(bool(next_page_token)),
                "port_count": len(range_ports),
                "protocol_count": len(range_protocols),
                "transport_protocol_count": len(range_transport_protocols),
                "min_start_time": min(start_times) if start_times else "N/A",
                "max_end_time": max(end_times) if end_times else "N/A",
            }
        )
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Retrieved {len(ranges)} host service history range(s) for '{host_id}'",
        )

    def _handle_find_related_assets_from_host(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        host_id = (param.get("host_id", "") or "").strip()
        at_time_raw = (param.get("at_time", "") or "").strip()
        page_token = (param.get("page_token", "") or "").strip()

        try:
            ipaddress.ip_address(host_id)
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid IPv4 or IPv6 value in 'host_id'")

        page_size, page_size_error = self._coerce_int_param(param.get("page_size", 100), "page_size")
        if page_size_error is not None:
            return action_result.set_status(phantom.APP_ERROR, page_size_error)
        if page_size is None or page_size < 1:
            return action_result.set_status(phantom.APP_ERROR, "'page_size' must be greater than 0")

        at_time, at_time_error = self._parse_iso8601_param(at_time_raw, "at_time")
        if at_time_error is not None:
            return action_result.set_status(phantom.APP_ERROR, at_time_error)

        try:
            with self._create_sdk() as sdk:
                host_response = sdk.global_data.get_host(
                    host_id=host_id,
                    at_time=at_time,
                    organization_id=self._organization_id,
                )
                host = host_response.result.result.resource
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to retrieve host seed for related assets (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to retrieve host seed for related assets: {err!s}")

        host_data = self._serialize(host)
        if not isinstance(host_data, dict):
            return action_result.set_status(phantom.APP_ERROR, "Unexpected host seed response shape for related-assets query generation")

        generated_query = self._build_related_assets_query_from_host(host_data, host_id)
        if not generated_query:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to generate a related-assets query from the selected host",
            )

        try:
            with self._create_sdk() as sdk:
                search_response = sdk.global_data.search(
                    search_query_input_body=models.SearchQueryInputBody(
                        query=generated_query,
                        page_size=page_size,
                        page_token=page_token or None,
                    ),
                    organization_id=self._organization_id,
                )
                search_result = search_response.result.result
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to search related assets from host seed (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to search related assets from host seed: {err!s}")

        search_result_data = self._serialize(search_result)
        if not isinstance(search_result_data, dict):
            search_result_data = {"result": search_result_data}

        hits = search_result_data.get("hits")
        if not isinstance(hits, list):
            hits = []
        next_page_token = search_result_data.get("next_page_token", "")
        if not isinstance(next_page_token, str):
            next_page_token = ""

        action_result.add_data(
            {
                "seed_host": host_data,
                "generated_query": generated_query,
                "search_result": search_result_data,
            }
        )
        action_result.update_summary(
            {
                "seed_host": host_id,
                "generated_query": generated_query,
                "total_hits": int(search_result_data.get("total_hits") or 0),
                "returned_hits": len(hits),
                "next_page_token_present": int(bool(next_page_token)),
            }
        )
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Related-assets search from host '{host_id}' returned {len(hits)} hit(s)",
        )

    def _handle_find_related_assets_from_web(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = (param.get("hostname", "") or "").strip()
        at_time_raw = (param.get("at_time", "") or "").strip()
        page_token = (param.get("page_token", "") or "").strip()

        if not self._validate_hostname(hostname):
            return action_result.set_status(
                phantom.APP_ERROR,
                "Please provide a valid domain or IP value in 'hostname'",
            )

        port, port_error = self._coerce_int_param(param.get("port"), "port")
        if port_error is not None:
            return action_result.set_status(phantom.APP_ERROR, port_error)
        if port is None or not 1 <= port <= 65535:
            return action_result.set_status(phantom.APP_ERROR, "'port' must be between 1 and 65535")

        page_size, page_size_error = self._coerce_int_param(param.get("page_size", 100), "page_size")
        if page_size_error is not None:
            return action_result.set_status(phantom.APP_ERROR, page_size_error)
        if page_size is None or page_size < 1:
            return action_result.set_status(phantom.APP_ERROR, "'page_size' must be greater than 0")

        at_time, at_time_error = self._parse_iso8601_param(at_time_raw, "at_time")
        if at_time_error is not None:
            return action_result.set_status(phantom.APP_ERROR, at_time_error)

        web_property_id = f"{hostname}:{port}"
        try:
            with self._create_sdk() as sdk:
                web_response = sdk.global_data.get_web_property(
                    webproperty_id=web_property_id,
                    at_time=at_time,
                    organization_id=self._organization_id,
                )
                web_property = web_response.result.result.resource
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to retrieve web property seed for related assets (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to retrieve web property seed for related assets: {err!s}")

        web_data = self._serialize(web_property)
        if not isinstance(web_data, dict):
            return action_result.set_status(phantom.APP_ERROR, "Unexpected web property seed response shape for related-assets query generation")

        generated_query = self._build_related_assets_query_from_web(web_data, hostname, port)
        if not generated_query:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unable to generate a related-assets query from the selected web property",
            )

        try:
            with self._create_sdk() as sdk:
                search_response = sdk.global_data.search(
                    search_query_input_body=models.SearchQueryInputBody(
                        query=generated_query,
                        page_size=page_size,
                        page_token=page_token or None,
                    ),
                    organization_id=self._organization_id,
                )
                search_result = search_response.result.result
        except models.SDKBaseError as err:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to search related assets from web property seed (status code: {err.status_code})",
            )
        except Exception as err:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to search related assets from web property seed: {err!s}")

        search_result_data = self._serialize(search_result)
        if not isinstance(search_result_data, dict):
            search_result_data = {"result": search_result_data}

        hits = search_result_data.get("hits")
        if not isinstance(hits, list):
            hits = []
        next_page_token = search_result_data.get("next_page_token", "")
        if not isinstance(next_page_token, str):
            next_page_token = ""

        action_result.add_data(
            {
                "seed_web_property": web_data,
                "generated_query": generated_query,
                "search_result": search_result_data,
            }
        )
        action_result.update_summary(
            {
                "seed_web_property": web_property_id,
                "generated_query": generated_query,
                "total_hits": int(search_result_data.get("total_hits") or 0),
                "returned_hits": len(hits),
                "next_page_token_present": int(bool(next_page_token)),
            }
        )
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Related-assets search from web property '{web_property_id}' returned {len(hits)} hit(s)",
        )

    def _handle_live_rescan(self, param: dict[str, Any]) -> int:
        action_result = self.add_action_result(ActionResult(dict(param)))
        target_type, scans_rescan_input_body, target_descriptor, build_error = self._build_rescan_body(param)
        if build_error is not None:
            return action_result.set_status(phantom.APP_ERROR, build_error)
        if scans_rescan_input_body is None or target_type is None:
            return action_result.set_status(phantom.APP_ERROR, "Unable to build live-rescan request body")

        wait_timeout_seconds, timeout_error = self._coerce_int_param(param.get("wait_timeout_seconds", 900), "wait_timeout_seconds")
        if timeout_error is not None:
            return action_result.set_status(phantom.APP_ERROR, timeout_error)
        if wait_timeout_seconds is None or wait_timeout_seconds < 1:
            return action_result.set_status(phantom.APP_ERROR, "'wait_timeout_seconds' must be greater than 0")

        max_diff_entries, max_diff_entries_error = self._coerce_int_param(param.get("max_diff_entries", 200), "max_diff_entries")
        if max_diff_entries_error is not None:
            return action_result.set_status(phantom.APP_ERROR, max_diff_entries_error)
        if max_diff_entries is None or max_diff_entries < 1:
            return action_result.set_status(phantom.APP_ERROR, "'max_diff_entries' must be greater than 0")

        request_target = scans_rescan_input_body.get("target", {})
        request_service_id = request_target.get("service_id") if isinstance(request_target.get("service_id"), dict) else {}
        request_web_origin = request_target.get("web_origin") if isinstance(request_target.get("web_origin"), dict) else {}

        pre_lookup: dict[str, Any] = {}
        try:
            with self._create_sdk() as sdk:
                if isinstance(request_service_id, dict) and request_service_id.get("ip"):
                    pre_lookup["lookup_type"] = "host"
                    pre_host_response = sdk.global_data.get_host(
                        host_id=str(request_service_id.get("ip")),
                        organization_id=self._organization_id,
                    )
                    pre_lookup["result"] = self._serialize(pre_host_response.result.result.resource)
                elif isinstance(request_web_origin, dict) and request_web_origin.get("hostname") and request_web_origin.get("port") is not None:
                    pre_lookup["lookup_type"] = "web_property"
                    pre_webproperty_id = f"{request_web_origin.get('hostname')}:{int(request_web_origin.get('port'))}"
                    pre_web_response = sdk.global_data.get_web_property(
                        webproperty_id=pre_webproperty_id,
                        organization_id=self._organization_id,
                    )
                    pre_lookup["result"] = self._serialize(pre_web_response.result.result.resource)
        except Exception as err:
            pre_lookup["lookup_error"] = str(err)

        self.save_progress(f"Starting live rescan for '{target_descriptor}' and waiting for completion...")
        initial_scan_data, start_error = self._start_tracked_scan(scans_rescan_input_body)
        if start_error is not None:
            return action_result.set_status(phantom.APP_ERROR, start_error)
        if initial_scan_data is None:
            return action_result.set_status(phantom.APP_ERROR, "Live rescan did not return a tracked scan")

        tracked_scan_id = str(initial_scan_data.get("tracked_scan_id") or "")
        if not tracked_scan_id:
            return action_result.set_status(phantom.APP_ERROR, "Live rescan response did not include 'tracked_scan_id'")

        poll_count = 0
        poll_interval = 5
        max_poll_interval = 20
        poll_start = time.monotonic()
        latest_scan_data = initial_scan_data
        completed = bool(latest_scan_data.get("completed"))

        while not completed and (time.monotonic() - poll_start) < wait_timeout_seconds:
            time.sleep(poll_interval)
            poll_count += 1
            poll_interval = min(max_poll_interval, poll_interval + 2)
            latest_scan_data, fetch_error = self._fetch_tracked_scan(tracked_scan_id)
            if fetch_error is not None:
                return action_result.set_status(phantom.APP_ERROR, fetch_error)
            if latest_scan_data is None:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    f"No scan data was returned while polling '{tracked_scan_id}'",
                )
            completed = bool(latest_scan_data.get("completed"))
            self.save_progress(f"Polling '{tracked_scan_id}' (attempt {poll_count}, completed={completed})")

        duration_seconds = round(time.monotonic() - poll_start, 2)
        if not completed:
            action_result.add_data(
                {
                    "target_type": target_type,
                    "initial_tracked_scan": initial_scan_data,
                    "final_tracked_scan": latest_scan_data,
                    "pre_lookup": pre_lookup,
                    "poll_count": poll_count,
                    "duration_seconds": duration_seconds,
                }
            )
            action_result.update_summary(
                {
                    "tracked_scan_id": tracked_scan_id,
                    "target_type": target_type,
                    "completed": 0,
                    "poll_count": poll_count,
                    "duration_seconds": duration_seconds,
                    "latest_task_status": self._latest_task_status(latest_scan_data),
                    "change_count": 0,
                    "diff_truncated": 0,
                }
            )
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Timed out waiting for scan '{tracked_scan_id}' after {wait_timeout_seconds}s",
            )

        status_counts = self._task_status_counts(latest_scan_data)
        latest_task_status = self._latest_task_status(latest_scan_data)
        terminal_failure = status_counts.get("rejected", 0) > 0 or status_counts.get("timed_out", 0) > 0

        post_lookup: dict[str, Any] = {}
        target = latest_scan_data.get("target") if isinstance(latest_scan_data.get("target"), dict) else {}
        service_id = target.get("service_id") if isinstance(target.get("service_id"), dict) else request_service_id
        web_origin = target.get("web_origin") if isinstance(target.get("web_origin"), dict) else request_web_origin

        try:
            with self._create_sdk() as sdk:
                if isinstance(service_id, dict) and service_id.get("ip"):
                    post_lookup["lookup_type"] = "host"
                    host_response = sdk.global_data.get_host(
                        host_id=str(service_id.get("ip")),
                        organization_id=self._organization_id,
                    )
                    post_lookup["result"] = self._serialize(host_response.result.result.resource)
                elif isinstance(web_origin, dict) and web_origin.get("hostname") and web_origin.get("port") is not None:
                    post_lookup["lookup_type"] = "web_property"
                    webproperty_id = f"{web_origin.get('hostname')}:{int(web_origin.get('port'))}"
                    web_response = sdk.global_data.get_web_property(
                        webproperty_id=webproperty_id,
                        organization_id=self._organization_id,
                    )
                    post_lookup["result"] = self._serialize(web_response.result.result.resource)
        except Exception as err:
            post_lookup["lookup_error"] = str(err)

        diff_entries: list[dict[str, str]] = []
        diff_truncated = False
        pre_snapshot = pre_lookup.get("result")
        post_snapshot = post_lookup.get("result")
        if isinstance(pre_snapshot, dict) and isinstance(post_snapshot, dict):
            diff_entries, diff_truncated = self._compute_snapshot_diff(
                pre_snapshot,
                post_snapshot,
                max_entries=max_diff_entries,
            )

        action_result.add_data(
            {
                "target_type": target_type,
                "initial_tracked_scan": initial_scan_data,
                "final_tracked_scan": latest_scan_data,
                "pre_lookup": pre_lookup,
                "post_lookup": post_lookup,
                "diff_entries": diff_entries,
                "diff_truncated": int(diff_truncated),
                "task_status_counts": status_counts,
                "poll_count": poll_count,
                "duration_seconds": duration_seconds,
            }
        )
        action_result.update_summary(
            {
                "tracked_scan_id": tracked_scan_id,
                "target_type": target_type,
                "completed": 1,
                "poll_count": poll_count,
                "duration_seconds": duration_seconds,
                "latest_task_status": latest_task_status,
                "change_count": len(diff_entries),
                "diff_truncated": int(diff_truncated),
            }
        )
        if terminal_failure:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Scan '{tracked_scan_id}' completed with terminal task status '{latest_task_status}'",
            )
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Live rescan completed successfully in {duration_seconds:.2f}s with {len(diff_entries)} detected change(s)",
        )

    def initialize(self) -> int:
        config = self.get_config()
        self._base_url = (config.get("base_url") or CENSYSPLATFORM_DEFAULT_BASE_URL).rstrip("/")
        self._api_token = config.get("api_token")
        organization_id = (config.get("organization_id") or "").strip()
        if not organization_id:
            return self.set_status(
                phantom.APP_ERROR,
                "'organization_id' must be configured",
            )
        if not self._validate_uuid4(organization_id):
            return self.set_status(
                phantom.APP_ERROR,
                "'organization_id' must be a valid UUIDv4",
            )
        self._organization_id = organization_id

        if not self._api_token:
            return self.set_status(phantom.APP_ERROR, "API token must be configured")

        return phantom.APP_SUCCESS

    def handle_action(self, param: dict[str, Any]) -> int:
        action_mapping = {
            ACTION_ID_TEST_CONNECTIVITY: self._handle_test_connectivity,
            ACTION_ID_LOOKUP_HOST: self._handle_lookup_host,
            ACTION_ID_LOOKUP_CERT: self._handle_lookup_cert,
            ACTION_ID_LOOKUP_WEB_PROPERTY: self._handle_lookup_web_property,
            ACTION_ID_SEARCH: self._handle_search,
            ACTION_ID_GET_HOST_EVENT_HISTORY: self._handle_get_host_event_history,
            ACTION_ID_GET_HOST_SERVICE_HISTORY: self._handle_get_host_service_history,
            ACTION_ID_FIND_RELATED_ASSETS_FROM_HOST: self._handle_find_related_assets_from_host,
            ACTION_ID_FIND_RELATED_ASSETS_FROM_WEB: self._handle_find_related_assets_from_web,
            ACTION_ID_LIVE_RESCAN: self._handle_live_rescan,
        }

        action_id = self.get_action_identifier()
        if action_id not in action_mapping:
            return phantom.APP_ERROR

        return action_mapping[action_id](param)


if __name__ == "__main__":
    import sys

    connector = CensysplatformConnector()
    connector.print_progress_message = True
    sys.exit(0)
