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
import uuid
from typing import Any

import phantom.app as phantom
from censys_platform import SDK, models
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from censysplatform_consts import (
    ACTION_ID_LOOKUP_CERT,
    ACTION_ID_LOOKUP_HOST,
    ACTION_ID_LOOKUP_WEB_PROPERTY,
    ACTION_ID_SEARCH,
    ACTION_ID_TEST_CONNECTIVITY,
    CENSYSPLATFORM_DEFAULT_BASE_URL,
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
