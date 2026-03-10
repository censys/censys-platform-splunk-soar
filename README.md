# Censys for Splunk SOAR

Publisher: Censys <br>
Connector Version: 1.0.1 <br>
Product Vendor: Censys <br>
Product Name: Censys Platform <br>
Minimum Product Version: 6.3.0

This app implements investigative actions to get IP, domain and certificate data from the Censys Platform.

### Configuration variables

This table lists the configuration variables required to operate Censys for Splunk SOAR. These variables are specified when configuring a Censys Platform asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | optional | string | Base URL for Censys Platform API |
**api_token** | required | password | Personal access token for authentication |
**organization_id** | required | string | Organization UUID used to scope requests |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity <br>
[lookup host](#action-lookup-host) - Retrieve a host by IPv4 or IPv6 address <br>
[lookup cert](#action-lookup-cert) - Retrieve a certificate by SHA256 fingerprint <br>
[lookup web property](#action-lookup-web-property) - Retrieve a web property by hostname and port <br>
[get host event history](#action-get-host-event-history) - Retrieve host event history for an IP and time window <br>
[get host service history](#action-get-host-service-history) - Retrieve historical service observations for a host <br>
[find related assets from host](#action-find-related-assets-from-host) - Generate and execute a related-assets search from a host seed <br>
[find related assets from web](#action-find-related-assets-from-web) - Generate and execute a related-assets search from a web property seed <br>
[live rescan](#action-live-rescan) - Initiate a live rescan and wait for completion, then return a baseline-vs-post change log <br>
[search](#action-search) - Search Censys assets using a CenQL query

## action: 'test connectivity'

Validate the asset configuration for connectivity

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.message | string | | |

## action: 'lookup host'

Retrieve a host by IPv4 or IPv6 address

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IPv4 or IPv6 address for lookup | string | `ip` |
**at_time** | optional | Optional ISO 8601 timestamp for historical lookup | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.ip | string | `ip` | |
action_result.data.\*.ip | string | `ip` | |
action_result.summary.ip | string | `ip` | |
action_result.summary.service_count | numeric | | |
action_result.summary.ports | string | `port` | |
action_result.summary.scan_time | string | | |
action_result.message | string | | |
action_result.parameter.at_time | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup cert'

Retrieve a certificate by SHA256 fingerprint

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**fingerprint_sha256** | required | Certificate SHA256 fingerprint | string | `sha256` `hash` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.fingerprint_sha256 | string | `sha256` `hash` | |
action_result.data.\*.fingerprint_sha256 | string | `sha256` `hash` | |
action_result.summary.display_name | string | | |
action_result.summary.fingerprint_sha256 | string | `sha256` `hash` | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup web property'

Retrieve a web property by hostname and port

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** | required | Hostname or IP address for lookup | string | `domain` `ip` |
**port** | required | TCP port value (1-65535) | numeric | |
**at_time** | optional | Optional ISO 8601 timestamp for historical lookup | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.hostname | string | `domain` `ip` | |
action_result.parameter.port | numeric | | |
action_result.data.\*.hostname | string | `domain` `ip` | |
action_result.data.\*.port | numeric | | |
action_result.summary.endpoint_count | numeric | | |
action_result.summary.hostname | string | `domain` `ip` | |
action_result.summary.port | numeric | | |
action_result.summary.endpoints | string | | |
action_result.summary.scan_time | string | | |
action_result.message | string | | |
action_result.parameter.at_time | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get host event history'

Retrieve host event history for an IP and time window

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host_id** | required | Host IP address | string | `ip` |
**start_time** | required | Upper RFC3339/ISO 8601 timestamp bound (newer time) | string | |
**end_time** | required | Lower RFC3339/ISO 8601 timestamp bound (older time) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.host_id | string | `ip` | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.data.\*.request.host_id | string | `ip` | |
action_result.data.\*.events.\*.resource.event_time | string | | |
action_result.data.\*.scanned_to | string | | |
action_result.summary.host_id | string | `ip` | |
action_result.summary.event_count | numeric | | |
action_result.summary.first_event_time | string | | |
action_result.summary.last_event_time | string | | |
action_result.summary.has_service_scanned | numeric | | |
action_result.summary.has_endpoint_scanned | numeric | | |
action_result.summary.has_dns_updates | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'get host service history'

Retrieve historical service observations for a host

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host_id** | required | Host IP address | string | `ip` |
**start_time** | optional | Optional RFC3339/ISO 8601 start timestamp | string | |
**end_time** | optional | Optional RFC3339/ISO 8601 end timestamp | string | |
**page_size** | optional | Maximum rows to return (1-100) | numeric | |
**page_token** | optional | Pagination token from prior response | string | |
**port** | optional | Optional service port filter | numeric | |
**protocol** | optional | Optional application protocol filter | string | |
**transport_protocol** | optional | Optional transport protocol filter (tcp, udp, quic) | string | |
**order_by** | optional | Optional comma-separated order list (e.g. port ASC,protocol DESC) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.host_id | string | `ip` | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.parameter.page_size | numeric | | |
action_result.parameter.page_token | string | | |
action_result.parameter.port | numeric | | |
action_result.parameter.protocol | string | | |
action_result.parameter.transport_protocol | string | | |
action_result.parameter.order_by | string | | |
action_result.data.\*.host_id | string | `ip` | |
action_result.data.\*.ranges.\*.ip | string | `ip` | |
action_result.data.\*.ranges.\*.port | numeric | | |
action_result.data.\*.ranges.\*.protocol | string | | |
action_result.data.\*.ranges.\*.transport_protocol | string | | |
action_result.data.\*.ranges.\*.start_time | string | | |
action_result.data.\*.ranges.\*.end_time | string | | |
action_result.data.\*.next_page_token | string | | |
action_result.summary.host_id | string | `ip` | |
action_result.summary.range_count | numeric | | |
action_result.summary.next_page_token_present | numeric | | |
action_result.summary.port_count | numeric | | |
action_result.summary.protocol_count | numeric | | |
action_result.summary.transport_protocol_count | numeric | | |
action_result.summary.min_start_time | string | | |
action_result.summary.max_end_time | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'find related assets from host'

Generate and execute a related-assets search from a host seed

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host_id** | required | Host IP address to use as the related-assets seed | string | `ip` |
**at_time** | optional | Optional RFC3339/ISO 8601 timestamp for the seed lookup | string | |
**page_size** | optional | Maximum number of related assets to return | numeric | |
**page_token** | optional | Pagination token from prior response | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.host_id | string | `ip` | |
action_result.parameter.at_time | string | | |
action_result.parameter.page_size | numeric | | |
action_result.parameter.page_token | string | | |
action_result.data.\*.generated_query | string | | |
action_result.data.\*.seed_host.ip | string | `ip` | |
action_result.data.\*.search_result.total_hits | numeric | | |
action_result.data.\*.search_result.next_page_token | string | | |
action_result.data.\*.search_result.hits.\*.host_v1.resource.ip | string | `ip` | |
action_result.data.\*.search_result.hits.\*.webproperty_v1.resource.hostname | string | `domain` | |
action_result.summary.seed_host | string | `ip` | |
action_result.summary.generated_query | string | | |
action_result.summary.total_hits | numeric | | |
action_result.summary.returned_hits | numeric | | |
action_result.summary.next_page_token_present | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'find related assets from web'

Generate and execute a related-assets search from a web property seed

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** | required | Web property hostname seed | string | `domain` `ip` |
**port** | required | Web property port | numeric | |
**at_time** | optional | Optional RFC3339/ISO 8601 timestamp for the seed lookup | string | |
**page_size** | optional | Maximum number of related assets to return | numeric | |
**page_token** | optional | Pagination token from prior response | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.hostname | string | `domain` `ip` | |
action_result.parameter.port | numeric | | |
action_result.parameter.at_time | string | | |
action_result.parameter.page_size | numeric | | |
action_result.parameter.page_token | string | | |
action_result.data.\*.generated_query | string | | |
action_result.data.\*.seed_web_property.hostname | string | `domain` `ip` | |
action_result.data.\*.seed_web_property.port | numeric | | |
action_result.data.\*.search_result.total_hits | numeric | | |
action_result.data.\*.search_result.next_page_token | string | | |
action_result.data.\*.search_result.hits.\*.host_v1.resource.ip | string | `ip` | |
action_result.data.\*.search_result.hits.\*.webproperty_v1.resource.hostname | string | `domain` | |
action_result.summary.seed_web_property | string | | |
action_result.summary.generated_query | string | | |
action_result.summary.total_hits | numeric | | |
action_result.summary.returned_hits | numeric | | |
action_result.summary.next_page_token_present | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'live rescan'

Initiate a live rescan and wait for completion, then return a baseline-vs-post change log

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | optional | Service target IP address | string | `ip` |
**hostname** | optional | Web target hostname | string | `domain` `ip` |
**port** | required | Target port | numeric | |
**protocol** | optional | Service protocol (required for service target) | string | |
**transport_protocol** | optional | Service transport protocol (unknown, tcp, udp, icmp, quic) for service target | string | |
**target_type** | optional | Optional explicit target type override: service_id or web_origin | string | |
**wait_timeout_seconds** | optional | Maximum wait time before polling times out | numeric | |
**max_diff_entries** | optional | Maximum number of diff rows to include in the change log | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.ip | string | `ip` | |
action_result.parameter.hostname | string | `domain` `ip` | |
action_result.parameter.port | numeric | | |
action_result.parameter.protocol | string | | |
action_result.parameter.transport_protocol | string | | |
action_result.parameter.target_type | string | | |
action_result.parameter.wait_timeout_seconds | numeric | | |
action_result.parameter.max_diff_entries | numeric | | |
action_result.data.\*.target_type | string | | |
action_result.data.\*.initial_tracked_scan.tracked_scan_id | string | | |
action_result.data.\*.final_tracked_scan.tracked_scan_id | string | | |
action_result.data.\*.final_tracked_scan.completed | numeric | | |
action_result.data.\*.final_tracked_scan.tasks.\*.status | string | | |
action_result.data.\*.pre_lookup.lookup_type | string | | |
action_result.data.\*.post_lookup.lookup_type | string | | |
action_result.data.\*.diff_entries.\*.change_type | string | | |
action_result.data.\*.diff_entries.\*.path | string | | |
action_result.data.\*.diff_entries.\*.before | string | | |
action_result.data.\*.diff_entries.\*.after | string | | |
action_result.data.\*.diff_truncated | numeric | | |
action_result.summary.tracked_scan_id | string | | |
action_result.summary.target_type | string | | |
action_result.summary.completed | numeric | | |
action_result.summary.poll_count | numeric | | |
action_result.summary.duration_seconds | numeric | | |
action_result.summary.latest_task_status | string | | |
action_result.summary.change_count | numeric | | |
action_result.summary.diff_truncated | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'search'

Search Censys assets using a CenQL query

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** | required | CenQL query string | string | |
**page_size** | optional | Maximum number of results to return | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.query | string | | |
action_result.summary.query_duration_millis | numeric | | |
action_result.summary.total_hits | numeric | | |
action_result.summary.hit_count | numeric | | |
action_result.message | string | | |
action_result.parameter.page_size | numeric | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
