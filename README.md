# Censys for Splunk SOAR

Publisher: Censys <br>
Connector Version: 1.0.0 <br>
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
**hostname** | required | Hostname or IP address for lookup | string | `domain` |
**port** | required | TCP port value (1-65535) | numeric | |
**at_time** | optional | Optional ISO 8601 timestamp for historical lookup | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.parameter.hostname | string | `domain` | |
action_result.parameter.port | numeric | | |
action_result.data.\*.hostname | string | | |
action_result.data.\*.port | numeric | | |
action_result.summary.endpoint_count | numeric | | |
action_result.summary.hostname | string | | |
action_result.summary.port | numeric | | |
action_result.summary.endpoints | string | | |
action_result.summary.scan_time | string | | |
action_result.message | string | | |
action_result.parameter.at_time | string | | |
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
