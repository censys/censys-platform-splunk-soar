# File: censysplatform_consts.py
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

# API endpoints
CENSYSPLATFORM_DEFAULT_BASE_URL = "https://api.platform.censys.io"

# Action identifiers
ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
ACTION_ID_LOOKUP_HOST = "lookup_host"
ACTION_ID_LOOKUP_CERT = "lookup_cert"
ACTION_ID_LOOKUP_WEB_PROPERTY = "lookup_web_property"
ACTION_ID_SEARCH = "search"

# Error messages
CENSYSPLATFORM_ERR_CONNECTIVITY_TEST = "Test Connectivity Failed"

# Success messages
CENSYSPLATFORM_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
