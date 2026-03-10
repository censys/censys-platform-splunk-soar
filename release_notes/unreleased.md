**Unreleased**

* - Added Censys Platform investigative actions for `lookup_host`, `lookup_cert`,
  * `lookup_web_property`, and `search`.
* - Implemented SDK-based connectivity validation and action handlers in
  * `censysplatform_connector.py`.
* - Added a custom widget for `search` that reuses the existing host,
  * certificate, and web property result fields.
* - Updated app metadata, configuration schema, and dependencies for Censys
  * Platform support.
* - Added history/related-assets/live-rescan action coverage with new actions:
  * `get_host_event_history`, `get_host_service_history`, `find_related_assets_from_host`,
  * `find_related_assets_from_web`, and streamlined `live_rescan` with built-in wait and diff view.
* - Added SOC-focused custom widget rendering for history, related-assets, search, and live-rescan actions,
  * replacing blank/default nested JSON tables with actionable summaries and triage-friendly result rows.
