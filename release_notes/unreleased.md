**Unreleased**

* - Added history/related-assets/live-rescan action coverage with new actions:
  * `get_host_event_history`, `get_host_service_history`, `find_related_assets_from_host`,
  * `find_related_assets_from_web`, and streamlined `live_rescan` with built-in wait and diff view.
* - Added SOC-focused custom widget rendering for history, related-assets, search, and live-rescan actions,
  * replacing blank/default nested JSON tables with actionable summaries and triage-friendly result rows.
