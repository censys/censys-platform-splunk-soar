**Unreleased**

* - Added history/pivot/live-rescan action coverage with new actions:
  * `get_host_event_history`, `get_host_service_history`, `find_related_infrastructure`,
  * and streamlined `live_rescan` with built-in wait and diff view.
* - Added SOC-focused custom widget rendering for history, CensEye pivot results, search, and live-rescan actions,
  * replacing blank/default nested JSON tables with actionable summaries and triage-friendly result rows.
