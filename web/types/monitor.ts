/**
 * Monitor types — adapted to VoidAccess YAML-backed monitor system.
 * Backend stores watches in monitors.yaml; `name` is the unique identifier.
 * Status is derived from enabled flag + scheduler state.
 * `alert_count` is unacknowledged alerts from GET /monitors/alerts/count (by_monitor).
 */

export interface MonitorAlert {
  id: number
  triggered_at: string
  change_type:
    | "new_entities"
    | "content_change"
    | "new_page"
    | "first_result"
    | "significant_change"
    | string
  summary: string
  severity: "info" | "warning" | "critical"
  entity_count_delta: number
  delivered: boolean
  delivery_channels: string[]
  acknowledged: boolean
  acknowledged_at: string | null
  diff_data: Record<string, unknown> | null
}

export interface AlertCountResponse {
  total_unacknowledged: number
  by_monitor: Record<string, number>
}

export interface Monitor {
  /** Unique identifier — maps to `name` in monitors.yaml */
  id: string
  type: "keyword" | "url"
  /** For keyword watches: the search query. For url watches: the target URL. */
  query: string
  /** active = enabled, paused = disabled. "alert" not used (no stored alert state). */
  status: "active" | "paused"
  check_interval_hours: number
  /** ISO string from APScheduler last_run_time, or null if never run */
  last_checked_at: string | null
  /** ISO string from APScheduler next_run_time, or null if scheduler not running */
  next_check_at: string | null
  /** Unacknowledged alerts for this monitor (from by_monitor) */
  alert_count: number
  /** ["webhook", "telegram", "email"] based on configured channels */
  alert_channels: string[]
  /** Underlying alert_on setting from YAML */
  alert_on: string
  /** ISO timestamp of most recent alert, or null if never run */
  last_run_at?: string | null
  /** change_type of most recent alert, or null */
  last_run_status?: string | null
  /** Total count of alerts for this monitor */
  total_runs?: number
  /** entity_count_delta from most recent alert */
  last_entity_count?: number
}

export interface CreateMonitorInput {
  name: string
  type: "keyword" | "url"
  query?: string
  url?: string
  interval_hours: number
  alert_on: string
  webhook_url?: string
  telegram_chat_id?: string
  email?: string
  enabled?: boolean
}

/** Raw watch shape returned by GET /monitors */
export interface RawWatch {
  name: string
  type: "keyword" | "url"
  query?: string
  url?: string
  interval_hours: number
  alert_on: string
  enabled: boolean
  webhook_url?: string | null
  telegram_chat_id?: string | null
  email?: string | null
}

/** Raw status shape returned by GET /monitors/status */
export interface RawWatchStatus {
  name: string
  next_run_time: string | null
  last_run_time: string | null
}
