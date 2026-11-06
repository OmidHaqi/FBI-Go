export type FindingStatus = 'INFO' | 'WARNING' | 'BLOCKED' | 'UNKNOWN'
export type PolicyMode = 'AUTO' | 'PINNED_WAN' | 'SYSTEM_DEFAULT'
export type FailureBehavior = 'STRICT' | 'FAILOVER'

export interface Device {
  id: string
  name: string
  kind: string
  state: string
  admin_up: boolean
  oper_state?: string
  carrier?: boolean
  addresses: string[]
  gateways?: string[]
  rx_bytes: number
  tx_bytes: number
  candidate: boolean
  reasons: string[]
}

export interface Route {
  family: string
  destination: string
  gateway?: string
  interface: string
  table: number
  metric: number
  source?: string
}

export interface Snapshot {
  devices: Device[]
  routes: Route[]
  warnings?: string[]
}

export interface DaemonStatus {
  state: 'PLANNED'
  mode: 'PLAN_ONLY'
  applied: false
  snapshot: Snapshot
}

export interface Finding {
  code: string
  status: FindingStatus
  detail: string
}

export interface DiagnosticReport {
  read_only: boolean
  findings: Finding[]
}

export interface Capabilities {
  mode: string
  read_only: string[]
  host_apply: string
  isolated_test: string
}

export interface PlanResource {
  safe_to_apply?: boolean
  reasons?: string[]
  warnings?: string[]
  wans?: unknown[]
  [key: string]: unknown
}

export interface PlanPreview {
  state: 'PLANNED'
  mode: 'PLAN_ONLY'
  applied: false
  requested_policy: ApplicationPolicy
  validated_wan_id?: string
  proposed_resources: PlanResource
  conflicts: string[]
  warnings: string[]
  required_operations: string[]
}

export interface ApplicationEntry {
  id: string
  name: string
  generic_name?: string
  icon?: string
  exec?: string
  launch_supported: boolean
  limitations?: string[]
  no_display: boolean
  hidden: boolean
  source: string
}

export interface ApplicationPolicy {
  id: string
  display_name?: string
  desktop_entry?: string
  executable?: string
  mode: PolicyMode
  preferred_wan?: string
  fallback_wan?: string
  failure_behavior?: FailureBehavior
  enabled: boolean
}

export interface PolicyResolution {
  policy: ApplicationPolicy
  status: string
  reason?: string
  preferred_interface?: string
  fallback_interface?: string
}

export interface BackendInfo {
  socket: string
  cli: string
  host_apply: string
}

export interface PolicyChange {
  id: string
  mode: 'AUTO' | 'PINNED_WAN'
  wan?: string | null
  behavior?: FailureBehavior | null
  fallback?: string | null
}
