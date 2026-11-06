import { invoke } from '@tauri-apps/api/core'
import type { ApplicationEntry, BackendInfo, Capabilities, DaemonStatus, DiagnosticReport, PlanPreview, PolicyChange, PolicyResolution } from './types'

export const demoMode = import.meta.env.VITE_DEMO === '1'
const readMethods = ['daemon.ping', 'daemon.version', 'daemon.capabilities', 'daemon.status', 'daemon.diagnostics', 'daemon.plan'] as const
export type ReadMethod = typeof readMethods[number]

export function isReadMethod(value: string): value is ReadMethod {
  return readMethods.includes(value as ReadMethod)
}

export async function daemonRead<T>(method: ReadMethod): Promise<T> {
  if (!isReadMethod(method)) throw new Error('Unsupported daemon method')
  return invoke<T>('daemon_read', { method })
}

export const backendInfo = () => invoke<BackendInfo>('backend_info')
export const cliRead = <T>(kind: 'apps' | 'policies') => invoke<T>('cli_read', { kind })
export const setPolicy = (change: PolicyChange) => invoke<void>('policy_set', { change })
export const removePolicy = (id: string) => invoke<void>('policy_remove', { id })
export const iconData = (icon: string) => invoke<string | null>('icon_data', { icon })

export interface LiveData {
  info?: BackendInfo
  capabilities?: Capabilities
  status?: DaemonStatus
  diagnostics?: DiagnosticReport
  plan?: PlanPreview
  apps: ApplicationEntry[]
  policies: PolicyResolution[]
  errors: string[]
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function validCapabilities(value: unknown): value is Capabilities {
  return record(value) && value.mode === 'PLAN_ONLY' && value.host_apply === 'UNSUPPORTED' && Array.isArray(value.read_only) && value.read_only.every(method => typeof method === 'string' && isReadMethod(method))
}

export function validStatus(value: unknown): value is DaemonStatus {
  return record(value) && value.state === 'PLANNED' && value.mode === 'PLAN_ONLY' && value.applied === false && record(value.snapshot) && Array.isArray(value.snapshot.devices) && Array.isArray(value.snapshot.routes)
}

export function validPlan(value: unknown): value is PlanPreview {
  return record(value) && value.state === 'PLANNED' && value.mode === 'PLAN_ONLY' && value.applied === false && record(value.proposed_resources) && Array.isArray(value.conflicts) && Array.isArray(value.warnings)
}

export async function loadLiveData(): Promise<LiveData> {
  const data: LiveData = { apps: [], policies: [], errors: [] }
  const [info, capabilities, apps, policies] = await Promise.allSettled([
    backendInfo(),
    daemonRead<Capabilities>('daemon.capabilities'),
    cliRead<ApplicationEntry[]>('apps'),
    cliRead<PolicyResolution[]>('policies'),
  ])
  if (info.status === 'fulfilled') data.info = info.value
  else data.errors.push(`Backend paths: ${String(info.reason)}`)
  if (apps.status === 'fulfilled' && (apps.value === null || Array.isArray(apps.value))) data.apps = apps.value ?? []
  else if (apps.status === 'fulfilled') data.errors.push('Application discovery: invalid CLI response')
  else data.errors.push(`Application discovery: ${String(apps.reason)}`)
  if (policies.status === 'fulfilled' && (policies.value === null || Array.isArray(policies.value))) data.policies = policies.value ?? []
  else if (policies.status === 'fulfilled') data.errors.push('Saved policies: invalid CLI response')
  else data.errors.push(`Saved policies: ${String(policies.reason)}`)
  if (capabilities.status === 'fulfilled' && validCapabilities(capabilities.value)) {
    data.capabilities = capabilities.value
    const allowed = new Set(capabilities.value.read_only)
    const calls = [
      ['daemon.status', 'Network status'],
      ['daemon.diagnostics', 'Diagnostics'],
      ['daemon.plan', 'Routing plan'],
    ] as const
    const results = await Promise.allSettled(calls.map(([method]) => allowed.has(method) ? daemonRead(method) : Promise.reject(new Error('Method not advertised by daemon'))))
    results.forEach((result, index) => {
      if (result.status === 'rejected') data.errors.push(`${calls[index][1]}: ${String(result.reason)}`)
      else if (index === 0 && validStatus(result.value)) data.status = result.value
      else if (index === 1 && record(result.value) && result.value.read_only === true && Array.isArray(result.value.findings)) data.diagnostics = result.value as unknown as DiagnosticReport
      else if (index === 2 && validPlan(result.value)) data.plan = result.value
      else data.errors.push(`${calls[index][1]}: invalid or unsafe backend response`)
    })
  } else data.errors.push(`Daemon connection: ${capabilities.status === 'rejected' ? String(capabilities.reason) : 'incompatible capabilities'}`)
  return data
}
