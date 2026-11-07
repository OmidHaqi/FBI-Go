import { useEffect, useMemo, useState } from 'react'
import { Activity, AlertCircle, AlertTriangle, ArrowDownLeft, ArrowRight, ArrowUpRight, Blocks, Check, ChevronDown, CircleHelp, Command, Compass, HardDrive, Info, LayoutDashboard, LockKeyhole, Moon, Network, RefreshCw, Router, Search, Settings2, ShieldCheck, Sun, Usb, Wifi, X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { backendInfo, cliRead, demoMode, iconData, loadLiveData, removePolicy, setPolicy } from './bridge'
import type { LiveData } from './bridge'
import { demoData } from './demo'
import { bytes, deviceGroup, severity } from './format'
import type { ApplicationEntry, Device, FailureBehavior, Finding, PolicyResolution } from './types'
import WindowBar from './WindowBar'
import { speed, useTraffic } from './traffic'
import type { TrafficSample } from './traffic'
import { invoke, isTauri } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

type Page = 'dashboard' | 'networks' | 'applications' | 'routing' | 'diagnostics' | 'settings'
type Theme = 'system' | 'light' | 'dark'

const pages: { id: Page; label: string; icon: LucideIcon }[] = [
  { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
  { id: 'networks', label: 'Networks', icon: Network },
  { id: 'applications', label: 'Applications', icon: Blocks },
  { id: 'routing', label: 'Routing plans', icon: Router },
  { id: 'diagnostics', label: 'Diagnostics', icon: Activity },
  { id: 'settings', label: 'Settings', icon: Settings2 },
]

function Badge({ children, tone = 'neutral' }: { children: React.ReactNode; tone?: 'neutral' | 'good' | 'warn' | 'danger' | 'demo' }) {
  return <span className={`badge badge-${tone}`}>{children}</span>
}

function PageTitle({ eyebrow, title, children }: { eyebrow: string; title: string; children?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{children && <p className="page-subtitle">{children}</p>}</div></div>
}

function Empty({ icon: Icon = CircleHelp, title, children }: { icon?: LucideIcon; title: string; children: React.ReactNode }) {
  return <div className="empty"><Icon size={28} strokeWidth={1.5} /><h3>{title}</h3><p>{children}</p></div>
}

function DeviceGlyph({ device }: { device: Device }) {
  const Icon = device.kind === 'wifi' || device.kind === 'wwan' ? Wifi : device.kind === 'usb_network' ? Usb : device.kind === 'vpn' ? LockKeyhole : device.kind === 'virtual' || device.kind === 'bridge' ? Blocks : Network
  return <div className={`device-glyph ${device.candidate ? 'device-glyph-active' : ''}`}><Icon size={19} /></div>
}

function DeviceState({ device }: { device: Device }) {
  const up = device.state === 'up'
  return <span className={`state-text ${up ? 'state-up' : 'state-down'}`}><span className="state-dot" />{up ? 'Link up' : 'Link down'}</span>
}

function DeviceCard({ device, compact = false, traffic }: { device: Device; compact?: boolean; traffic?: TrafficSample }) {
  return <article className={`device-card ${compact ? 'device-card-compact' : ''}`}>
    <div className="device-card-head"><DeviceGlyph device={device} /><div className="device-identity"><h3>{device.name}</h3><span>{device.kind.replaceAll('_', ' ')}</span></div><DeviceState device={device} /></div>
    <div className="device-card-detail"><span>WAN candidate</span><strong>{device.candidate ? 'Yes' : 'No'}</strong></div>
    <div className="device-card-detail"><span>IPv4 / IPv6</span><strong className="truncate">{device.addresses?.join(', ') || 'No address observed'}</strong></div>
    {!compact && <><div className="device-card-detail"><span>Gateway</span><strong>{device.gateways?.join(', ') || 'Not observed'}</strong></div><div className="device-card-detail"><span>Carrier · operstate</span><strong>{device.carrier === undefined ? 'Unknown' : device.carrier ? 'Present' : 'Absent'} · {device.oper_state || 'Unknown'}</strong></div><div className="device-card-detail"><span>Driver · bus</span><strong>{device.driver || 'Unknown'} · {device.bus || 'Unknown'}</strong></div></>}
    <div className="device-rates"><span>↓ {speed(traffic?.rx_bytes_per_second)}</span><span>↑ {speed(traffic?.tx_bytes_per_second)}</span></div>
    <div className="device-counters"><span><ArrowDownLeft size={14} /> RX {bytes(device.rx_bytes)}</span><span><ArrowUpRight size={14} /> TX {bytes(device.tx_bytes)}</span></div>
    {!compact && device.reasons?.length > 0 && <p className="device-reason">{device.reasons.join(' · ')}</p>}
  </article>
}

function FindingItem({ finding }: { finding: Finding }) {
  const Icon = finding.status === 'BLOCKED' ? AlertCircle : finding.status === 'WARNING' ? AlertTriangle : finding.status === 'INFO' ? Info : CircleHelp
  return <div className="finding-item"><div className={`finding-icon finding-${finding.status.toLowerCase()}`}><Icon size={17} /></div><div><div className="finding-title">{finding.code.replaceAll('_', ' ')}</div><p>{finding.detail}</p></div><Badge tone={finding.status === 'BLOCKED' ? 'danger' : finding.status === 'WARNING' ? 'warn' : 'neutral'}>{finding.status}</Badge></div>
}

function Dashboard({ data, navigate, traffic }: { data: LiveData; navigate: (page: Page) => void; traffic: Map<string, TrafficSample> }) {
  const devices = data.status?.snapshot.devices ?? []
  const candidates = devices.filter(d => d.candidate)
  const findings = data.diagnostics?.findings ?? []
  return <>
    <PageTitle eyebrow="SYSTEM OVERVIEW" title="Network at a glance">Observed host inventory and read-only routing status.</PageTitle>
    <div className="hero"><div><span className="hero-label"><ShieldCheck size={17} /> SAFETY MODE</span><h2>Plan only. No host routing changes.</h2><p>FBI-Go can inspect and preview your network. Production host activation is unsupported.</p><button className="hero-link" onClick={() => navigate('routing')}>View routing plan <ArrowRight size={16} /></button></div><div className="hero-mark"><Compass size={84} strokeWidth={1} /></div></div>
    <div className="stat-grid">
      <div className="stat-card"><span>Detected interfaces</span><strong>{data.status ? devices.length : '—'}</strong><small>From the latest read-only snapshot</small></div>
      <div className="stat-card"><span>WAN candidates</span><strong>{data.status ? candidates.length : '—'}</strong><small>Eligibility does not prove connectivity</small></div>
      <div className="stat-card"><span>Live traffic</span><strong>{traffic.size || '—'}</strong><small>Per-interface rates below; no VPN double-counting</small></div>
      <div className="stat-card"><span>Compatibility</span><strong className="stat-label">{data.diagnostics ? severity(findings) : 'Unknown'}</strong><small>{data.diagnostics ? `${findings.length} findings` : 'Daemon diagnostics unavailable'}</small></div>
    </div>
    <div className="section-heading"><div><h2>Interfaces</h2><p>Physical links and virtual devices</p></div><button className="text-button" onClick={() => navigate('networks')}>All networks <ArrowRight size={15} /></button></div>
    {devices.length ? <div className="device-grid">{devices.slice(0, 3).map(d => <DeviceCard key={d.id + d.name} device={d} traffic={traffic.get(d.name)} compact />)}</div> : <Empty icon={Network} title="No interface data">Connect the read-only daemon to load a real snapshot.</Empty>}
    <div className="section-heading"><div><h2>Attention needed</h2><p>Compatibility and safety findings</p></div><button className="text-button" onClick={() => navigate('diagnostics')}>Open diagnostics <ArrowRight size={15} /></button></div>
    <div className="panel">{findings.length ? findings.filter(f => f.status !== 'INFO').slice(0, 3).map((f, i) => <FindingItem key={`${f.code}-${i}`} finding={f} />) : <Empty icon={ShieldCheck} title="No findings available">Diagnostics are unavailable or returned no warnings. This is not proof of routing safety.</Empty>}</div>
  </>
}

function Networks({ data, traffic }: { data: LiveData; traffic: Map<string, TrafficSample> }) {
  const devices = data.status?.snapshot.devices ?? []
  const physical = devices.filter(d => deviceGroup(d) === 'Physical')
  const virtual = devices.filter(d => deviceGroup(d) === 'Virtual / VPN')
  return <><PageTitle eyebrow="NETWORK INVENTORY" title="Networks">Actual link metadata from the read-only daemon. Health probes and latency are not available.</PageTitle>
    <div className="note"><Info size={17} /><span>WAN candidate means the interface passed conservative local checks. Internet reachability and uplink independence have not been measured.</span></div>
    {(['Physical', 'Virtual / VPN'] as const).map(group => {
      const list = group === 'Physical' ? physical : virtual
      return <section key={group}><div className="section-heading"><div><h2>{group}</h2><p>{list.length} observed interfaces</p></div></div>{list.length ? <div className="device-grid">{list.map(d => <DeviceCard key={d.id + d.name} device={d} traffic={traffic.get(d.name)} />)}</div> : <Empty icon={Network} title={`No ${group.toLowerCase()} devices observed`}>The current snapshot does not include devices in this group.</Empty>}</section>
    })}
    <div className="section-heading"><div><h2>Observed routes</h2><p>Read-only routing inventory</p></div></div>
    <div className="table-scroll"><table><thead><tr><th>Family</th><th>Destination</th><th>Gateway</th><th>Interface</th><th>Table</th><th>Metric</th></tr></thead><tbody>{(data.status?.snapshot.routes ?? []).map((r, i) => <tr key={`${r.interface}-${r.table}-${i}`}><td>{r.family}</td><td className="mono">{r.destination}</td><td className="mono">{r.gateway || '—'}</td><td>{r.interface}</td><td>{r.table}</td><td>{r.metric}</td></tr>)}</tbody></table>{!data.status?.snapshot.routes?.length && <div className="table-empty">No routes available in the current snapshot.</div>}</div>
  </>
}

function AppIcon({ app }: { app: ApplicationEntry }) {
  const [src, setSrc] = useState<string | null>(null)
  useEffect(() => {
    let active = true
    setSrc(null)
    if (!demoMode && app.icon) iconData(app.icon).then(value => { if (active) setSrc(value) }).catch(() => {})
    return () => { active = false }
  }, [app.icon])
  return <span className="app-icon" aria-hidden="true">{src ? <img src={src} alt="" /> : app.name.slice(0, 1).toUpperCase()}</span>
}

function Applications({ data, onReload, notify }: { data: LiveData; onReload: () => Promise<void>; notify: (message: string, error?: boolean) => void }) {
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<'all' | 'configured' | 'unsupported'>('all')
  const [selected, setSelected] = useState<string | null>(null)
  const [mode, setMode] = useState<'AUTO' | 'PINNED_WAN'>('AUTO')
  const [wan, setWan] = useState('')
  const [behavior, setBehavior] = useState<FailureBehavior>('STRICT')
  const [fallback, setFallback] = useState('')
  const [busy, setBusy] = useState(false)
  const policies = useMemo(() => new Map(data.policies.map(p => [p.policy.id, p])), [data.policies])
  const apps = useMemo(() => data.apps.filter(app => !app.hidden && !app.no_display && (app.name.toLowerCase().includes(search.toLowerCase()) || app.id.toLowerCase().includes(search.toLowerCase())) && (filter === 'all' || filter === 'configured' && policies.has(app.id) || filter === 'unsupported' && !app.launch_supported)), [data.apps, search, filter, policies])
  const selectedApp = data.apps.find(app => app.id === selected)
  const current = selected ? policies.get(selected) : undefined
  const wanOptions = (data.status?.snapshot.devices ?? []).filter(d => d.id.startsWith('mac:') && d.candidate)

  function choose(app: ApplicationEntry) {
    setSelected(app.id)
    const p = policies.get(app.id)?.policy
    setMode(p?.mode === 'PINNED_WAN' ? 'PINNED_WAN' : 'AUTO')
    setWan(p?.preferred_wan ?? '')
    setBehavior(p?.failure_behavior ?? 'STRICT')
    setFallback(p?.fallback_wan ?? '')
  }

  async function save() {
    if (!selected || demoMode) return
    setBusy(true)
    try {
      await setPolicy({ id: selected, mode, wan: mode === 'PINNED_WAN' ? wan : null, behavior: mode === 'PINNED_WAN' ? behavior : null, fallback: mode === 'PINNED_WAN' && behavior === 'FAILOVER' ? fallback : null })
      await onReload()
      notify('Policy saved for future managed launches. Host routing remains inactive.')
    } catch (error) { notify(String(error), true) } finally { setBusy(false) }
  }

  async function remove() {
    if (!selected || demoMode) return
    setBusy(true)
    try { await removePolicy(selected); await onReload(); notify('Saved policy removed.') }
    catch (error) { notify(String(error), true) } finally { setBusy(false) }
  }

  return <><PageTitle eyebrow="APPLICATION POLICIES" title="Applications">Discover desktop entries and save per-application preferences.</PageTitle>
    <div className="note"><LockKeyhole size={17} /><span>Saving a policy changes your configuration file only. It does not route this app, launch it, or affect a running process.</span></div>
    <div className="app-layout"><div className="app-list-panel"><div className="app-list-tools"><label className="search-field"><Search size={17} /><span className="sr-only">Search applications</span><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search applications" /></label><label className="filter-field"><span className="sr-only">Filter applications</span><select value={filter} onChange={e => setFilter(e.target.value as typeof filter)}><option value="all">All</option><option value="configured">Configured</option><option value="unsupported">Limited support</option></select><ChevronDown size={14} /></label></div><div className="app-count">{apps.length} applications</div><div className="app-list">{apps.length ? apps.slice(0, 100).map(app => <button key={app.id} className={`app-row ${selected === app.id ? 'app-row-selected' : ''}`} onClick={() => choose(app)}><AppIcon app={app} /><span className="app-row-main"><strong>{app.name}</strong><small>{app.generic_name || app.id}</small></span><span className="app-row-status">{policies.has(app.id) ? 'Configured' : 'System'}</span></button>) : <Empty icon={Search} title="No applications found">Try another search, or check desktop entry discovery.</Empty>}</div></div>
    <div className="policy-panel">{selectedApp ? <><div className="policy-head"><AppIcon app={selectedApp} /><div><h2>{selectedApp.name}</h2><p className="mono">{selectedApp.id}</p></div></div><div className="policy-state"><span>Saved policy</span><Badge tone={current?.status === 'RESOLVED' ? 'good' : current ? 'warn' : 'neutral'}>{current?.status || 'Not configured'}</Badge></div>{current?.reason && <p className="field-help">{current.reason}</p>}{!selectedApp.launch_supported && <div className="inline-warning"><AlertTriangle size={16} />Desktop launch limitations: {selectedApp.limitations?.join('; ') || 'Unknown'}. The UI cannot launch it.</div>}
      <fieldset className="form-group"><legend>Routing preference</legend><label className="radio-card"><input type="radio" checked={mode === 'AUTO'} onChange={() => setMode('AUTO')} /><span><strong>Automatic</strong><small>Save AUTO preference. No active routing.</small></span></label><label className="radio-card"><input type="radio" checked={mode === 'PINNED_WAN'} onChange={() => setMode('PINNED_WAN')} /><span><strong>Pin to WAN</strong><small>Save a preferred WAN identity.</small></span></label></fieldset>
      {mode === 'PINNED_WAN' && <div className="form-stack"><label>Preferred WAN<select value={wan} onChange={e => setWan(e.target.value)}><option value="">Select a candidate</option>{wanOptions.map(d => <option value={d.id} key={d.id}>{d.name} · {d.id}</option>)}</select></label><label>Failure behavior<select value={behavior} onChange={e => setBehavior(e.target.value as FailureBehavior)}><option value="STRICT">Strict — no fallback</option><option value="FAILOVER">Failover — explicit alternate</option></select></label>{behavior === 'FAILOVER' && <label>Fallback WAN<select value={fallback} onChange={e => setFallback(e.target.value)}><option value="">Select fallback</option>{wanOptions.filter(d => d.id !== wan).map(d => <option value={d.id} key={d.id}>{d.name} · {d.id}</option>)}</select></label>}{wanOptions.length === 0 && <p className="field-help">No resolvable MAC-based WAN candidate is available from the daemon.</p>}</div>}
      <div className="policy-actions"><button className="primary-button" disabled={busy || demoMode || mode === 'PINNED_WAN' && (!wan || behavior === 'FAILOVER' && !fallback)} onClick={save}>{busy ? 'Saving…' : 'Save policy'}</button>{current && <button className="secondary-button" disabled={busy || demoMode} onClick={remove}>Remove saved policy</button>}</div><p className="field-help">Policy status is configuration and resolution only. Enforcement and host app launch are unsupported.</p></> : <Empty icon={Command} title="Select an application">Choose an installed application to inspect or edit its saved policy.</Empty>}</div></div>
  </>
}

function RoutingPlans({ data }: { data: LiveData }) {
  const p = data.plan
  return <><PageTitle eyebrow="ROUTING PREVIEW" title="Routing plans">A read-only proposal from the daemon. No resources are reserved or installed.</PageTitle><div className="plan-banner"><LockKeyhole size={21} /><div><strong>PLAN_ONLY</strong><p>Host activation is unsupported. Preview identifiers may conflict with resources the daemon cannot read.</p></div><Badge tone="warn">NOT APPLIED</Badge></div>
    {!p ? <Empty icon={Router} title="Plan unavailable">Connect a compatible version 1 daemon to see a preview.</Empty> : <div className="two-column"><div className="panel padded"><h2>Proposed resources</h2><div className="detail-pair"><span>State</span><strong>{p.state}</strong></div><div className="detail-pair"><span>Applied</span><strong>{p.applied ? 'Yes' : 'No'}</strong></div><div className="detail-pair"><span>Requested mode</span><strong>{p.requested_policy?.mode || '—'}</strong></div><div className="detail-pair"><span>Safe to apply</span><strong>{p.proposed_resources?.safe_to_apply ? 'Planner says yes; host still unsupported' : 'No'}</strong></div><pre className="resource-json">{JSON.stringify(p.proposed_resources, null, 2)}</pre></div><div className="panel padded"><h2>Warnings & conflicts</h2>{(p.conflicts ?? []).length === 0 && (p.warnings ?? []).length === 0 ? <p className="muted">No warnings returned. Inventory may still be incomplete.</p> : <>{(p.conflicts ?? []).map((c, i) => <div className="plan-issue" key={`c${i}`}><AlertCircle size={16} />{c}</div>)}{(p.warnings ?? []).map((w, i) => <div className="plan-issue warning" key={`w${i}`}><AlertTriangle size={16} />{w}</div>)}</>}<h3>Required operations</h3><p className="muted">{p.required_operations?.length ? p.required_operations.join(', ') : 'No executable operations exposed to the desktop client.'}</p></div></div>}
  </>
}

function Diagnostics({ data }: { data: LiveData }) {
  const findings = data.diagnostics?.findings ?? []
  const groups = ['BLOCKED', 'WARNING', 'UNKNOWN', 'INFO'] as const
  return <><PageTitle eyebrow="COMPATIBILITY" title="Diagnostics">Read-only checks for routing conflicts and operating-system integration.</PageTitle><div className="note"><Info size={17} /><span>Permission-denied inspection is UNKNOWN. This report cannot certify production host routing safety.</span></div>
    {data.errors.length > 0 && <section><div className="section-heading"><div><h2>Connection & data errors</h2></div></div><div className="panel">{data.errors.map((e, i) => <div className="plan-issue" key={i}><AlertCircle size={16} />{e}</div>)}</div></section>}
    {data.diagnostics ? groups.map(group => { const list = findings.filter(f => f.status === group); return list.length ? <section key={group}><div className="section-heading"><div><h2>{group[0] + group.slice(1).toLowerCase()}</h2><p>{list.length} findings</p></div></div><div className="panel">{list.map((f, i) => <FindingItem key={`${f.code}-${i}`} finding={f} />)}</div></section> : null }) : <Empty icon={Activity} title="Diagnostics unavailable">Start the read-only daemon and refresh.</Empty>}
  </>
}

function Settings({ data, theme, setTheme }: { data: LiveData; theme: Theme; setTheme: (theme: Theme) => void }) {
  const [trayMode, setTrayMode] = useState(() => localStorage.getItem('fbi-go-tray-mode') !== 'false')
  useEffect(() => { if (isTauri()) void invoke('set_tray_mode', { enabled: trayMode }).catch(() => {}) }, [trayMode])
  function changeTrayMode(enabled: boolean) { localStorage.setItem('fbi-go-tray-mode', String(enabled)); setTrayMode(enabled) }
  return <><PageTitle eyebrow="PREFERENCES" title="Settings">Desktop appearance and backend connection details.</PageTitle><div className="settings-grid"><div className="panel padded"><h2>Appearance</h2><p className="muted">System colors are followed by default.</p><div className="theme-options">{(['system', 'light', 'dark'] as const).map(option => { const Icon = option === 'system' ? HardDrive : option === 'light' ? Sun : Moon; return <button key={option} className={`theme-button ${theme === option ? 'selected' : ''}`} onClick={() => setTheme(option)}><Icon size={18} />{option[0].toUpperCase() + option.slice(1)}{theme === option && <Check size={15} />}</button> })}</div><div className="detail-pair"><span>Language</span><strong>English</strong></div><p className="field-help">Layout uses logical spacing and is ready for a future Persian RTL translation.</p></div>
    <div className="panel padded"><h2>Backend connection</h2><div className="detail-pair"><span>Mode</span><strong>{data.capabilities?.mode || 'Disconnected'}</strong></div><div className="detail-pair"><span>Daemon socket</span><strong className="mono wrap">{data.info?.socket || 'Unavailable'}</strong></div><div className="detail-pair"><span>CLI binary</span><strong className="mono wrap">{data.info?.cli || 'Unavailable'}</strong></div><div className="detail-pair"><span>Host apply</span><strong>UNSUPPORTED</strong></div><label className="tray-toggle"><input type="checkbox" checked={trayMode} onChange={event => changeTrayMode(event.target.checked)} />Keep monitoring when window closes</label><p className="field-help">Disable tray mode to exit when closing the window. GNOME Shell may need an AppIndicator extension to show the tray icon; disable tray mode if Open and Quit are not visible.</p><p className="field-help">Start `fbi daemon serve --dry-run` in a private directory. The UI only connects to the selected version 1 socket.</p></div></div></>
}

export default function App() {
  useEffect(() => {
    const disableWebviewMenu = (event: MouseEvent) => event.preventDefault()
    document.addEventListener('contextmenu', disableWebviewMenu, true)
    return () => document.removeEventListener('contextmenu', disableWebviewMenu, true)
  }, [])
  const [page, setPage] = useState<Page>('dashboard')
  useEffect(() => {
    if (!isTauri()) return
    let active = true
    let unlisten: (() => void) | undefined
    void listen('open-networks', () => setPage('networks')).then(stop => { if (active) unlisten = stop; else stop() })
    return () => { active = false; unlisten?.() }
  }, [])
  const [data, setData] = useState<LiveData>(demoMode ? demoData : { apps: [], policies: [], errors: [] })
  const [loading, setLoading] = useState(!demoMode)
  const [toast, setToast] = useState<{ message: string; error: boolean } | null>(null)
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem('fbi-go-theme') as Theme) || 'system')
  const traffic = useTraffic()
  useEffect(() => { if (theme === 'system') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = theme; localStorage.setItem('fbi-go-theme', theme) }, [theme])
  useEffect(() => { if (isTauri()) void invoke('set_tray_mode', { enabled: localStorage.getItem('fbi-go-tray-mode') !== 'false' }).catch(() => {}) }, [])
  useEffect(() => { if (!demoMode) void refresh() }, [])
  function notify(message: string, error = false) { setToast({ message, error }); window.setTimeout(() => setToast(null), 6000) }
  async function refresh() { if (demoMode) return; setLoading(true); try { setData(await loadLiveData()) } finally { setLoading(false) } }
  async function refreshPolicies() {
    if (demoMode) return
    const [policies, info] = await Promise.all([cliRead<PolicyResolution[]>('policies'), backendInfo()])
    setData(previous => ({ ...previous, policies: policies ?? [], info }))
  }
  const activePage = pages.find(item => item.id === page)!
  return <><WindowBar /><div className="app-shell" dir="ltr"><aside className="sidebar"><div className="brand"><div className="brand-symbol"><Compass size={24} strokeWidth={1.8} /></div><div><strong>FBI-Go</strong><span>NETWORK MANAGER</span></div></div><div className="sidebar-label">WORKSPACE</div><nav aria-label="Main navigation">{pages.map(item => <button key={item.id} aria-label={item.label} className={`nav-item ${page === item.id ? 'active' : ''}`} aria-current={page === item.id ? 'page' : undefined} onClick={() => setPage(item.id)}><item.icon size={18} strokeWidth={1.8} /><span>{item.label}</span></button>)}</nav><div className="sidebar-bottom"><div className="sidebar-mode"><span className="sidebar-mode-icon"><ShieldCheck size={17} /></span><span><strong>Protected by design</strong><small>Host apply unavailable</small></span></div><div className="sidebar-version">FBI-Go {import.meta.env.VITE_APP_VERSION} · PLAN_ONLY</div></div></aside>
    <div className="main-shell"><header className="topbar"><div className="breadcrumb"><span>FBI-Go</span><span className="breadcrumb-divider">/</span><strong>{activePage.label}</strong></div><div className="topbar-actions">{demoMode && <Badge tone="demo">DEMO DATA</Badge>}<Badge tone={data.capabilities?.mode === 'PLAN_ONLY' ? 'warn' : 'neutral'}>{data.capabilities?.mode || 'DAEMON OFFLINE'}</Badge><button className="icon-button" aria-label="Refresh data" title="Refresh data" onClick={() => void refresh()} disabled={loading || demoMode}><RefreshCw size={17} className={loading ? 'spin' : ''} /></button></div></header><main id="main-content" className="content" tabIndex={-1}>{loading && !data.status && !demoMode && <div className="note" role="status">Loading read-only backend data…</div>}{data.errors.length > 0 && page !== 'diagnostics' && !demoMode && <div className="error-banner"><AlertCircle size={17} /><span>Some backend data is unavailable. <button onClick={() => setPage('diagnostics')}>View details</button></span></div>}{page === 'dashboard' && <Dashboard data={data} navigate={setPage} traffic={traffic} />}{page === 'networks' && <Networks data={data} traffic={traffic} />}{page === 'applications' && <Applications data={data} onReload={refreshPolicies} notify={notify} />}{page === 'routing' && <RoutingPlans data={data} />}{page === 'diagnostics' && <Diagnostics data={data} />}{page === 'settings' && <Settings data={data} theme={theme} setTheme={setTheme} />}</main><footer className="footer"><span><span className="footer-dot" /> {demoMode ? 'Demo data · no backend connection' : data.capabilities ? 'Read-only daemon connected' : 'Daemon connection unavailable'}</span><span>PLAN_ONLY · No host changes</span></footer></div>
    {toast && <div className={`toast ${toast.error ? 'toast-error' : ''}`} role="status"><span>{toast.message}</span><button onClick={() => setToast(null)} aria-label="Dismiss notification"><X size={16} /></button></div>}
  </div></>
}
