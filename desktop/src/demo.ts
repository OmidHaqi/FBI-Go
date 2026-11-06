import type { LiveData } from './bridge'

export const demoData: LiveData = {
  info: { socket: '/run/user/1000/fbi-go/control.sock', cli: '/usr/local/bin/fbi', host_apply: 'UNSUPPORTED' },
  capabilities: { mode: 'PLAN_ONLY', read_only: ['daemon.ping', 'daemon.version', 'daemon.capabilities', 'daemon.status', 'daemon.diagnostics', 'daemon.plan'], host_apply: 'UNSUPPORTED', isolated_test: 'UNSUPPORTED' },
  status: { state: 'PLANNED', mode: 'PLAN_ONLY', applied: false, snapshot: {
    devices: [
      { id: 'mac:aa:bb:cc:dd:ee:01', name: 'wlan-demo', kind: 'wifi', state: 'up', admin_up: true, oper_state: 'up', carrier: true, addresses: ['192.0.2.9/24', '2001:db8::9/64'], gateways: ['192.0.2.1'], rx_bytes: 1425804096, tx_bytes: 324809322, candidate: true, reasons: [] },
      { id: 'mac:aa:bb:cc:dd:ee:02', name: 'eth-demo', kind: 'ethernet_or_other', state: 'down', admin_up: true, oper_state: 'down', carrier: false, addresses: ['198.51.100.9/24'], gateways: ['198.51.100.1'], rx_bytes: 89541252, tx_bytes: 10248831, candidate: false, reasons: ['link has no carrier or is not operational'] },
      { id: 'tun-demo', name: 'tun-demo', kind: 'vpn', state: 'up', admin_up: true, oper_state: 'up', carrier: true, addresses: ['10.8.0.2/24'], rx_bytes: 4280496, tx_bytes: 1302848, candidate: false, reasons: ['excluded device type: vpn'] },
    ],
    routes: [{ family: 'ipv4', destination: '0.0.0.0/0', gateway: '192.0.2.1', interface: 'wlan-demo', table: 254, metric: 100 }],
  } },
  diagnostics: { read_only: true, findings: [
    { code: 'vpn_tun', status: 'BLOCKED', detail: 'tun-demo: explicit VPN compatibility policy required' },
    { code: 'wan_candidates', status: 'BLOCKED', detail: '1 operational physical WAN candidate; dual-WAN activation requires two independent uplinks' },
    { code: 'networkmanager', status: 'INFO', detail: 'NetworkManager active; no configuration changes planned' },
    { code: 'ipv6_default', status: 'WARNING', detail: 'IPv6 behavior needs a separate policy' },
  ] },
  plan: { state: 'PLANNED', mode: 'PLAN_ONLY', applied: false,
    requested_policy: { id: 'desktop-preview', mode: 'AUTO', enabled: true },
    proposed_resources: { safe_to_apply: false, reasons: ['Only one WAN candidate available'] },
    conflicts: ['Only one WAN candidate available'],
    warnings: ['No host resources are reserved by this preview'],
    required_operations: [],
  },
  apps: [
    { id: 'org.example.Browser.desktop', name: 'Browser', generic_name: 'Web browser', icon: 'firefox', source: '/usr/share/applications', launch_supported: true, no_display: false, hidden: false },
    { id: 'org.example.Editor.desktop', name: 'Code Editor', generic_name: 'Development', icon: 'code', source: '/usr/share/applications', launch_supported: true, no_display: false, hidden: false },
    { id: 'org.example.Chat.desktop', name: 'Chat', generic_name: 'Messaging', icon: 'chat', source: '/usr/share/applications', launch_supported: false, limitations: ['D-Bus activation is not supported'], no_display: false, hidden: false },
  ],
  policies: [{ policy: { id: 'org.example.Browser.desktop', mode: 'PINNED_WAN', preferred_wan: 'mac:aa:bb:cc:dd:ee:01', failure_behavior: 'STRICT', enabled: true }, status: 'RESOLVED', preferred_interface: 'wlan-demo' }],
  errors: [],
}
