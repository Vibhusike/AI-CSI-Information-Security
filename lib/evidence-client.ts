export type EvidenceType =
  | 'authentication'
  | 'endpoint_auth'
  | 'email_headers'
  | 'dns'
  | 'browser_history'
  | 'sysmon'
  | 'firewall'
  | 'ids'
  | 'network_flow'
  | 'endpoint'
  | 'memory'
  | 'pcap'
  | 'proxy'
  | 'edr'
  | 'registry'
  | 'unknown';

export async function sha256Text(text: string) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}
