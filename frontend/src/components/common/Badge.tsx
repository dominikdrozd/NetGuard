import type { Protocol, Verdict } from '../../types';
import { protocolStr } from '../../utils/format';

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return <span className={`badge ${verdict}`}>{verdict}</span>;
}

export function ProtocolBadge({ protocol }: { protocol: Protocol }) {
  const s = protocolStr(protocol);
  return <span className={`badge ${s}`}>{s}</span>;
}
