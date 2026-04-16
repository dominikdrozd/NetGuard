import type { Connection, Protocol, Verdict } from '../../types';
import { protocolStr } from '../../utils/format';

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return <span className={`badge ${verdict}`}>{verdict}</span>;
}

export function ProtocolBadge({ protocol }: { protocol: Protocol }) {
  const s = protocolStr(protocol);
  return <span className={`badge ${s}`}>{s}</span>;
}

/**
 * HTTP context badge. Renders next to the protocol badge, showing method +
 * path (e.g. "GET /users") and the response content-type short label
 * (e.g. "html", "json", "js") when decrypted content is available.
 */
export function HttpBadge({ conn }: { conn: Connection }) {
  const method = conn.http_method;
  const path = conn.request_url ? pathFromUrl(conn.request_url) : null;
  const kind = classifyContentType(conn.decrypted_response_headers);
  const decrypted = Boolean(
    conn.decrypted_request_headers ||
    conn.decrypted_response_status ||
    conn.decrypted_response_headers ||
    conn.decrypted_response_body
  );

  if (!method && !path && !kind && !decrypted) return null;

  return (
    <span style={{ display: 'inline-flex', gap: 4, alignItems: 'center', flexWrap: 'nowrap' }}>
      {decrypted && (
        <span
          title="Decrypted by mitmproxy — full request + response visible in detail view"
          style={{
            fontSize: 10,
            padding: '1px 5px',
            borderRadius: 3,
            background: 'rgba(34,197,94,0.15)',
            color: 'var(--green, #22c55e)',
            fontWeight: 600,
            letterSpacing: 0.3,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 2,
          }}
        >
          <span aria-hidden="true">&#128275;</span>
          DEC
        </span>
      )}
      {method && (
        <span className={`badge method-${method.toLowerCase()}`} style={methodStyle(method)}>
          {method}
        </span>
      )}
      {path && (
        <span
          className="text-mono"
          style={{
            fontSize: 11,
            color: 'var(--text-muted)',
            maxWidth: 260,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
          title={path}
        >
          {path}
        </span>
      )}
      {kind && (
        <span className={`badge kind-${kind}`} style={contentKindStyle(kind)}>
          {kind}
        </span>
      )}
    </span>
  );
}

function pathFromUrl(url: string): string {
  // Strip scheme + host; keep path + query + fragment. If URL is just a host
  // (no path), return "/".
  const m = url.match(/^https?:\/\/[^/]+(\/.*)?$/);
  if (m) return m[1] || '/';
  // Fallback for non-absolute URLs or weird inputs
  return url;
}

const KIND_PATTERNS: Array<[RegExp, string]> = [
  [/\btext\/html\b/i, 'html'],
  [/\bapplication\/(x-)?javascript\b/i, 'js'],
  [/\btext\/javascript\b/i, 'js'],
  [/\btext\/css\b/i, 'css'],
  [/\bapplication\/json\b/i, 'json'],
  [/\bapplication\/xml\b/i, 'xml'],
  [/\btext\/xml\b/i, 'xml'],
  [/\btext\/plain\b/i, 'text'],
  [/\bimage\//i, 'img'],
  [/\bvideo\//i, 'video'],
  [/\baudio\//i, 'audio'],
  [/\bfont\//i, 'font'],
  [/\bapplication\/octet-stream\b/i, 'bin'],
  [/\bapplication\/pdf\b/i, 'pdf'],
  [/\bapplication\/zip\b/i, 'zip'],
];

function classifyContentType(headers: string | undefined): string | null {
  if (!headers) return null;
  // Headers are the mitmproxy-style "Name: value" joined with newlines.
  const m = headers.match(/^content-type:\s*(.+)$/im);
  if (!m) return null;
  const ct = m[1];
  for (const [re, label] of KIND_PATTERNS) {
    if (re.test(ct)) return label;
  }
  // Unknown — strip params, return subtype (e.g. "application/x-foo" -> "foo")
  const bare = ct.split(';')[0].trim().toLowerCase();
  const slashIdx = bare.indexOf('/');
  return slashIdx >= 0 ? bare.slice(slashIdx + 1).replace(/^x-/, '') : bare;
}

// Color the HTTP method by semantic group so the row scans quickly.
function methodStyle(method: string): React.CSSProperties {
  const m = method.toUpperCase();
  const colors: Record<string, [string, string]> = {
    GET:    ['rgba(59,130,246,0.15)',  'var(--blue, #3b82f6)'],
    POST:   ['rgba(34,197,94,0.15)',   'var(--green, #22c55e)'],
    PUT:    ['rgba(234,179,8,0.15)',   '#eab308'],
    PATCH:  ['rgba(234,179,8,0.15)',   '#eab308'],
    DELETE: ['rgba(239,68,68,0.15)',   'var(--red, #ef4444)'],
    HEAD:   ['rgba(156,163,175,0.15)', 'var(--text-muted, #9ca3af)'],
    OPTIONS:['rgba(156,163,175,0.15)', 'var(--text-muted, #9ca3af)'],
  };
  const [bg, fg] = colors[m] || ['rgba(156,163,175,0.15)', 'var(--text-muted, #9ca3af)'];
  return {
    fontSize: 10,
    padding: '1px 6px',
    borderRadius: 3,
    background: bg,
    color: fg,
    fontWeight: 600,
    letterSpacing: 0.3,
  };
}

function contentKindStyle(kind: string): React.CSSProperties {
  return {
    fontSize: 10,
    padding: '1px 6px',
    borderRadius: 3,
    background: 'var(--bg-elev)',
    color: 'var(--text-muted)',
    fontWeight: 500,
    textTransform: 'lowercase',
  };
}
