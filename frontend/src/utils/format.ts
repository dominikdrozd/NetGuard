import type { Protocol } from '../types';

export function timeAgo(ts: string): string {
  const sec = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (sec < 5) return 'just now';
  if (sec < 60) return sec + 's ago';
  if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
  return Math.floor(sec / 3600) + 'h ago';
}

export function formatTime(ts: string): string {
  return new Date(ts).toLocaleTimeString();
}

export function formatDateTime(ts: string): string {
  return new Date(ts).toLocaleString();
}

export function formatSize(bytes: number | undefined): string {
  if (!bytes) return '-';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

export function basename(path: string): string {
  return path.split('/').pop() || path;
}

export function appName(process: { exe_path: string } | null): string {
  if (process) return basename(process.exe_path) || process.exe_path;
  return 'unknown';
}

export function protocolStr(p: Protocol): string {
  if (typeof p === 'string') return p;
  return 'other';
}
