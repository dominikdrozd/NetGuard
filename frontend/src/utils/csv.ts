export function csvEsc(val: unknown): string {
  const s = String(val == null ? '' : val);
  if (/^[=+\-@\t\r]/.test(s)) return "'" + s;
  if (/[,"\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

export function downloadCsv(filename: string, header: string, rows: string[]) {
  const content = header + '\n' + rows.join('\n');
  const blob = new Blob([content], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
