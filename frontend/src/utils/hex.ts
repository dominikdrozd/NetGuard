export function hexToAsciiLines(hexStr: string): string {
  if (!hexStr) return '';
  const bytes = hexStr.split(' ');
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(4, '0');
    const hex = chunk.join(' ').padEnd(47, ' ');
    const ascii = chunk.map(b => {
      const n = parseInt(b, 16);
      return (n >= 32 && n <= 126) ? String.fromCharCode(n) : '.';
    }).join('');
    lines.push(`${offset}  ${hex}  |${ascii}|`);
  }
  return lines.join('\n');
}
