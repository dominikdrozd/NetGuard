import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: path.resolve(__dirname, '../crates/netguard-web/static'),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:3031',
      '/auth': 'http://127.0.0.1:3031',
      '/ws-ticket': 'http://127.0.0.1:3031',
      '/ws': {
        target: 'ws://127.0.0.1:3031',
        ws: true,
      },
    },
  },
});
