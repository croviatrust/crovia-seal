import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json' with { type: 'json' };

export default defineConfig({
  plugins: [crx({ manifest })],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    target: 'es2022',
    rollupOptions: {
      input: {
        verify: 'src/verify/verify.html',
      },
      output: {
        // keep filenames predictable (helpful when debugging extensions)
        chunkFileNames: 'assets/[name]-[hash].js',
      },
    },
  },
});
