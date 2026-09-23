import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8081',
      '/admin': 'http://127.0.0.1:8081',
    },
  },
  build: {
    rollupOptions: {
      output: {
        // vendor 分包：框架与 UI 库独立成块，业务迭代发版后浏览器缓存仍命中
        // （rolldown-vite 的 manualChunks 只支持函数形式）
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return 'vendor-react';
          if (/[\\/]node_modules[\\/]@mantine[\\/]/.test(id)) return 'vendor-mantine';
          return undefined;
        },
      },
    },
  },
})
