import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/rest.ts', 'src/testing.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
  removeNodeProtocol: false,
  external: [/^@ghuri\//, /^node:/, 'hono'],
})
