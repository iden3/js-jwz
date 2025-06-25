import { build } from 'esbuild';
import { exit } from 'process';

import pkg from '../package.json' with { type: 'json' };


const external = [
  ...Object.keys(pkg.dependencies || {}),
  ...Object.keys(pkg.peerDependencies || {}),
];

const baseConfig = {
  entryPoints: ['src/index.ts'],
  bundle: true,
  minify: false,
  sourcemap: true,
  platform: 'node',
  target: 'es2022',
  outfile: 'dist/node/esm/index.js',
  format: 'esm',
  external
};

build({
  ...baseConfig
}).catch(() => exit(1));

build({
  ...baseConfig,
  format: 'cjs',
  outfile: 'dist/node/cjs/index.cjs',
}).catch(() => exit(1));
