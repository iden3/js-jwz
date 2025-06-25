import commonJS from '@rollup/plugin-commonjs';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';
import json from '@rollup/plugin-json';
import tsConfig from '../tsconfig.json' with { type: 'json' };
import packageJson from '../package.json' with { type: 'json' };


const compilerOptions = {
  ...tsConfig.compilerOptions,
  outDir: undefined,
  declarationDir: undefined,
  declaration: undefined,
  sourceMap: undefined,
  declarationMap: undefined,
};

const external = [
  ...Object.keys(packageJson.peerDependencies).filter((key) => key.startsWith('@iden3/')),
  'snarkjs',
  'ffjavascript'
];
const config = {
  input: 'src/index.ts',
  external,
  output: [
    {
      format: 'es',
      file: 'dist/browser/esm/index.js',
      sourcemap: true
    }
  ],
  plugins: [
    typescript({
      compilerOptions
    }),
    commonJS(),
    nodeResolve({
      browser: true
    }),
  ],
  treeshake: {
    preset: 'smallest'
  }
};

export default [
  config,
  {
    ...config,
    plugins: [
      json(),
      typescript({
        compilerOptions
      }),
      nodeResolve({
        browser: true
      }),
      commonJS(),
    ],
    external: [],
    output: [
      {
        format: 'iife',
        file: 'dist/browser/umd/index.js',
        name: 'JWZ',
        sourcemap: true
      }
    ]
  }
];
