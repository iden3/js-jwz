import commonJS from '@rollup/plugin-commonjs';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';
import tsConfig from '../tsconfig.json' assert { type: 'json' };
import packageJson from '../package.json' assert { type: 'json' };
import terser from '@rollup/plugin-terser';
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
      compilerOptions: {
        ...tsConfig.compilerOptions
      }
    }),
    commonJS(),
    nodeResolve({
      browser: true
    }),
    terser()
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
      typescript({
        compilerOptions: {
          ...tsConfig.compilerOptions
        }
      }),
      nodeResolve({
        browser: true
      }),
      commonJS(),
      terser()
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
