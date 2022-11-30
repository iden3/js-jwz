const esbuild = require('esbuild');
const baseConfig = require('./base.config');
const pkg = require('../package.json');

const name = 'Iden3JWZ';

esbuild.build({
    ...baseConfig,
    minify: true,
    format: 'iife',
    outfile: pkg.main.replace('cjs', 'umd'),
    globalName: name
}).catch(() => {
    return process.exit(1);
});
