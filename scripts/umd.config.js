const esbuild = require('esbuild');
const baseConfig = require('./base.config');
const pkg = require('../package.json');

const name = 'JWZ';

esbuild.build({
    ...baseConfig,
    minify: true,
    format: 'iife',
    outfile: pkg.main.replace('cjs', 'umd'),
    globalName: name
}).catch((err) => {
    console.error(err);
    return process.exit(1);
});
