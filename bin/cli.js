#!/usr/bin/env node
'use strict';

/**
 * @fileoverview CLI for localssl — generate self-signed SSL certs.
 * @author idirdev
 */

const { generateCA, generateCert, writeCerts } = require('../src/index');

const args = process.argv.slice(2);

/**
 * Parse a named argument value from the argv array.
 * @param {string[]} argv - Array of CLI arguments.
 * @param {string}   flag - Flag name (e.g. "--domain").
 * @param {*}        def  - Default value.
 * @returns {string|*}
 */
function getArg(argv, flag, def) {
  const i = argv.indexOf(flag);
  return i !== -1 && argv[i + 1] !== undefined ? argv[i + 1] : def;
}

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log([
    '',
    'Usage: localssl generate [options]',
    '',
    'Options:',
    '  --domain <name>   Primary domain / CN (default: localhost)',
    '  --san <name>      Additional SAN (repeatable)',
    '  --days <n>        Validity in days (default: 365)',
    '  --outdir <path>   Output directory (default: ./certs)',
    '  --bits <n>        RSA key size (default: 2048)',
    '  --with-ca         Also generate a CA certificate',
    '',
    'Examples:',
    '  localssl generate --domain myapp.local --san "*.myapp.local" --days 730',
    '  localssl generate --domain localhost --with-ca --outdir /tmp/dev-certs',
    '',
  ].join('\n'));
  process.exit(0);
}

const domain = getArg(args, '--domain', 'localhost');
const days = parseInt(getArg(args, '--days', '365'), 10);
const outdir = getArg(args, '--outdir', './certs');
const bits = parseInt(getArg(args, '--bits', '2048'), 10);
const withCA = args.includes('--with-ca');

// Collect all --san values
const san = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--san' && args[i + 1]) {
    san.push(args[i + 1]);
    i++;
  }
}

try {
  let ca = null;
  if (withCA) {
    ca = generateCA({ commonName: domain + ' Dev CA', days: days * 10, bits });
    const caPaths = writeCerts({ key: ca.key, cert: ca.cert, meta: { ...ca.meta, domain: domain + '-ca' } }, outdir);
    console.log('CA certificate:');
    console.log('  cert: ' + caPaths.certPath);
    console.log('  key:  ' + caPaths.keyPath);
  }

  const bundle = generateCert({ domain, san, days, bits, ca });
  const paths = writeCerts(bundle, outdir);

  console.log('\nServer certificate for ' + domain + ':');
  console.log('  cert: ' + paths.certPath);
  console.log('  key:  ' + paths.keyPath);
  console.log('  valid: ' + days + ' days');
  if (san.length > 0) {
    console.log('  SAN:  ' + san.join(', '));
  }
} catch (err) {
  console.error('Error: ' + err.message);
  process.exit(1);
}
