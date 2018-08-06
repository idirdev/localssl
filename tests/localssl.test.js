'use strict';

/**
 * @fileoverview Tests for localssl.
 * @author idirdev
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  generateKeyPair,
  generateCA,
  generateCert,
  writeCerts,
  getCertInfo,
  verifyCert,
} = require('../src/index');

// ── generateKeyPair ─────────────────────────────────────────────────────────

describe('generateKeyPair', () => {
  it('returns public and private keys in PEM format', () => {
    const kp = generateKeyPair();
    assert.ok(kp.publicKey.includes('-----BEGIN PUBLIC KEY-----'));
    assert.ok(kp.privateKey.includes('-----BEGIN PRIVATE KEY-----'));
  });

  it('uses 2048 bits by default', () => {
    const kp = generateKeyPair();
    // Key body must be non-trivial
    assert.ok(kp.publicKey.length > 200);
  });

  it('accepts custom bit size', () => {
    const kp = generateKeyPair(1024);
    assert.ok(kp.publicKey.includes('-----BEGIN PUBLIC KEY-----'));
  });
});

// ── generateCA ──────────────────────────────────────────────────────────────

describe('generateCA', () => {
  it('returns key, cert, and meta', () => {
    const ca = generateCA({ commonName: 'Test CA', days: 365 });
    assert.ok(ca.key);
    assert.ok(ca.cert);
    assert.ok(ca.meta);
  });

  it('meta has correct commonName', () => {
    const ca = generateCA({ commonName: 'My CA' });
    assert.equal(ca.meta.commonName, 'My CA');
  });

  it('meta marks isCA as true', () => {
    const ca = generateCA();
    assert.equal(ca.meta.isCA, true);
  });

  it('cert is PEM encoded', () => {
    const ca = generateCA();
    assert.ok(ca.cert.includes('-----BEGIN CERTIFICATE-----'));
    assert.ok(ca.cert.includes('-----END CERTIFICATE-----'));
  });

  it('fingerprint is colon-separated hex string', () => {
    const ca = generateCA();
    assert.match(ca.meta.fingerprint, /^[0-9A-F]{2}(:[0-9A-F]{2})+$/);
  });
});

// ── generateCert ────────────────────────────────────────────────────────────

describe('generateCert', () => {
  it('returns key, cert, and meta for a domain', () => {
    const bundle = generateCert({ domain: 'test.local', days: 30 });
    assert.ok(bundle.key.includes('-----BEGIN PRIVATE KEY-----'));
    assert.ok(bundle.cert.includes('-----BEGIN CERTIFICATE-----'));
    assert.equal(bundle.meta.domain, 'test.local');
  });

  it('defaults domain to localhost', () => {
    const bundle = generateCert();
    assert.equal(bundle.meta.domain, 'localhost');
  });

  it('includes SAN entries in meta', () => {
    const bundle = generateCert({ domain: 'app.local', san: ['*.app.local', '127.0.0.1'] });
    assert.ok(bundle.meta.san.includes('*.app.local'));
    assert.ok(bundle.meta.san.includes('127.0.0.1'));
  });

  it('marks signedByCA when ca is provided', () => {
    const ca = generateCA({ commonName: 'Test CA' });
    const bundle = generateCert({ domain: 'signed.local', ca });
    assert.equal(bundle.meta.signedByCA, true);
  });

  it('marks signedByCA false when no ca provided', () => {
    const bundle = generateCert({ domain: 'self.local' });
    assert.equal(bundle.meta.signedByCA, false);
  });
});

// ── writeCerts ──────────────────────────────────────────────────────────────

describe('writeCerts', () => {
  it('writes key, cert, and meta files', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'localssl-'));
    const bundle = generateCert({ domain: 'write.local' });
    const result = writeCerts(bundle, tmp);

    assert.ok(fs.existsSync(result.keyPath));
    assert.ok(fs.existsSync(result.certPath));
    assert.ok(fs.existsSync(result.metaPath));

    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('key file contains private key', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'localssl-'));
    const bundle = generateCert({ domain: 'content.local' });
    const result = writeCerts(bundle, tmp);
    const keyContent = fs.readFileSync(result.keyPath, 'utf8');
    assert.ok(keyContent.includes('-----BEGIN PRIVATE KEY-----'));
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('meta file is valid JSON', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'localssl-'));
    const bundle = generateCert({ domain: 'json.local' });
    const result = writeCerts(bundle, tmp);
    const meta = JSON.parse(fs.readFileSync(result.metaPath, 'utf8'));
    assert.equal(meta.domain, 'json.local');
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('throws on invalid bundle', () => {
    assert.throws(() => writeCerts({}, os.tmpdir()), /Invalid certificate bundle/);
  });
});

// ── getCertInfo ─────────────────────────────────────────────────────────────

describe('getCertInfo', () => {
  it('returns parsed info from a generated cert', () => {
    const bundle = generateCert({ domain: 'info.local' });
    const info = getCertInfo(bundle.cert);
    assert.ok(info);
    assert.ok(info.subject.includes('info.local'));
  });

  it('returns null for non-string input', () => {
    assert.equal(getCertInfo(null), null);
    assert.equal(getCertInfo(42), null);
  });
});

// ── verifyCert ──────────────────────────────────────────────────────────────

describe('verifyCert', () => {
  it('returns valid for cert issued by matching CA', () => {
    const ca = generateCA({ commonName: 'Dev CA' });
    const bundle = generateCert({ domain: 'verify.local', ca });
    const result = verifyCert(bundle.cert, ca.cert);
    assert.equal(result.valid, true);
  });

  it('returns invalid for cert issued by different CA', () => {
    const ca1 = generateCA({ commonName: 'CA One' });
    const ca2 = generateCA({ commonName: 'CA Two' });
    const bundle = generateCert({ domain: 'verify.local', ca: ca1 });
    const result = verifyCert(bundle.cert, ca2.cert);
    assert.equal(result.valid, false);
  });

  it('returns invalid for unparseable cert', () => {
    const result = verifyCert('not-pem', '');
    assert.equal(result.valid, false);
  });
});
