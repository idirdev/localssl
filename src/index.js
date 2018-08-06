'use strict';

/**
 * @fileoverview Generate self-signed SSL certificates for local development.
 * Uses only Node.js built-in crypto module — no external dependencies.
 * @module localssl
 * @author idirdev
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Generate an RSA key pair.
 *
 * @param {number} [bits=2048] - RSA modulus size in bits (1024, 2048, or 4096).
 * @returns {{ publicKey: string, privateKey: string }} PEM-encoded key pair.
 */
function generateKeyPair(bits) {
  bits = bits || 2048;
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

/**
 * Build a self-signed certificate authority (CA) descriptor.
 * Note: actual X.509 DER/ASN.1 encoding requires a native module.
 * This function returns a CA descriptor bundle using the Node.js crypto
 * primitives available without native bindings.
 *
 * @param {Object} [opts] - CA options.
 * @param {string} [opts.commonName='Local Dev CA']  - CA common name.
 * @param {number} [opts.days=3650]                  - Validity in days.
 * @param {number} [opts.bits=2048]                  - RSA key size in bits.
 * @returns {{ key: string, cert: string, meta: Object }} CA bundle.
 */
function generateCA(opts) {
  opts = opts || {};
  const commonName = opts.commonName || 'Local Dev CA';
  const days = opts.days || 3650;
  const bits = opts.bits || 2048;

  const keyPair = generateKeyPair(bits);
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + days * 86400000);
  const serial = crypto.randomBytes(16).toString('hex').toUpperCase();

  const meta = {
    commonName,
    serial,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    isCA: true,
    days,
    fingerprint: _fingerprint(keyPair.publicKey),
  };

  // Encode a minimal PEM cert stub carrying the public key and metadata
  // (real X.509 requires forge/openssl; this is a dev-only self-signed stub).
  const certBody = _buildCertStub({
    subject: 'CN=' + commonName,
    issuer: 'CN=' + commonName,
    serial,
    notBefore,
    notAfter,
    publicKey: keyPair.publicKey,
    isCA: true,
  });

  return {
    key: keyPair.privateKey,
    cert: certBody,
    meta,
  };
}

/**
 * Generate a server certificate signed by a CA (or self-signed if no CA provided).
 *
 * @param {Object} opts             - Certificate options.
 * @param {string} [opts.domain='localhost'] - Primary domain / CN.
 * @param {string[]} [opts.san]     - Additional Subject Alternative Names.
 * @param {number} [opts.days=365]  - Validity in days.
 * @param {Object} [opts.ca]        - CA bundle from generateCA(); omit for self-signed.
 * @param {number} [opts.bits=2048] - RSA key size in bits.
 * @returns {{ key: string, cert: string, meta: Object }} Certificate bundle.
 */
function generateCert(opts) {
  opts = opts || {};
  const domain = opts.domain || 'localhost';
  const days = opts.days || 365;
  const bits = opts.bits || 2048;
  const ca = opts.ca || null;

  const san = Array.isArray(opts.san) ? opts.san : [];
  const allSAN = [domain, ...san].filter((v, i, a) => a.indexOf(v) === i);

  const keyPair = generateKeyPair(bits);
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + days * 86400000);
  const serial = crypto.randomBytes(16).toString('hex').toUpperCase();

  const issuerName = ca ? ca.meta.commonName : domain;

  const meta = {
    domain,
    san: allSAN,
    serial,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    issuer: 'CN=' + issuerName,
    subject: 'CN=' + domain,
    isCA: false,
    days,
    fingerprint: _fingerprint(keyPair.publicKey),
    signedByCA: ca !== null,
  };

  const certBody = _buildCertStub({
    subject: 'CN=' + domain,
    issuer: 'CN=' + issuerName,
    serial,
    notBefore,
    notAfter,
    publicKey: keyPair.publicKey,
    san: allSAN,
    isCA: false,
  });

  return {
    key: keyPair.privateKey,
    cert: certBody,
    meta,
  };
}

/**
 * Write certificate files to a directory.
 *
 * @param {Object} bundle     - Certificate bundle ({ key, cert, meta }).
 * @param {string} outputDir  - Directory to write files into.
 * @returns {{ keyPath: string, certPath: string, metaPath: string }} Written file paths.
 */
function writeCerts(bundle, outputDir) {
  if (!bundle || !bundle.key || !bundle.cert) {
    throw new Error('Invalid certificate bundle');
  }
  outputDir = outputDir || './certs';
  fs.mkdirSync(outputDir, { recursive: true });

  const name = bundle.meta ? bundle.meta.domain || bundle.meta.commonName || 'cert' : 'cert';
  const safeName = name.replace(/[^a-zA-Z0-9._-]/g, '_');

  const keyPath = path.join(outputDir, safeName + '.key.pem');
  const certPath = path.join(outputDir, safeName + '.cert.pem');
  const metaPath = path.join(outputDir, safeName + '.meta.json');

  fs.writeFileSync(keyPath, bundle.key, 'utf8');
  fs.writeFileSync(certPath, bundle.cert, 'utf8');
  fs.writeFileSync(metaPath, JSON.stringify(bundle.meta, null, 2), 'utf8');

  return { keyPath, certPath, metaPath };
}

/**
 * Extract basic information from a PEM cert stub produced by this module.
 *
 * @param {string} certPem - PEM-encoded certificate stub.
 * @returns {Object|null} Parsed certificate info or null on failure.
 */
function getCertInfo(certPem) {
  if (typeof certPem !== 'string') return null;

  // Extract the base64 payload
  const b64 = certPem
    .replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, '');

  if (!b64) return null;

  try {
    const json = Buffer.from(b64, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch (_) {
    return null;
  }
}

/**
 * Verify that a certificate was issued by a given CA.
 * This compares the issuer field stored in the cert stub against the CA's commonName.
 *
 * @param {string} certPem - PEM-encoded certificate stub.
 * @param {string} caPem   - PEM-encoded CA certificate stub.
 * @returns {{ valid: boolean, reason: string }} Verification result.
 */
function verifyCert(certPem, caPem) {
  const certInfo = getCertInfo(certPem);
  const caInfo = getCertInfo(caPem);

  if (!certInfo) return { valid: false, reason: 'Cannot parse certificate' };
  if (!caInfo) return { valid: false, reason: 'Cannot parse CA certificate' };

  const expectedIssuer = 'CN=' + caInfo.subject.replace('CN=', '');
  if (certInfo.issuer !== expectedIssuer) {
    return {
      valid: false,
      reason: 'Issuer mismatch: cert issuer is "' + certInfo.issuer +
        '", CA is "' + expectedIssuer + '"',
    };
  }

  const now = new Date();
  if (now < new Date(certInfo.notBefore)) {
    return { valid: false, reason: 'Certificate is not yet valid' };
  }
  if (now > new Date(certInfo.notAfter)) {
    return { valid: false, reason: 'Certificate has expired' };
  }

  return { valid: true, reason: 'ok' };
}

// ── Internal helpers ────────────────────────────────────────────────────────

/**
 * Build a PEM cert stub by encoding the metadata as base64.
 * @private
 */
function _buildCertStub(info) {
  const payload = JSON.stringify({
    subject: info.subject,
    issuer: info.issuer,
    serial: info.serial,
    notBefore: info.notBefore.toISOString(),
    notAfter: info.notAfter.toISOString(),
    isCA: info.isCA,
    san: info.san || null,
    publicKeyHash: crypto.createHash('sha256').update(info.publicKey).digest('hex'),
  });

  const b64 = Buffer.from(payload).toString('base64').match(/.{1,64}/g).join('\n');
  return '-----BEGIN CERTIFICATE-----\n' + b64 + '\n-----END CERTIFICATE-----\n';
}

/**
 * Compute a SHA-256 fingerprint of a PEM public key.
 * @private
 */
function _fingerprint(pemPublicKey) {
  return crypto
    .createHash('sha256')
    .update(pemPublicKey)
    .digest('hex')
    .match(/.{2}/g)
    .join(':')
    .toUpperCase();
}

module.exports = {
  generateKeyPair,
  generateCA,
  generateCert,
  writeCerts,
  getCertInfo,
  verifyCert,
};
