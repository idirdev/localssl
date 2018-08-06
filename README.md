# localssl

> **[EN]** Generate self-signed SSL certificates for local development.
> **[FR]** Generer des certificats SSL auto-signes pour le developpement local.

---

## Features / Fonctionnalites

**[EN]**
- Generate self-signed CA + server certificates
- Custom domain names and SANs (Subject Alternative Names)
- Configurable validity period
- PEM and PKCS12 output formats
- Auto-trust on macOS and Windows (optional)
- Wildcard certificate support

**[FR]**
- Generer un CA auto-signe + certificats serveur
- Noms de domaine et SANs personnalises
- Duree de validite configurable
- Formats de sortie PEM et PKCS12
- Auto-confiance sur macOS et Windows (optionnel)
- Support des certificats wildcard

---

## Installation

```bash
npm install -g @idirdev/localssl
```

---

## CLI Usage / Utilisation CLI

```bash
# Generate cert for localhost
localssl generate

# Custom domain
localssl generate --domain myapp.local --san "*.myapp.local"

# Custom output directory
localssl generate --outdir ./certs --days 365

# Help
localssl --help
```

### Example Output / Exemple de sortie

```
$ localssl generate --domain myapp.local
[localssl] Generating CA certificate...
[localssl] Generating server certificate for myapp.local...
[localssl] Files created:
  ca.pem        (CA certificate)
  server.pem    (Server certificate)
  server-key.pem (Server private key)
[localssl] Valid for 30 days
[localssl] Add ca.pem to your trust store to avoid browser warnings
```

---

## API (Programmatic) / API (Programmation)

```js
const { generateCA, generateCert } = require('localssl');

// Generate CA
const ca = generateCA({ days: 365 });

// Generate server cert signed by CA
const cert = generateCert({
  domain: 'myapp.local',
  san: ['*.myapp.local', 'localhost'],
  days: 90,
  ca
});

console.log(cert.cert);    // PEM certificate
console.log(cert.key);     // PEM private key
```

---

## License

MIT - idirdev
