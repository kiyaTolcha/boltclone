import tls from 'node:tls';

const WEAK_CIPHER_PATTERNS = /rc4|des|null|export|md5/i;
const WEAK_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3']);

function connectTls(hostname, port, timeout) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout }, () => {
      resolve({
        cert: socket.getPeerCertificate(),
        protocol: socket.getProtocol(),
        cipher: socket.getCipher(),
        authorized: socket.authorized,
        authorizationError: socket.authorizationError
      });
      socket.end();
    });
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
  });
}

export async function runTlsChecks(hostname, timeout) {
  const findings = [];
  const info = await connectTls(hostname, 443, timeout);

  if (!info) {
    findings.push({ category: 'tls', title: 'TLS connection failed', severity: 'low', url: `https://${hostname}`, evidence: 'Could not establish a TLS connection on port 443 (site may be HTTP-only or unreachable).' });
    return findings;
  }

  if (!info.authorized) {
    findings.push({ category: 'tls', title: 'Invalid or untrusted certificate chain', severity: 'high', url: `https://${hostname}`, evidence: info.authorizationError || 'Certificate did not verify against trusted roots.' });
  }

  if (info.cert && info.cert.valid_to) {
    const expiry = new Date(info.cert.valid_to);
    const daysLeft = Math.round((expiry.getTime() - Date.now()) / 86400000);
    if (daysLeft < 0) {
      findings.push({ category: 'tls', title: 'Certificate expired', severity: 'high', url: `https://${hostname}`, evidence: `Expired ${-daysLeft} day(s) ago (${info.cert.valid_to})` });
    } else if (daysLeft < 30) {
      findings.push({ category: 'tls', title: 'Certificate expiring soon', severity: 'medium', url: `https://${hostname}`, evidence: `Expires in ${daysLeft} day(s) (${info.cert.valid_to})` });
    }
  }

  if (info.protocol && WEAK_PROTOCOLS.has(info.protocol)) {
    findings.push({ category: 'tls', title: 'Weak TLS protocol version', severity: 'high', url: `https://${hostname}`, evidence: `Negotiated protocol: ${info.protocol}` });
  }

  if (info.cipher?.name && WEAK_CIPHER_PATTERNS.test(info.cipher.name)) {
    findings.push({ category: 'tls', title: 'Weak cipher suite', severity: 'medium', url: `https://${hostname}`, evidence: `Negotiated cipher: ${info.cipher.name}` });
  }

  return findings;
}
