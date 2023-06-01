import { readFile } from 'fs/promises';
import forge from 'node-forge';
const { pki, md } = forge;

export const generateCertificate = async (commonName: string, days?: number) => {
    const keyPair = await new Promise<forge.pki.rsa.KeyPair>((res, rej) => {
        pki.rsa.generateKeyPair({ bits: 2048 }, (err, keyPair) => (err ? rej(err) : res(keyPair)));
    });
    const cert = pki.createCertificate();

    cert.publicKey = keyPair.publicKey;
    cert.version = 2;
    cert.serialNumber = Date.now().toString(10);
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + (days || 365));

    const attributes = [
        {
            name: 'commonName',
            value: commonName,
        },
    ];
    cert.setSubject(attributes);
    cert.setIssuer(attributes);

    cert.sign(keyPair.privateKey, md.sha256.create());

    return {
        certificate: pki.certificateToPem(cert),
        privateKey: pki.privateKeyToPem(keyPair.privateKey),
    };
};

export const certificateFingerprint = (certificatePem: string, hashAlgorithm?: 'SHA-256' | 'SHA-1') => {
    const cert = pki.certificateFromPem(certificatePem);
    return pki.getPublicKeyFingerprint(cert.publicKey, {
        type: 'SubjectPublicKeyInfo',
        md: hashAlgorithm === 'SHA-1' ? md.sha1.create() : md.sha256.create(),
        encoding: 'hex',
    });
};

export const certificateHasExpired = (certificatePem: string) => {
    const cert = pki.certificateFromPem(certificatePem);
    return cert.validity.notAfter < new Date();
};

export const createPkcs12Container = (
    certPem: string,
    keyPem: string,
    password?: string,
    algorithm?: 'aes256' | '3des'
) => {
    const p12 = forge.pkcs12.toPkcs12Asn1(
        pki.privateKeyFromPem(keyPem),
        pki.certificateFromPem(certPem),
        password || '',
        { algorithm: algorithm || '3des' } // Apparently any sane algorithm is not supported by the typical ingestors (like go), so we default to 3des
    );

    return forge.asn1.toDer(p12);
};

export const arrayBufferToPem = (buffer: ArrayBuffer, tag: 'CERTIFICATE' | 'PRIVATE KEY' | 'PUBLIC KEY') => {
    const base64 = Buffer.from(buffer).toString('base64');
    return `-----BEGIN ${tag}-----\n${base64.replace(/(.{64})/g, '$1\n').trim()}\n-----END ${tag}-----`; // Thanks Copilot!
};

export const pemToArrayBuffer = (pem: string) => {
    const base64 = pem
        .replace(/-----BEGIN (.*)-----/, '')
        .replace(/-----END (.*)-----/, '')
        .replace(/\n/g, '');
    return Uint8Array.from(Buffer.from(base64, 'base64')).buffer;
};

export const parsePemCertificateFromFile = async (path: string) => {
    const certPem = await readFile(path, 'utf8');
    const cert = pki.certificateFromPem(certPem);

    return { cert, certPem, certDer: Buffer.from(pemToArrayBuffer(certPem)) };
};

export const certSubjectToAsn1 = (cert: forge.pki.Certificate) => forge.pki.distinguishedNameToAsn1(cert.subject);

export const asn1ValueToDer = (asn1: forge.asn1.Asn1) =>
    typeof asn1.value === 'string'
        ? forge.util.createBuffer(asn1.value)
        : asn1.value.reduce((acc, cur) => {
              acc.putBuffer(forge.asn1.toDer(cur));
              return acc;
          }, forge.util.createBuffer());
