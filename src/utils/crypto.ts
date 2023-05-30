import { BmpString, Integer } from 'asn1js';
import { webcrypto } from 'crypto';
import { readFile } from 'fs/promises';
import {
    AttributeTypeAndValue,
    AuthenticatedSafe,
    CertBag,
    Certificate,
    CryptoEngine,
    PFX,
    PKCS8ShroudedKeyBag,
    PrivateKeyInfo,
    SafeBag,
    SafeContents,
    setEngine,
} from 'pkijs';

const crypto = new CryptoEngine({ name: 'node-webcrypto', crypto: webcrypto as Crypto });
setEngine('node-webcrypto', crypto); // We need to do this, because there is a bug in pkijs (https://github.com/PeculiarVentures/PKI.js/issues/379)

export const generateCertificate = async (commonName: string, days?: number) => {
    const algorithm = crypto.getAlgorithmParameters('RSA-PSS', 'generateKey');
    const { privateKey, publicKey } = await crypto.generateKey(
        algorithm.algorithm as EcKeyAlgorithm,
        true,
        algorithm.usages
    );

    const cert = new Certificate();
    cert.version = 2;
    cert.serialNumber = new Integer({ value: Date.now() });
    cert.notBefore.value = new Date();
    cert.notAfter.value = new Date();
    cert.notAfter.value.setDate(cert.notBefore.value.getDate() + (days || 365));

    cert.issuer.typesAndValues.push(
        new AttributeTypeAndValue({
            type: '2.5.4.3', // Common name
            value: new BmpString({ value: commonName }),
        })
    );
    cert.subject.typesAndValues.push(
        new AttributeTypeAndValue({
            type: '2.5.4.3', // Common name
            value: new BmpString({ value: commonName }),
        })
    );

    await cert.subjectPublicKeyInfo.importKey(publicKey, crypto);
    await cert.sign(privateKey, 'SHA-256', crypto);

    return {
        certificate: cert.toSchema().toBER(false),
        privateKey: await crypto.exportKey('pkcs8', privateKey),
    };
};

export const certificateFingerprint = async (certificateBuffer: ArrayBuffer, hashAlgorithm?: 'SHA-256' | 'SHA-1') => {
    const certificate = await Certificate.fromBER(certificateBuffer);
    const hash = await crypto.digest(
        hashAlgorithm || 'SHA-256',
        certificate.subjectPublicKeyInfo.toSchema().toBER(false)
    );
    return Buffer.from(hash).toString('hex');
};

export const certificateHasExpired = async (certificateBuffer: ArrayBuffer) => {
    const certificate = await Certificate.fromBER(certificateBuffer);
    return certificate.notAfter.value < new Date();
};

export const createPkcs12Container = async (cert: ArrayBuffer, key: ArrayBuffer, password?: string) => {
    const encodedPassword = new TextEncoder().encode(password || '').buffer;

    const pkcs12 = new PFX({
        parsedValue: {
            integrityMode: 0, // Password-Based Integrity Mode
            authenticatedSafe: new AuthenticatedSafe({
                parsedValue: {
                    safeContents: [
                        {
                            privacyMode: 0, // 0 - No privacy mode
                            value: new SafeContents({
                                safeBags: [
                                    new SafeBag({
                                        bagId: '1.2.840.113549.1.12.10.1.2', // Shrouded Private Key Bag
                                        bagValue: new PKCS8ShroudedKeyBag({
                                            parsedValue: PrivateKeyInfo.fromBER(key),
                                        }),
                                    }),
                                ],
                            }),
                        },
                        {
                            privacyMode: 1, // 1 - Password based privacy mode,
                            value: new SafeContents({
                                safeBags: [
                                    new SafeBag({
                                        bagId: '1.2.840.113549.1.12.10.1.3', // Certificate bag
                                        bagValue: new CertBag({
                                            parsedValue: Certificate.fromBER(cert),
                                        }),
                                    }),
                                ],
                            }),
                        },
                    ],
                },
            }),
        },
    });

    if (!pkcs12.parsedValue?.authenticatedSafe)
        throw new Error('Broken certificate container: pkcs12.parsedValue.authenticatedSafe is empty');

    await pkcs12.parsedValue.authenticatedSafe.parsedValue.safeContents[0].value.safeBags[0].bagValue.makeInternalValues(
        {
            password: encodedPassword,
            contentEncryptionAlgorithm: {
                name: 'AES-CBC', // OpenSSL can only handle AES-CBC (https://github.com/PeculiarVentures/PKI.js/blob/469c403d102ee5149e8eb9ad19754c9696ed7c55/test/pkcs12SimpleExample.ts#L438)
                length: 128,
            },
            hmacHashAlgorithm: 'SHA-1', // OpenSSL can only handle SHA-1 (https://github.com/PeculiarVentures/PKI.js/blob/469c403d102ee5149e8eb9ad19754c9696ed7c55/test/pkcs12SimpleExample.ts#L441)
            iterationCount: 100000,
        },
        crypto
    );

    pkcs12.parsedValue.authenticatedSafe.makeInternalValues(
        {
            safeContents: [
                {
                    // Private key contents are encrypted differently, so this needs to be empty.
                },
                {
                    password: encodedPassword,
                    contentEncryptionAlgorithm: {
                        name: 'AES-CBC',
                        length: 128,
                    },
                    hmacHashAlgorithm: 'SHA-1',
                    iterationCount: 100000,
                },
            ],
        },
        crypto
    );

    await pkcs12.makeInternalValues(
        {
            password: encodedPassword,
            iterations: 100000,
            pbkdf2HashAlgorithm: 'SHA-256',
            hmacHashAlgorithm: 'SHA-256',
        },
        crypto
    );
    return pkcs12.toSchema().toBER();
};

export const arrayBufferToPem = (buffer: ArrayBuffer, tag: 'CERTIFICATE' | 'PRIVATE KEY' | 'PUBLIC KEY') => {
    const base64 = Buffer.from(buffer).toString('base64');
    return `-----BEGIN ${tag}-----\n${base64.replace(/(.{64})/g, '$1\n').trim()}\n-----END ${tag}-----`; // Thanks Copilot!
};

export const parsePemCertificateFromFile = async (path: string) => {
    const certPem = await readFile(path, 'utf8');

    // A PEM certificate is just a base64-encoded DER certificate with a header and footer.
    const certBase64 = certPem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\r\n])/g, '');
    const certDer = Buffer.from(certBase64, 'base64');

    return { cert: Certificate.fromBER(certDer), certPem, certDer };
};

export const pemToArrayBuffer = (pem: string) => {
    const base64 = pem
        .replace(/-----BEGIN (.*)-----/, '')
        .replace(/-----END (.*)-----/, '')
        .replace(/\n/g, '');
    return Uint8Array.from(Buffer.from(base64, 'base64')).buffer;
};
