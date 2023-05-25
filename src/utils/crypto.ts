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
    PrivateKeyInfo,
    SafeBag,
    SafeContents,
} from 'pkijs';

const crypto = new CryptoEngine({ name: 'node-webcrypto', crypto: webcrypto as Crypto });

export const generateCertificate = async (commonName: string, days?: number) => {
    const algorithm = crypto.getAlgorithmParameters('ecdsa', 'generateKey');
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
export const createPkcs12Container = async (cert: ArrayBuffer, key: ArrayBuffer, password?: string) => {
    const pkcs12 = new PFX({
        parsedValue: {
            integrityMode: 0, // Password-Based Integrity Mode
            authenticatedSafe: new AuthenticatedSafe({
                parsedValue: {
                    safeContents: [
                        {
                            privacyMode: password ? 1 : 0, // 1 - Password based privacy mode, 0 - No privacy mode
                            value: new SafeContents({
                                safeBags: [
                                    new SafeBag({
                                        bagId: '1.2.840.113549.1.12.10.1.1', // Private key bag
                                        bagValue: PrivateKeyInfo.fromBER(key),
                                    }),
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

    pkcs12.parsedValue.authenticatedSafe.makeInternalValues(
        {
            safeContents: password
                ? [
                      {
                          password: new TextEncoder().encode(password),
                          contentEncryptionAlgorithm: {
                              name: 'AES-CBC',
                              length: 128,
                          },
                          hmacHashAlgorithm: 'SHA-256',
                          iterationCount: 2048,
                      },
                  ]
                : [{}],
        },
        crypto
    );

    await pkcs12.makeInternalValues(
        {
            password: password || '',
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
