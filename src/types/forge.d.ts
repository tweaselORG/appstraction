import type forge from 'node-forge';

declare module 'node-forge' {
    namespace pki {
        function distinguishedNameToAsn1(dn: forge.pki.Certificate['subject' | 'issuer']): forge.pki.Asn1;
    }
}
