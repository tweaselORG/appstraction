import type { PlistObject } from 'plist';

declare module 'ipa-extract-info' {
    export default async function extract(
        fileDescriptor: number,
        { autoClose = true } = {}
    ): { info: PlistObject; mobileprovision: null | Buffer };
}
