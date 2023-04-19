import { execa } from 'execa';
import type { TargetProcess } from 'frida';
import frida from 'frida';
import { createWriteStream } from 'fs';
import fs from 'fs-extra';
import type { FileHandle } from 'fs/promises';
import _ipaInfo from 'ipa-extract-info';
import type { Readable } from 'stream';
import { temporaryFile } from 'tempy';
import type { Entry, ZipFile } from 'yauzl';
import { fromFd } from 'yauzl';
import type { SupportedPlatform } from './index';

// eslint-disable-next-line @typescript-eslint/no-empty-function
export const asyncNop = async () => {};
export const asyncUnimplemented = (action: string) => async () => {
    throw new Error('Unimplemented on this platform: ' + action);
};

export const retryCondition = async (
    condition: () => boolean | Promise<boolean>,
    maxTries = 50,
    pauseBetweenTries = 250
) => {
    let tries = 0;

    while (!(await condition())) {
        if (tries > maxTries) return false;

        await pause(pauseBetweenTries);
        tries++;
    }

    return true;
};

/**
 * Pause for a given duration.
 *
 * @param durationInMs The duration to pause for, in milliseconds.
 */
export const pause = (durationInMs: number) =>
    new Promise((res) => {
        setTimeout(res, durationInMs);
    });

/**
 * Get metadata about the app at the given path. This includes the following properties:
 *
 * - `id`: The app's ID.
 * - `name`: The app's display name.
 * - `version`: The app's human-readable version.
 * - `versionCode`: The app's version code.
 * - `architectures`: The architectures the device needs to support to run the app. On Android, this will be empty for
 *   apps that don't have native code.
 *
 * @param appPath Path to the app file (`.ipa` on iOS, `.apk` on Android) to get the metadata of.
 * @param platform The platform the app file is for. If not provided, it will be inferred from the file extension.
 *
 * @returns An object with the properties listed above, or `undefined` if the file doesn't exist or is not a valid app
 *   for the platform.
 */
export const parseAppMeta = async (
    appPath: string,
    _platform?: SupportedPlatform
): Promise<
    | {
          id: string;
          name?: string;
          version?: string;
          versionCode?: string;
          architectures: ('arm64' | 'arm' | 'x86' | 'x86_64' | 'mips' | 'mips64')[];
      }
    | undefined
> => {
    const platform = _platform ?? (appPath.endsWith('.ipa') ? 'ios' : 'android');

    if (platform === 'android') {
        // This sometimes fails with `AndroidManifest.xml:42: error: ERROR getting 'android:icon' attribute: attribute
        // value reference does not exist` but still has the correct version in the output.
        const { stdout } = await execa('aapt', ['dump', 'badging', appPath], { reject: false });

        const id = stdout.match(/package: name='(.*?)'/)?.[1];
        if (!id) return undefined;

        const nativeCode =
            stdout
                .match(/native-code: (.+)/)?.[1]
                ?.split(' ')
                .map((s) => s.replace(/'/g, ''))
                .filter(Boolean) ?? [];
        // See: https://github.com/tweaselORG/appstraction/issues/4#issuecomment-1485068617 and
        // https://android.stackexchange.com/a/168320
        const architectureNativeCodeMap = {
            arm: 'armeabi-v7a',
            arm64: 'arm64-v8a',
            x86: 'x86',
            // eslint-disable-next-line camelcase
            x86_64: 'x86_64',
            mips: 'mips',
            mips64: 'mips64',
        } as const;

        return {
            id,
            name: stdout.match(/application-label:'(.*?)'/)?.[1],
            version: stdout.match(/versionName='([^']+?)'/)?.[1],
            versionCode: stdout.match(/versionCode='([^']+?)'/)?.[1],
            architectures: (
                Object.keys(architectureNativeCodeMap) as (keyof typeof architectureNativeCodeMap)[]
            ).filter((a) => nativeCode.includes(architectureNativeCodeMap[a])),
        };
    } else if (platform === 'ios') {
        const meta = await ipaInfo(appPath);

        const id = meta.info['CFBundleIdentifier'] as string | undefined;
        if (!id) return undefined;

        // As per: https://developer.apple.com/documentation/bundleresources/information_property_list/uirequireddevicecapabilities
        const architectureCapabilityMap = {
            arm: 'armv7',
            arm64: 'arm64',
        } as const;
        const architectures = (
            Object.keys(architectureCapabilityMap) as (keyof typeof architectureCapabilityMap)[]
        ).filter((a) => (meta.info['UIRequiredDeviceCapabilities'] as string[]).includes(architectureCapabilityMap[a]));

        return {
            id,
            // See https://stackoverflow.com/a/15423880 for why we use `CFBundleDisplayName` instead of `CFBundleName`.
            name: meta.info['CFBundleDisplayName'] as string | undefined,
            version: meta.info['CFBundleShortVersionString'] as string | undefined,
            versionCode: meta.info['CFBundleVersion'] as string | undefined,
            architectures,
        };
    }

    throw new Error(`Unsupported platform "${platform}".`);
};

export const ipaInfo = async (ipaPath: string) => {
    const fd = await fs.open(ipaPath, 'r');
    return await _ipaInfo(fd);
};

export const getObjFromFridaScript = async (targetProcess: TargetProcess | undefined, script: string) => {
    if (!targetProcess) throw new Error('Must provide targetProcess.');
    const fridaDevice = await frida.getUsbDevice();
    const fridaSession = await fridaDevice.attach(targetProcess);
    const fridaScript = await fridaSession.createScript(script);
    const resultPromise = new Promise<unknown>((res, rej) => {
        fridaScript.message.connect((message) => {
            if (message.type === 'send' && message.payload?.name === 'get_obj_from_frida_script')
                res(message.payload?.payload);
            else rej(message);
        });
    });
    await fridaScript.load();

    await fridaSession.detach();
    return await resultPromise; // We want this to be caught here if it fails, thus the `await`.
};

export const isRecord = (maybeRecord: unknown): maybeRecord is Record<string, unknown> =>
    !!maybeRecord && typeof maybeRecord === 'object';

/**
 * Promise wrapper for yauzl.fromFd.
 *
 * @param zip FileHandle of the zip file.
 *
 * @returns ZipFile to be used with yauzl.
 */
export const openZipFile = async (zip: FileHandle) =>
    new Promise<ZipFile>((resolve) => {
        fromFd(zip.fd, { lazyEntries: true }, (err, zipFile) => {
            if (err) throw err;
            resolve(zipFile);
        });
    });

/**
 * Run a function on each entry in a zip file. Resolves if all entries have been processed.
 *
 * @param zip FileHandle of the zip file.
 * @param callback Function to run on each entry, it will receive the entry and a reference to the current ZipFile.
 */
export const forEachInZip = async (zip: FileHandle, callback: (entry: Entry, zipFile: ZipFile) => Promise<void>) =>
    openZipFile(zip).then(
        (zipFile) =>
            new Promise<void>((resolve) => {
                zipFile.readEntry();
                zipFile.on('entry', (entry: Entry) => {
                    callback(entry, zipFile).then(() => zipFile.readEntry());
                });
                zipFile.on('end', () => resolve());
            })
    );

/**
 * Get a Readable stream of a file entry in a zip file.
 *
 * @param zip FileHandle of the zip file.
 * @param filename Name of the file entry in the zip.
 *
 * @returns A Readable stream of the file entry, or void if the file entry was not found.
 */
export const getFileFromZip = async (zip: FileHandle, filename: string) =>
    openZipFile(zip).then(
        (zipFile) =>
            new Promise<Readable | void>((resolve) => {
                zipFile.readEntry();
                zipFile.on('entry', (entry: Entry) => {
                    if (entry.fileName !== filename) {
                        zipFile.readEntry();
                        return;
                    }
                    zipFile.openReadStream(entry, (err, stream) => {
                        if (err) throw err;
                        resolve(stream);
                    });
                });
                zipFile.on('end', () => resolve());
            })
    );

/**
 * Write the contents of a zip entry to a temporary file.
 *
 * @param zipFile Yauzl ZipFile to read from.
 * @param entry Entry in the zip file.
 * @param extension Optional file extension to use for the temporary file.
 *
 * @returns The file name of the temporary file.
 */
export const tmpFileFromZipEntry = async (zipFile: ZipFile, entry: Entry, extension?: string) =>
    new Promise<string>((resolve) => {
        zipFile.openReadStream(entry, (err, stream) => {
            if (err) throw Error;
            const tmpFile = temporaryFile({ extension });
            stream.pipe(createWriteStream(tmpFile).on('finish', () => resolve(tmpFile)));
        });
    });
