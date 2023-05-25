import { runAndroidDevTool } from 'andromatic';
import { fileTypeFromFile } from 'file-type';
import type { TargetProcess } from 'frida';
import frida from 'frida';
import fs from 'fs-extra';
import { open } from 'fs/promises';
import _ipaInfo from 'ipa-extract-info';

import type { AppPath, SupportedPlatform } from '../index';
import { getFileFromZip, writeFileFromZipToTmp } from './zip';

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
 * @param appPath Path to the app file (`.ipa` on iOS, `.apk` on Android) to get the metadata of. On Android, this can
 *   also be an array of the paths of the split APKs of a single app or the following custom APK bundle formats:
 *   `.xapk`, `.apkm` and `.apks`.
 * @param platform The platform the app file is for. If not provided, it will be inferred from the file extension.
 *
 * @returns An object with the properties listed above, or `undefined` if the file doesn't exist or is not a valid app
 *   for the platform.
 */
export const parseAppMeta = async <Platform extends SupportedPlatform>(
    appPath: AppPath<Platform>,
    _platform?: Platform
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
    const platform = _platform ?? (typeof appPath === 'string' && appPath.endsWith('.ipa') ? 'ios' : 'android');

    if (platform === 'android') {
        const parseApk = async (apkPath: string) => {
            // This sometimes fails with `AndroidManifest.xml:42: error: ERROR getting 'android:icon' attribute: attribute
            // value reference does not exist` but still has the correct version in the output.
            const { stdout } = await runAndroidDevTool('aapt', ['dump', 'badging', apkPath], { reject: false });

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
                isSplit: stdout.includes("split='"),
            };
        };

        if (Array.isArray(appPath)) {
            for (const apkPath of appPath) {
                const meta = await parseApk(apkPath);
                if (!meta?.isSplit) return meta;
            }

            return undefined;
        } else if (appPath.endsWith('.xapk')) {
            const xapk = await open(appPath);
            return await getFileFromZip(xapk, 'manifest.json').then(async (manifest) => {
                if (!manifest) return undefined;
                const manifestString = await new Promise<string>((resolve) => {
                    let result = '';
                    manifest.on('data', (chunk) => (result += chunk.toString()));
                    manifest.on('end', () => resolve(result));
                });
                const manifestJson: XapkManifest = JSON.parse(manifestString);
                const baseApkFileName = manifestJson.split_apks?.find((apk) => apk.id === 'base');
                const baseApkPath = baseApkFileName && (await writeFileFromZipToTmp(xapk, baseApkFileName.file));
                await xapk.close();
                return baseApkPath ? parseApk(baseApkPath) : undefined;
            });
        } else if (appPath.endsWith('.apkm') || appPath.endsWith('.apks')) {
            if ((await fileTypeFromFile(appPath))?.mime !== 'application/zip')
                throw new Error(
                    'Failed to parse app meta: Encrypted apkm files are not supported, use the newer zip format instead.'
                );

            const bundle = await open(appPath);
            const baseApkPath = await writeFileFromZipToTmp(bundle, 'base.apk');
            await bundle.close();
            return baseApkPath ? parseApk(baseApkPath) : undefined;
        }

        return parseApk(appPath);
    } else if (platform === 'ios') {
        const meta = await ipaInfo(appPath as AppPath<'ios'>);

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

export const ipaInfo = async (ipaPath: `${string}.ipa`) => {
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

// Taken from: https://stackoverflow.com/a/67605309
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ParametersExceptFirst<F> = F extends (arg0: any, ...rest: infer R) => any ? R : never;

export type XapkManifest = {
    expansions?: { file: string; install_location: string; install_path: string }[];
    split_apks?: { file: string; id: string }[];
};

// I adapted this from https://github.com/sindresorhus/execa/blob/b44d4066aebd2db0c7864936e710b9fa6f5ab9d2/lib/command.js#L12-L25

const NO_ESCAPE_REGEXP = /^[\w.-]+$/;
const DOUBLE_QUOTES_REGEXP = /"/g;
const IS_QUOTED_REGEXP = /^".*"$/;

export const escapeArg = (arg: string) => {
    if (typeof arg !== 'string' || NO_ESCAPE_REGEXP.test(arg)) {
        return arg;
    }

    return `"${arg.replace(DOUBLE_QUOTES_REGEXP, '\\"')}"`;
};

export const escapeCommand = (args: string[]) => {
    const escapedCommand = args.map((arg) => escapeArg(arg)).join(' ');
    return IS_QUOTED_REGEXP.test(escapedCommand) ? escapedCommand : `'${escapedCommand}'`;
};
