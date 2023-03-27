import { execa } from 'execa';
import type { TargetProcess } from 'frida';
import frida from 'frida';
import fs from 'fs-extra';
import _ipaInfo from 'ipa-extract-info';
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
 * Get metadata (namely app ID and version) about the app at the given path.
 *
 * @param appPath Path to the app file (`.ipa` on iOS, `.apk` on Android) to get the metadata of.
 * @param platform The platform the app file is for. If not provided, it will be inferred from the file extension.
 *
 * @returns The an object with the app ID and version, or `undefined` if the file doesn't exist or is not a valid app
 *   for the platform.
 */
export const parseAppMeta = async (
    appPath: string,
    _platform?: SupportedPlatform
): Promise<{ id: string; version?: string } | undefined> => {
    const platform = _platform ?? (appPath.endsWith('.ipa') ? 'ios' : 'android');

    if (platform === 'android') {
        // This sometimes fails with `AndroidManifest.xml:42: error: ERROR getting 'android:icon' attribute: attribute
        // value reference does not exist` but still has the correct version in the output.
        const { stdout } = await execa('aapt', ['dump', 'badging', appPath], { reject: false });

        const id = stdout.match(/package: name='(.*?)'/)?.[1];
        if (!id) return undefined;

        return { id, version: stdout.match(/versionName='([^']+?)'/)?.[1] };
    } else if (platform === 'ios') {
        const meta = await ipaInfo(appPath);

        const id = meta.info['CFBundleIdentifier'] as string | undefined;
        if (!id) return undefined;

        return { id, version: meta.info['CFBundleShortVersionString'] as string | undefined };
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
