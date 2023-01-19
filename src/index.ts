import { androidApi } from './android';
import { iosApi } from './ios';

import type { ExecaChildProcess } from 'execa';

export type SupportedPlatform = 'android' | 'ios';
export type SupportedRunTarget<Platform extends SupportedPlatform> = Platform extends 'android'
    ? 'emulator'
    : Platform extends 'ios'
    ? 'device'
    : never;

export type PlatformApi<Platform extends SupportedPlatform> = {
    ensureDevice: () => Promise<void>;
    resetDevice: () => Promise<void>;
    clearStuckModals: () => Promise<void>;

    installApp: (appPath: string) => Promise<unknown>;
    uninstallApp: (appId: string) => Promise<unknown>;
    setAppPermissions: (appId: string) => Promise<unknown>;
    startApp: (appId: string) => Promise<unknown>;

    getForegroundAppId: () => Promise<string | undefined>;
    getPidForAppId: (appId: string) => Promise<number | undefined>;
    getPrefs: (appId: string) => Promise<Record<string, unknown> | undefined>;
    // TODO: This isn’t really generic right now.
    getPlatformSpecificData: (appId: string) => Promise<Platform extends 'android' ? void : Record<string, unknown>>;
    setClipboard: (text: string) => Promise<void>;

    getAppVersion: (appPath: string) => Promise<string | undefined>;

    _internal: Platform extends 'android'
        ? {
              ensureFrida: () => Promise<void>;

              emuProcess?: ExecaChildProcess;
              objectionProcesses: ExecaChildProcess[];
          }
        : Platform extends 'ios'
        ? { getAppId: (appPath: string) => Promise<string | undefined> }
        : never;
};

export type PlatformApiOptions<Platform extends SupportedPlatform, RunTarget extends SupportedRunTarget<Platform>> = {
    platform: Platform;
    runTarget: RunTarget;
    targetOptions: RunTargetOptions[Platform][RunTarget];
};

type RunTargetOptions = {
    android: {
        emulator: {
            snapshotName: string;
            fridaPsPath: string;
            objectionPath: string;
        };
        device: never;
    };
    ios: {
        emulator: never;
        device: {
            rootPw?: string;
            ip: string;
            fridaPsPath: string;
        };
    };
};

export const platformApi = <Platform extends SupportedPlatform, RunTarget extends SupportedRunTarget<Platform>>(
    options: PlatformApiOptions<Platform, RunTarget>
): PlatformApi<Platform> => {
    switch (options.platform) {
        case 'android':
            return androidApi(
                options as PlatformApiOptions<'android', SupportedRunTarget<'android'>>
            ) as PlatformApi<Platform>;
        case 'ios':
            return iosApi(options as PlatformApiOptions<'ios', SupportedRunTarget<'ios'>>) as PlatformApi<Platform>;
        default:
            throw new Error(`Unsupported platform: ${options.platform}`);
    }
};
