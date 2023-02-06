import type { ExecaChildProcess } from 'execa';
import { androidApi } from './android';
import { iosApi } from './ios';

/** A platform that is supported by this library. */
export type SupportedPlatform = 'android' | 'ios';
/** A run target that is supported by this library for the given platform. */
export type SupportedRunTarget<Platform extends SupportedPlatform> = Platform extends 'android'
    ? 'emulator' | 'device'
    : Platform extends 'ios'
    ? 'device'
    : never;

/** Functions that are available for the platforms. */
export type PlatformApi<Platform extends SupportedPlatform, RunTarget extends SupportedRunTarget<Platform>> = {
    /** Assert that the selected device is connected and ready to be used with the selected capabilities. */
    ensureDevice: () => Promise<void>;
    /** Reset the device to the snapshot specified in the `targetOptions.snapshotName` (only available for emulators). */
    resetDevice: Platform extends 'android' ? (RunTarget extends 'emulator' ? () => Promise<void> : never) : never;
    /**
     * Clear any potential stuck modals by pressing the back button followed by the home button.
     *
     * This is currently broken on iOS (see https://github.com/tweaselORG/appstraction/issues/12).
     *
     * Requires the `ssh` capability on iOS.
     */
    clearStuckModals: Platform extends 'android' ? () => Promise<void> : never;

    /**
     * Install the app at the given path.
     *
     * @param appPath Path to the app file (`.ipa` on iOS, `.apk` on Android) to install. Currently, this can also be a
     *   glob for split APKs on Android, but this may change in the future.
     * @todo How to handle split APKs on Android (#4)?
     */
    installApp: (appPath: string) => Promise<void>;
    /**
     * Uninstall the app with the given app ID. Will not fail if the app is not installed.
     *
     * This also removes any data stored by the app.
     *
     * @param appId The app ID of the app to uninstall.
     */
    uninstallApp: (appId: string) => Promise<void>;
    /**
     * Set the permissions for the app with the given app ID. This includes dangerous permissions on Android.
     *
     * Requires the `ssh` and `frida` capabilities on iOS.
     *
     * @param appId The app ID of the app to set the permissions for.
     *
     * @todo Allow specifying which permissions to grant.
     */
    setAppPermissions: (appId: string) => Promise<void>;
    /**
     * Start the app with the given app ID. Doesn't wait for the app to be ready. Also enables the certificate pinning
     * bypass if enabled.
     *
     * Requires the `frida` or `ssh` capability on iOS. On Android, this will start the app with or without a
     * certificate pinning bypass depending on the `certificate-pinning-bypass` capability.
     *
     * @param appId The app ID of the app to start.
     */
    startApp: (appId: string) => Promise<void>;

    /**
     * Get the app ID of the running app that is currently in the foreground.
     *
     * Requires the `frida` capability on iOS.
     *
     * @returns The app ID of the app that is currently in the foreground, or `undefined` if no app is in the
     *   foreground.
     */
    getForegroundAppId: () => Promise<string | undefined>;
    /**
     * Get the PID of the app with the given app ID if it is currently running.
     *
     * Requires the `frida` capability on iOS.
     *
     * @param appId The app ID of the app to get the PID for.
     *
     * @returns The PID of the app if it is currently running, or `undefined` if the app is not running.
     */
    getPidForAppId: (appId: string) => Promise<number | undefined>;
    /**
     * Get the preferences (`SharedPreferences` on Android, `NSUserDefaults` on iOS) of the app with the given app ID.
     *
     * Requires the `frida` capability on Android and iOS.
     *
     * @param appId The app ID of the app to get the preferences for.
     *
     * @returns The preferences of the app, or `undefined` if the app is not installed.
     */
    getPrefs: (appId: string) => Promise<Record<string, unknown> | undefined>;
    /**
     * Get the value of the given attribute of the device.
     *
     * Requires the `frida` capability on iOS.
     *
     * @param attribute The attribute to get the value of, where:
     *
     *   - `idfv`: The `identifierForVendor` for app given in `options` (iOS only).
     *
     * @param options Some attributes require additional options:
     *
     *   - `idfv`: The app ID of the app to get the `identifierForVendor` for.
     *
     * @returns
     */
    getDeviceAttribute: <Attribute extends DeviceAttribute<Platform>>(
        attribute: Attribute,
        ...options: Attribute extends keyof GetDeviceAttributeOptions
            ? [options: GetDeviceAttributeOptions[Attribute]]
            : [options?: undefined]
    ) => Promise<string>;
    /**
     * Set the clipboard to the given text.
     *
     * Requires the `frida` capability on Android and iOS.
     *
     * @param text The text to set the clipboard to.
     */
    setClipboard: (text: string) => Promise<void>;

    /**
     * Get the app/bundle ID of the app at the given path.
     *
     * @param appPath Path to the app file (`.ipa` on iOS, `.apk` on Android) to get the app ID of.
     *
     * @returns The app ID, or `undefined` if the file doesn't exist or is not a valid app for the platform.
     */
    getAppId: (appPath: string) => Promise<string | undefined>;
    /**
     * Get the version of the app at the given path.
     *
     * @param appPath Path to the app file (`.ipa` on iOS, `.apk` on Android) to get the version of.
     *
     * @returns The version of the app, or `undefined` if the file doesn't exist or is not a valid app for the platform.
     */
    getAppVersion: (appPath: string) => Promise<string | undefined>;

    /** @ignore */
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

/** The options for the `platformApi()` function. */
export type PlatformApiOptions<
    Platform extends SupportedPlatform,
    RunTarget extends SupportedRunTarget<Platform>,
    Capabilities extends SupportedCapability<Platform>[]
> = {
    /** The platform you want to run on. */
    platform: Platform;
    /** The target (emulator, physical device) you want to run on. */
    runTarget: RunTarget;
    /**
     * The capabilities you want. Depending on what you're trying to do, you may not need or want to root the device,
     * install Frida, etc. In this case, you can exclude those capabilities. This will influence which functions you can
     * run.
     */
    capabilities: Capabilities;
    /** The options for the selected platform/run target combination. */
    targetOptions: RunTargetOptions<Capabilities>[Platform][RunTarget];
};

/** The options for a specific platform/run target combination. */
export type RunTargetOptions<
    Capabilities extends SupportedCapability<'android' | 'ios'>[],
    Capability = Capabilities[number]
> = {
    /** The options for the Android platform. */
    android: {
        /** The options for the Android emulator run target. */
        emulator: {
            /** The name of a snapshot to use for the `resetDevice()` function. */
            snapshotName?: string;
        } & ('frida' extends Capability
            ? {
                  /** The path to the [`frida-ps`](https://frida.re/docs/frida-ps/) binary. */
                  fridaPsPath: string;
              }
            : unknown) &
            ('certificate-pinning-bypass' extends Capability
                ? {
                      /** The path to the [`objection`](https://github.com/sensepost/objection/) binary. */
                      objectionPath: string;
                  }
                : unknown);
        /** The options for the Android physical device run target. */
        device: ('frida' extends Capability
            ? {
                  /** The path to the [`frida-ps`](https://frida.re/docs/frida-ps/) binary. */
                  fridaPsPath: string;
              }
            : unknown) &
            ('certificate-pinning-bypass' extends Capability
                ? {
                      /** The path to the [`objection`](https://github.com/sensepost/objection/) binary. */
                      objectionPath: string;
                  }
                : unknown);
    };
    /** The options for the iOS platform. */
    ios: {
        /** The options for the iOS emulator run target. */
        emulator: never;
        /** The options for the iOS physical device run target. */
        device: ('ssh' extends Capability
            ? {
                  /** The password of the root user on the device, defaults to `alpine` if not set. */
                  rootPw?: string;
                  /** The device's IP address. */
                  ip: string;
              }
            : unknown) &
            ('frida' extends Capability
                ? {
                      /** The path to the [`frida-ps`](https://frida.re/docs/frida-ps/) binary. */
                      fridaPsPath: string;
                  }
                : unknown);
    };
};

/** A capability for the `platformApi()` function. */
export type SupportedCapability<Platform extends SupportedPlatform> = Platform extends 'android'
    ? 'frida' | 'certificate-pinning-bypass'
    : Platform extends 'ios'
    ? 'ssh' | 'frida'
    : never;

/** A supported attribute for the `getDeviceAttribute()` function, depending on the platform. */
export type DeviceAttribute<Platform extends SupportedPlatform> = Platform extends 'android'
    ? never
    : Platform extends 'ios'
    ? 'idfv'
    : never;
/** The options for each attribute available through the `getDeviceAttribute()` function. */
export type GetDeviceAttributeOptions = {
    /** The options for the `idfv` attribute. */
    idfv: {
        /** The app ID of the app to get the `identifierForVendor` for. */
        appId: string;
    };
};

/**
 * Get the API object with the functions for the given platform and run target.
 *
 * @param options The options for the API object.
 *
 * @returns The API object for the given platform and run target.
 */
export function platformApi<
    Platform extends SupportedPlatform,
    RunTarget extends SupportedRunTarget<Platform>,
    Capabilities extends SupportedCapability<Platform>[]
>(options: PlatformApiOptions<Platform, RunTarget, Capabilities>): PlatformApi<Platform, RunTarget> {
    switch (options.platform) {
        case 'android':
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            return androidApi(options as any) as PlatformApi<Platform, RunTarget>;
        case 'ios':
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            return iosApi(options as any) as PlatformApi<Platform, RunTarget>;
        default:
            throw new Error(`Unsupported platform: ${options.platform}`);
    }
}

export { pause } from './util';
