import { execa } from 'execa';
import frida from 'frida';
import type { PlatformApi, PlatformApiOptions, SupportedCapability, SupportedRunTarget } from '.';
import { asyncUnimplemented, getObjFromFridaScript, ipaInfo, isRecord } from './util';

const fridaScripts = {
    getPrefs: `// Taken from: https://codeshare.frida.re/@dki/ios-app-info/
function dictFromNSDictionary(nsDict) {
    var jsDict = {};
    var keys = nsDict.allKeys();
    var count = keys.count();
    for (var i = 0; i < count; i++) {
        var key = keys.objectAtIndex_(i);
        var value = nsDict.objectForKey_(key);
        jsDict[key.toString()] = value.toString();
    }

    return jsDict;
}
var prefs = ObjC.classes.NSUserDefaults.alloc().init().dictionaryRepresentation();
send({ name: "get_obj_from_frida_script", payload: dictFromNSDictionary(prefs) });`,
    setClipboard: (text: string) => `ObjC.classes.UIPasteboard.generalPasteboard().setString_("${text}");`,
    getIdfv: `var idfv = ObjC.classes.UIDevice.currentDevice().identifierForVendor().toString();
send({ name: "get_obj_from_frida_script", payload: idfv });`,
    grantLocationPermission: (appId: string) =>
        `ObjC.classes.CLLocationManager.setAuthorizationStatusByType_forBundleIdentifier_(4, "${appId}");`,
    startApp: (appId: string) =>
        `ObjC.classes.LSApplicationWorkspace.defaultWorkspace().openApplicationWithBundleID_("${appId}");`,
} as const;

export const iosApi = <RunTarget extends SupportedRunTarget<'ios'>>(
    options: PlatformApiOptions<'ios', RunTarget, SupportedCapability<'ios'>[]>
): PlatformApi<'ios', 'device'> => ({
    _internal: {
        getAppId: async (ipaPath) => (await ipaInfo(ipaPath)).info['CFBundleIdentifier'] as string | undefined,
    },

    resetDevice: asyncUnimplemented('resetDevice') as never,
    ensureDevice: async () => {
        if ((await execa('ideviceinfo', ['-k', 'DeviceName'], { reject: false })).exitCode !== 0)
            throw new Error('You need to connect your device and trust this computer.');

        if (options.capabilities.includes('frida')) {
            const session = await frida
                .getUsbDevice()
                .then((f) => f.attach('SpringBoard'))
                .catch((err) => {
                    throw new Error('Cannot connect using Frida.', { cause: err });
                });
            await session.detach();
        }

        if (options.capabilities.includes('ssh')) {
            try {
                const { stdout } = await execa('sshpass', [
                    '-p',
                    options.targetOptions.rootPw || 'alpine',
                    'ssh',
                    `root@${options.targetOptions.ip}`,
                    `uname`,
                ]);
                if (stdout !== 'Darwin') throw new Error('Wrong uname output.');
            } catch (err) {
                throw new Error('Cannot connect using SSH.', { cause: err });
            }
        }
    },
    clearStuckModals: asyncUnimplemented('clearStuckModals') as never,

    // We're using `libimobiledevice` instead of `cfgutil` because the latter doesn't wait for the app to be fully
    // installed before exiting.
    installApp: async (ipaPath) => {
        await execa('ideviceinstaller', ['--install', ipaPath]);
    },
    uninstallApp: async (appId) => {
        await execa('ideviceinstaller', ['--uninstall', appId]);
    },
    setAppPermissions: async (appId: string) => {
        if (!options.capabilities.includes('ssh') || !options.capabilities.includes('frida'))
            throw new Error('SSH and Frida are required for setting app permissions.');

        // prettier-ignore
        const permissionsToGrant = ['kTCCServiceLiverpool', 'kTCCServiceUbiquity', 'kTCCServiceCalendar', 'kTCCServiceAddressBook', 'kTCCServiceReminders', 'kTCCServicePhotos', 'kTCCServiceMediaLibrary', 'kTCCServiceBluetoothAlways', 'kTCCServiceMotion', 'kTCCServiceWillow', 'kTCCServiceExposureNotification'];
        const permissionsToDeny = ['kTCCServiceCamera', 'kTCCServiceMicrophone', 'kTCCServiceUserTracking'];

        // value === 0 for not granted, value === 2 for granted
        const setPermission = (permission: string, value: 0 | 2) =>
            execa('sshpass', [
                '-p',
                options.targetOptions.rootPw || 'alpine',
                'ssh',
                `root@${options.targetOptions.ip}`,
                'sqlite3',
                '/private/var/mobile/Library/TCC/TCC.db',
                `'INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version) VALUES("${permission}", "${appId}", 0, ${value}, 2, 1);'`,
            ]);
        const grantLocationPermission = async () => {
            const session = await frida.getUsbDevice().then((f) => f.attach('SpringBoard'));
            const script = await session.createScript(fridaScripts.grantLocationPermission(appId));
            await script.load();
            await session.detach();
        };

        for (const permission of permissionsToGrant) await setPermission(permission, 2);
        for (const permission of permissionsToDeny) await setPermission(permission, 0);
        await grantLocationPermission();
    },
    startApp: async (appId) => {
        if (options.capabilities.includes('frida')) {
            const session = await frida.getUsbDevice().then((f) => f.attach('SpringBoard'));
            const script = await session.createScript(fridaScripts.startApp(appId));
            await script.load();
            await session.detach();
        } else if (options.capabilities.includes('ssh')) {
            execa('sshpass', [
                '-p',
                options.targetOptions.rootPw || 'alpine',
                'ssh',
                `root@${options.targetOptions.ip}`,
                `open ${appId}`,
            ]);
        } else {
            throw new Error('Frida or SSH (with the open package installed) is required for starting apps.');
        }
    },

    getForegroundAppId: async () => {
        if (!options.capabilities.includes('frida'))
            throw new Error('Frida is required for getting the foreground app ID.');

        const device = await frida.getUsbDevice();
        const app = await device.getFrontmostApplication();
        return app?.identifier;
    },
    getPidForAppId: async (appId) => {
        if (!options.capabilities.includes('frida'))
            throw new Error('Frida is required for getting the PID for an app ID.');

        const { stdout: psJson } = await execa(options.targetOptions.fridaPsPath, [
            '--usb',
            '--applications',
            '--json',
        ]);
        const ps: { pid: number; name: string; identifier: string }[] = JSON.parse(psJson);
        return ps.find((p) => p.identifier === appId)?.pid;
    },
    async getPrefs(appId) {
        if (!options.capabilities.includes('frida')) throw new Error('Frida is required for getting prefs.');

        const pid = await this.getPidForAppId(appId);
        const res = await getObjFromFridaScript(pid, fridaScripts.getPrefs);
        if (isRecord(res)) return res;
        throw new Error('Failed to get prefs.');
    },
    async getDeviceAttribute(attribute, ...args) {
        if (!options.capabilities.includes('frida'))
            throw new Error('Frida is required for getting device attributes.');

        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const opts = args[0]!;

        switch (attribute) {
            case 'idfv': {
                const pid = await this.getPidForAppId(opts.appId);
                const idfv = await getObjFromFridaScript(pid, fridaScripts.getIdfv);
                if (typeof idfv === 'string') return idfv;
                throw new Error('Failed to get IDFV.');
            }
        }

        throw new Error(`Unsupported device attribute: ${attribute}`);
    },
    async setClipboard(text) {
        if (!options.capabilities.includes('frida')) throw new Error('Frida is required for setting the clipboard.');

        const session = await frida.getUsbDevice().then((f) => f.attach('SpringBoard'));
        const script = await session.createScript(fridaScripts.setClipboard(text));
        await script.load();
        await session.detach();
    },

    getAppId: async (ipaPath) => (await ipaInfo(ipaPath)).info['CFBundleIdentifier'] as string | undefined,
    getAppVersion: async (ipaPath) => (await ipaInfo(ipaPath)).info['CFBundleShortVersionString'] as string | undefined,
});
