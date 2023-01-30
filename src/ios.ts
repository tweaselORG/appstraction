import { execa } from 'execa';
import frida from 'frida';
import type { PlatformApi, PlatformApiOptions, SupportedCapability, SupportedRunTarget } from '.';
import { asyncNop, asyncUnimplemented, getObjFromFridaScript, ipaInfo, isRecord } from './util';

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
} as const;

export const iosApi = <RunTarget extends SupportedRunTarget<'ios'>>(
    options: PlatformApiOptions<'ios', RunTarget, SupportedCapability<'ios'>[]>
): PlatformApi<'ios'> => ({
    _internal: {
        getAppId: async (ipaPath) => (await ipaInfo(ipaPath)).info['CFBundleIdentifier'] as string | undefined,
    },

    resetDevice: asyncUnimplemented('resetDevice'),
    // TODO: Assert that we actually have a device here.
    ensureDevice: asyncNop,
    clearStuckModals: async () => {
        if (!options.capabilities.includes('ssh')) throw new Error('SSH is required for clearing stuck modals.');

        await execa('sshpass', [
            '-p',
            options.targetOptions.rootPw || 'alpine',
            'ssh',
            `root@${options.targetOptions.ip}`,
            `activator send libactivator.system.clear-switcher; activator send libactivator.system.homebutton`,
        ]);
    },

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
        const setPermission = async (permission: string, value: 0 | 2) => {
            const timestamp = Math.floor(Date.now() / 1000);
            await execa('sshpass', [
                '-p',
                options.targetOptions.rootPw || 'alpine',
                'ssh',
                `root@${options.targetOptions.ip}`,
                'sqlite3',
                '/private/var/mobile/Library/TCC/TCC.db',
                `'INSERT OR REPLACE INTO access VALUES("${permission}", "${appId}", 0, ${value}, 2, 1, NULL, NULL, 0, "UNUSED", NULL, 0, ${timestamp});'`,
            ]);
        };
        const grantLocationPermission = async () => {
            await execa('sshpass', [
                '-p',
                options.targetOptions.rootPw || 'alpine',
                'ssh',
                `root@${options.targetOptions.ip}`,
                'open com.apple.Preferences',
            ]);
            const session = await frida.getUsbDevice().then((f) => f.attach('Settings'));
            const script = await session.createScript(fridaScripts.grantLocationPermission(appId));
            await script.load();
            await session.detach();
        };

        for (const permission of permissionsToGrant) await setPermission(permission, 2);
        for (const permission of permissionsToDeny) await setPermission(permission, 0);
        await grantLocationPermission();
    },
    startApp: async (appId) => {
        if (!options.capabilities.includes('ssh')) throw new Error('SSH is required for starting apps.');

        await execa('sshpass', [
            '-p',
            options.targetOptions.rootPw || 'alpine',
            'ssh',
            `root@${options.targetOptions.ip}`,
            `open ${appId}`,
        ]);
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
                const idfv = getObjFromFridaScript(pid, fridaScripts.getIdfv);
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

    getAppVersion: async (ipaPath) => (await ipaInfo(ipaPath)).info['CFBundleShortVersionString'] as string | undefined,
});
