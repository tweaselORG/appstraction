import { execa } from 'execa';
import frida from 'frida';
import type { PlatformApi, PlatformApiOptions, SupportedRunTarget } from '.';
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
    options: PlatformApiOptions<'ios', RunTarget>
): PlatformApi<'ios'> => ({
    _internal: {
        getAppId: async (ipaPath) => (await ipaInfo(ipaPath)).info['CFBundleIdentifier'] as string | undefined,
    },

    resetDevice: asyncUnimplemented('resetDevice'),
    ensureDevice: asyncNop,
    clearStuckModals: async () => {
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
    installApp: (ipaPath) => execa('ideviceinstaller', ['--install', ipaPath]),
    uninstallApp: (appId) => execa('ideviceinstaller', ['--uninstall', appId]),
    setAppPermissions: async (appId: string) => {
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
    startApp: (appId) =>
        execa('sshpass', [
            '-p',
            options.targetOptions.rootPw || 'alpine',
            'ssh',
            `root@${options.targetOptions.ip}`,
            `open ${appId}`,
        ]),

    getForegroundAppId: async () => {
        const device = await frida.getUsbDevice();
        const app = await device.getFrontmostApplication();
        return app?.identifier;
    },
    getPidForAppId: async (appId) => {
        const { stdout: psJson } = await execa(options.targetOptions.fridaPsPath, [
            '--usb',
            '--applications',
            '--json',
        ]);
        const ps: { pid: number; name: string; identifier: string }[] = JSON.parse(psJson);
        return ps.find((p) => p.identifier === appId)?.pid;
    },
    async getPrefs(appId) {
        const pid = await this.getPidForAppId(appId);
        const res = await getObjFromFridaScript(pid, fridaScripts.getPrefs);
        if (isRecord(res)) return res;
        throw new Error('Failed to get prefs.');
    },
    async getPlatformSpecificData(appId) {
        const getIdfv = async () => {
            const pid = await this.getPidForAppId(appId);
            return getObjFromFridaScript(pid, fridaScripts.getIdfv);
        };

        return { idfv: await getIdfv() };
    },
    async setClipboard(text) {
        const session = await frida.getUsbDevice().then((f) => f.attach('SpringBoard'));
        const script = await session.createScript(fridaScripts.setClipboard(text));
        await script.load();
        await session.detach();
    },

    getAppVersion: async (ipaPath) => (await ipaInfo(ipaPath)).info['CFBundleShortVersionString'] as string | undefined,
});
