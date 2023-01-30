import { execa } from 'execa';
import type { PlatformApi, PlatformApiOptions, SupportedCapability, SupportedRunTarget } from '.';
import { asyncUnimplemented, getObjFromFridaScript, isRecord, pause } from './util';

const fridaScripts = {
    getPrefs: `var app_ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
var pref_mgr = Java.use('android.preference.PreferenceManager').getDefaultSharedPreferences(app_ctx);
var HashMapNode = Java.use('java.util.HashMap$Node');

var prefs = {};

var iterator = pref_mgr.getAll().entrySet().iterator();
while (iterator.hasNext()) {
    var entry = Java.cast(iterator.next(), HashMapNode);
    prefs[entry.getKey().toString()] = entry.getValue().toString();
}

send({ name: "get_obj_from_frida_script", payload: prefs });`,
    setClipboard: (
        text: string
    ) => `var app_ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
var cm = Java.cast(app_ctx.getSystemService("clipboard"), Java.use("android.content.ClipboardManager"));
cm.setText(Java.use("java.lang.StringBuilder").$new("${text}"));
send({ name: "get_obj_from_frida_script", payload: true });`,
} as const;

export const androidApi = <RunTarget extends SupportedRunTarget<'android'>>(
    options: PlatformApiOptions<'android', RunTarget, SupportedCapability<'android'>[]>
): PlatformApi<'android'> => ({
    _internal: {
        emuProcess: undefined,
        objectionProcesses: [],

        ensureFrida: async () => {
            if (!options.capabilities.includes('frida')) return;

            const fridaCheck = await execa(`${options.targetOptions.fridaPsPath} -U | grep frida-server`, {
                shell: true,
                reject: false,
            });
            if (fridaCheck.exitCode === 0) return;

            await execa('adb', ['root']);
            let adbTries = 0;
            while ((await execa('adb', ['get-state'], { reject: false })).exitCode !== 0) {
                if (adbTries > 100) throw new Error('Failed to connect via adb.');
                await pause(250);
                adbTries++;
            }

            await execa('adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"', { shell: true });
            let fridaTries = 0;
            while (
                (
                    await execa(`${options.targetOptions.fridaPsPath} -U | grep frida-server`, {
                        shell: true,
                        reject: false,
                    })
                ).exitCode !== 0
            ) {
                if (fridaTries > 100) throw new Error('Failed to start Frida.');
                await pause(250);
                fridaTries++;
            }
        },
    },

    async resetDevice() {
        if (options.runTarget !== 'emulator') throw new Error('Resetting devices is only supported for emulators.');
        await execa('adb', ['emu', 'avd', 'snapshot', 'load', options.targetOptions.snapshotName]);
        await this._internal.ensureFrida();
    },
    async ensureDevice() {
        if ((await execa('adb', ['get-state'], { reject: false })).exitCode !== 0)
            throw new Error('You need to start the emulator.');

        await this._internal.ensureFrida();
    },
    clearStuckModals: async () => {
        // Press back button.
        await execa('adb', ['shell', 'input', 'keyevent', '4']);
        // Press home button.
        await execa('adb', ['shell', 'input', 'keyevent', '3']);
    },

    installApp: async (apkPath) => {
        // TODO: We shouldn't grant runtime permissions here. Move that to setAppPermissions().
        await execa('adb', ['install-multiple', '-g', apkPath], { shell: true });
    },
    uninstallApp: async (appId) => {
        await execa('adb', ['shell', 'pm', 'uninstall', '--user', '0', appId]).catch((err) => {
            // Don't fail if app wasn't installed.
            if (!err.stdout.includes('not installed for 0')) throw err;
        });
    },
    // Basic permissions are granted at install time, we only need to grant dangerous permissions, see:
    // https://android.stackexchange.com/a/220297.
    setAppPermissions: async (appId) => {
        const { stdout: permStr } = await execa('adb', ['shell', 'pm', 'list', 'permissions', '-g', '-d', '-u']);
        const dangerousPermissions = permStr
            .split('\n')
            .filter((l) => l.startsWith('  permission:'))
            .map((l) => l.replace('  permission:', ''));

        for (const permission of dangerousPermissions) {
            // We expect this to fail for permissions the app doesn't want.
            // eslint-disable-next-line @typescript-eslint/no-empty-function
            await execa('adb', ['shell', 'pm', 'grant', appId, permission]).catch(() => {});
        }
    },
    startApp(appId) {
        // We deliberately don't await these since objection doesn't exit after the app is started.
        if (options.capabilities.includes('certificate-pinning-bypass')) {
            const process = execa(options.targetOptions.objectionPath, [
                '--gadget',
                appId,
                'explore',
                '--startup-command',
                'android sslpinning disable',
            ]);
            this._internal.objectionProcesses.push(process);
            return Promise.resolve();
        }

        execa('adb', ['shell', 'monkey', '-p', appId, '-v', '1', '--dbg-no-events']);
        return Promise.resolve();
    },

    // Adapted after: https://stackoverflow.com/a/28573364
    getForegroundAppId: async () => {
        const { stdout } = await execa('adb', ['shell', 'dumpsys', 'activity', 'recents']);
        const foregroundLine = stdout.split('\n').find((l) => l.includes('Recent #0'));
        const [, appId] = Array.from(foregroundLine?.match(/A=\d+:(.+?) U=/) || []);
        return appId ? appId.trim() : undefined;
    },
    getPidForAppId: async (appId) => {
        const { stdout } = await execa('adb', ['shell', 'pidof', '-s', appId]);
        return parseInt(stdout, 10);
    },
    async getPrefs(appId) {
        if (!options.capabilities.includes('frida')) throw new Error('Frida is required for getting preferences.');

        const pid = await this.getPidForAppId(appId);
        const res = await getObjFromFridaScript(pid, fridaScripts.getPrefs);
        if (isRecord(res)) return res;
        throw new Error('Failed to get prefs.');
    },
    getDeviceAttribute: asyncUnimplemented('getDeviceAttribute'),
    async setClipboard(text) {
        if (!options.capabilities.includes('frida')) throw new Error('Frida is required for setting the clipboard.');

        const launcherPid = await this.getPidForAppId('com.google.android.apps.nexuslauncher');
        const res = await getObjFromFridaScript(launcherPid, fridaScripts.setClipboard(text));
        if (!res) throw new Error('Setting clipboard failed.');
    },

    getAppVersion: async (apkPath) =>
        // These sometimes fail with `AndroidManifest.xml:42: error: ERROR getting 'android:icon' attribute: attribute value
        // reference does not exist` but still have the correct version in the output.
        (await execa('aapt', ['dump', 'badging', apkPath], { reject: false })).stdout.match(/versionName='(.+?)'/)?.[1],
});
