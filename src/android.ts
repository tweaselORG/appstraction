import { execa } from 'execa';
import frida from 'frida';
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
): PlatformApi<'android', 'device' | 'emulator'> => ({
    _internal: {
        objectionProcesses: [],

        awaitAdb: async () => {
            let adbTries = 0;
            while ((await execa('adb', ['get-state'], { reject: false })).exitCode !== 0) {
                if (adbTries > 100) throw new Error('Failed to connect via adb.');
                await pause(250);
                adbTries++;
            }
        },
        async ensureFrida() {
            if (!options.capabilities.includes('frida')) return;

            const fridaCheck = await execa(`frida-ps -U | grep frida-server`, {
                shell: true,
                reject: false,
            });
            if (fridaCheck.exitCode === 0) return;

            await this.requireRoot('Frida');

            await execa('adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"', { shell: true });
            let fridaTries = 0;
            while (
                (
                    await execa(`frida-ps -U | grep frida-server`, {
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
        async requireRoot(action) {
            if (!options.capabilities.includes('root')) throw new Error(`Root access is required for ${action}.`);

            await execa('adb', ['root']);
            await this.awaitAdb();
        },

        getCertificateSubjectHashOld: (path: string) =>
            execa('openssl', ['x509', '-inform', 'PEM', '-subject_hash_old', '-in', path]).then(
                ({ stdout }) => stdout.split('\n')[0]
            ),
        hasCertificateAuthority: (filename) =>
            execa('adb', ['shell', 'ls', `/system/etc/security/cacerts/${filename}`], { reject: false }).then(
                ({ exitCode }) => exitCode === 0
            ),
        overlayTmpfs: async (directoryPath) => {
            const isTmpfsAlready = (await execa('adb', ['shell', 'mount'])).stdout
                .split('\n')
                .some((line) => line.includes(directoryPath) && line.includes('type tmpfs'));
            if (isTmpfsAlready) return;

            await execa('adb', ['shell', 'mkdir', '-pm', '600', '/data/local/tmp/appstraction-overlay-tmpfs-tmp']);
            await execa('adb', [
                'shell',
                'cp',
                '--preserve=all',
                `${directoryPath}/*`,
                '/data/local/tmp/appstraction-overlay-tmpfs-tmp',
            ]);

            await execa('adb', ['shell', 'mount', '-t', 'tmpfs', 'tmpfs', directoryPath]);
            await execa('adb', [
                'shell',
                'cp',
                '--preserve=all',
                '/data/local/tmp/appstraction-overlay-tmpfs-tmp/*',
                directoryPath,
            ]);

            await execa('adb', ['shell', 'rm', '-r', '/data/local/tmp/appstraction-overlay-tmpfs-tmp']);
        },
    },

    async resetDevice(snapshotName) {
        if (options.runTarget !== 'emulator') throw new Error('Resetting devices is only supported for emulators.');

        // Annoyingly, this command doesn't return a non-zero exit code if it fails (e.g. if the snapshot doesn't
        // exist). It only prints to stdout (not even stderr -.-).
        const { stdout } = await execa('adb', ['emu', 'avd', 'snapshot', 'load', snapshotName]);
        if (stdout.includes('KO')) throw new Error(`Failed to load snapshot: ${stdout}.`);

        await this.ensureDevice();
    },
    async ensureDevice() {
        await this._internal.awaitAdb().catch((err) => {
            throw new Error(
                options.runTarget === 'device' ? 'You need to connect your device.' : 'You need to start the emulator.',
                { cause: err }
            );
        });

        await this._internal.ensureFrida();
    },
    clearStuckModals: async () => {
        // Press back button.
        await execa('adb', ['shell', 'input', 'keyevent', '4']);
        // Press home button.
        await execa('adb', ['shell', 'input', 'keyevent', '3']);
    },

    installApp: async (apkPath) => {
        await execa('adb', ['install-multiple', apkPath], { shell: true });
    },
    uninstallApp: async (appId) => {
        await execa('adb', ['shell', 'pm', 'uninstall', '--user', '0', appId]).catch((err) => {
            // Don't fail if app wasn't installed.
            if (!err.stdout.includes('not installed for 0')) throw err;
        });
    },
    setAppPermissions: async (appId, _permissions) => {
        const getAllPermissions = () =>
            // The `-g` is required to also get the runtime permissions, see https://github.com/tweaselORG/appstraction/issues/15#issuecomment-1420771931.
            execa('adb', ['shell', 'pm', 'list', 'permissions', '-u', '-g'])
                .then((r) => r.stdout)
                .then((stdout) =>
                    stdout
                        .split('\n')
                        .filter((l) => l.startsWith('  permission:'))
                        .map((l) => l.replace('  permission:', ''))
                );

        type Permissions = Exclude<typeof _permissions, undefined>;
        const permissions =
            _permissions || (await getAllPermissions()).reduce<Permissions>((acc, p) => ({ ...acc, [p]: 'allow' }), {});

        for (const [permission, value] of Object.entries(permissions)) {
            const command = { allow: 'grant', deny: 'revoke' }[value!];

            // We expect this to fail for unchangeable permissions and those the app doesn't want.
            await execa('adb', ['shell', 'pm', command, appId, permission]).catch((err) => {
                if (
                    err.exitCode === 255 &&
                    (err.stderr.includes('not a changeable permission type') ||
                        err.stderr.includes('has not requested permission'))
                )
                    return;

                throw new Error(`Failed to set permission "${permission}".`, { cause: err });
            });
        }
    },
    setAppBackgroundBatteryUsage: async (appId, state) => {
        switch (state) {
            case 'unrestricted':
                await execa('adb', ['shell', 'cmd', 'appops', 'set', appId, 'RUN_ANY_IN_BACKGROUND', 'allow']);
                await execa('adb', ['shell', 'dumpsys', 'deviceidle', 'whitelist', `+${appId}`]);
                return;
            case 'optimized':
                await execa('adb', ['shell', 'cmd', 'appops', 'set', appId, 'RUN_ANY_IN_BACKGROUND', 'allow']);
                await execa('adb', ['shell', 'dumpsys', 'deviceidle', 'whitelist', `-${appId}`]);
                return;
            case 'restricted':
                await execa('adb', ['shell', 'cmd', 'appops', 'set', appId, 'RUN_ANY_IN_BACKGROUND', 'ignore']);
                await execa('adb', ['shell', 'dumpsys', 'deviceidle', 'whitelist', `-${appId}`]);
                return;
            default:
                throw new Error(`Invalid battery optimization state: ${state}`);
        }
    },
    startApp(appId) {
        // We deliberately don't await these since objection doesn't exit after the app is started.
        if (options.capabilities.includes('certificate-pinning-bypass')) {
            const process = execa('objection', [
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

        // We need to find any running app that we can inject into to set the clipboard.
        const fridaDevice = await frida.getUsbDevice();
        const runningApps = (await fridaDevice.enumerateApplications()).filter((a) => a.pid !== 0);
        if (runningApps.length === 0) throw new Error('Setting clipboard failed: No running app found.');

        for (const app of runningApps) {
            const res = await getObjFromFridaScript(app.pid, fridaScripts.setClipboard(text));
            if (res) return;
        }
        throw new Error('Setting clipboard failed.');
    },

    async installCertificateAuthority(path) {
        // Android only loads CAs with a filename of the form `<subject_hash_old>.0`.
        const certFilename = `${await this._internal.getCertificateSubjectHashOld(path)}.0`;

        if (await this._internal.hasCertificateAuthority(certFilename)) return;

        await this._internal.requireRoot('installCertificateAuthority');

        // Since Android 10, we cannot write to `/system` anymore, even if we are root, see:
        // https://github.com/tweaselORG/meta/issues/18#issuecomment-1437057934
        // Thanks to HTTP Toolkit for the idea to use a tmpfs as a workaround:
        // https://github.com/httptoolkit/httptoolkit-server/blob/9658bef164fb5cfce13b2c4b1bedacc158767f57/src/interceptors/android/adb-commands.ts#L228-L230
        await this._internal.overlayTmpfs('/system/etc/security/cacerts');

        await execa('adb', ['push', path, `/system/etc/security/cacerts/${certFilename}`]);
    },
    async removeCertificateAuthority(path) {
        const certFilename = `${await this._internal.getCertificateSubjectHashOld(path)}.0`;

        if (!(await this._internal.hasCertificateAuthority(certFilename))) return;

        await this._internal.requireRoot('removeCertificateAuthority');

        await this._internal.overlayTmpfs('/system/etc/security/cacerts');
        await execa('adb', ['shell', 'rm', `/system/etc/security/cacerts/${certFilename}`]);
    },
    setProxy: async (proxy) => {
        // Regardless of whether we want to set or remove the proxy, we don't want proxy auto-config to interfere.
        await execa('adb', ['shell', 'settings', 'delete', 'global', 'global_proxy_pac_url']);

        if (proxy === null) {
            // Just deleting the settings only works after a reboot, this ensures that the proxy is disabled
            // immediately, see https://github.com/tweaselORG/appstraction/issues/25#issuecomment-1438813160.
            await execa('adb', ['shell', 'settings', 'put', 'global', 'http_proxy', ':0']);
            await execa('adb', ['shell', 'settings', 'delete', 'global', 'global_http_proxy_host']);
            await execa('adb', ['shell', 'settings', 'put', 'global', 'global_http_proxy_port', '0']);
            return;
        }

        const proxyString = `${proxy.host}:${proxy.port}`;
        await execa('adb', ['shell', 'settings', 'put', 'global', 'http_proxy', proxyString]);
        await execa('adb', ['shell', 'settings', 'put', 'global', 'global_http_proxy_host', proxy.host]);
        await execa('adb', ['shell', 'settings', 'put', 'global', 'global_http_proxy_port', proxy.port.toString()]);
    },
});

/** The IDs of known permissions on Android. */
export const androidPermissions = [
    'android.permission.ACCEPT_HANDOVER',
    'android.permission.ACCESS_BACKGROUND_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_LOCATION_EXTRA_COMMANDS',
    'android.permission.ACCESS_MEDIA_LOCATION',
    'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.ACCESS_NOTIFICATION_POLICY',
    'android.permission.ACCESS_WIFI_STATE',
    'android.permission.ACTIVITY_RECOGNITION',
    'android.permission.ANSWER_PHONE_CALLS',
    'android.permission.AUTHENTICATE_ACCOUNTS',
    'android.permission.BLUETOOTH_ADMIN',
    'android.permission.BLUETOOTH_ADVERTISE',
    'android.permission.BLUETOOTH_CONNECT',
    'android.permission.BLUETOOTH_SCAN',
    'android.permission.BLUETOOTH',
    'android.permission.BODY_SENSORS_BACKGROUND',
    'android.permission.BODY_SENSORS',
    'android.permission.BROADCAST_STICKY',
    'android.permission.CALL_COMPANION_APP',
    'android.permission.CALL_PHONE',
    'android.permission.CAMERA',
    'android.permission.CHANGE_NETWORK_STATE',
    'android.permission.CHANGE_WIFI_MULTICAST_STATE',
    'android.permission.CHANGE_WIFI_STATE',
    'android.permission.DELIVER_COMPANION_MESSAGES',
    'android.permission.DISABLE_KEYGUARD',
    'android.permission.EXPAND_STATUS_BAR',
    'android.permission.FLASHLIGHT',
    'android.permission.FOREGROUND_SERVICE',
    'android.permission.GET_ACCOUNTS',
    'android.permission.GET_PACKAGE_SIZE',
    'android.permission.GET_TASKS',
    'android.permission.HIDE_OVERLAY_WINDOWS',
    'android.permission.HIGH_SAMPLING_RATE_SENSORS',
    'android.permission.INTERNET',
    'android.permission.KILL_BACKGROUND_PROCESSES',
    'android.permission.MANAGE_ACCOUNTS',
    'android.permission.MANAGE_OWN_CALLS',
    'android.permission.MODIFY_AUDIO_SETTINGS',
    'android.permission.NEARBY_WIFI_DEVICES',
    'android.permission.NFC_PREFERRED_PAYMENT_INFO',
    'android.permission.NFC_TRANSACTION_EVENT',
    'android.permission.NFC',
    'android.permission.PERSISTENT_ACTIVITY',
    'android.permission.POST_NOTIFICATIONS',
    'android.permission.PROCESS_OUTGOING_CALLS',
    'android.permission.QUERY_ALL_PACKAGES',
    'android.permission.READ_BASIC_PHONE_STATE',
    'android.permission.READ_CALENDAR',
    'android.permission.READ_CALL_LOG',
    'android.permission.READ_CELL_BROADCASTS',
    'android.permission.READ_CONTACTS',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.READ_INSTALL_SESSIONS',
    'android.permission.READ_MEDIA_AUDIO',
    'android.permission.READ_MEDIA_IMAGES',
    'android.permission.READ_MEDIA_VIDEO',
    'android.permission.READ_NEARBY_STREAMING_POLICY',
    'android.permission.READ_PHONE_NUMBERS',
    'android.permission.READ_PHONE_STATE',
    'android.permission.READ_PROFILE',
    'android.permission.READ_SMS',
    'android.permission.READ_SOCIAL_STREAM',
    'android.permission.READ_SYNC_SETTINGS',
    'android.permission.READ_SYNC_STATS',
    'android.permission.READ_USER_DICTIONARY',
    'android.permission.RECEIVE_BOOT_COMPLETED',
    'android.permission.RECEIVE_MMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.RECEIVE_WAP_PUSH',
    'android.permission.RECORD_AUDIO',
    'android.permission.REORDER_TASKS',
    'android.permission.REQUEST_COMPANION_PROFILE_WATCH',
    'android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND',
    'android.permission.REQUEST_COMPANION_START_FOREGROUND_SERVICES_FROM_BACKGROUND',
    'android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND',
    'android.permission.REQUEST_DELETE_PACKAGES',
    'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
    'android.permission.REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE',
    'android.permission.REQUEST_PASSWORD_COMPLEXITY',
    'android.permission.RESTART_PACKAGES',
    'android.permission.SCHEDULE_EXACT_ALARM',
    'android.permission.SEND_SMS',
    'android.permission.SET_WALLPAPER_HINTS',
    'android.permission.SET_WALLPAPER',
    'android.permission.SUBSCRIBED_FEEDS_READ',
    'android.permission.SUBSCRIBED_FEEDS_WRITE',
    'android.permission.TRANSMIT_IR',
    'android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION',
    'android.permission.USE_BIOMETRIC',
    'android.permission.USE_CREDENTIALS',
    'android.permission.USE_EXACT_ALARM',
    'android.permission.USE_FINGERPRINT',
    'android.permission.USE_FULL_SCREEN_INTENT',
    'android.permission.USE_SIP',
    'android.permission.UWB_RANGING',
    'android.permission.VIBRATE',
    'android.permission.WAKE_LOCK',
    'android.permission.WRITE_CALENDAR',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.WRITE_CONTACTS',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.WRITE_PROFILE',
    'android.permission.WRITE_SMS',
    'android.permission.WRITE_SOCIAL_STREAM',
    'android.permission.WRITE_SYNC_SETTINGS',
    'android.permission.WRITE_USER_DICTIONARY',
    'com.android.alarm.permission.SET_ALARM',
    'com.android.browser.permission.READ_HISTORY_BOOKMARKS',
    'com.android.browser.permission.WRITE_HISTORY_BOOKMARKS',
    'com.android.launcher.permission.INSTALL_SHORTCUT',
    'com.android.launcher.permission.UNINSTALL_SHORTCUT',
    'com.android.voicemail.permission.ADD_VOICEMAIL',
    'com.google.android.gms.dck.permission.DIGITAL_KEY_READ',
    'com.google.android.gms.dck.permission.DIGITAL_KEY_WRITE',
    'com.google.android.gms.permission.ACTIVITY_RECOGNITION',
    'com.google.android.gms.permission.AD_ID_NOTIFICATION',
    'com.google.android.gms.permission.AD_ID',
    'com.google.android.gms.permission.CAR_FUEL',
    'com.google.android.gms.permission.CAR_MILEAGE',
    'com.google.android.gms.permission.CAR_SPEED',
    'com.google.android.gms.permission.CAR_VENDOR_EXTENSION',
    'com.google.android.gms.permission.REQUEST_SCREEN_LOCK_COMPLEXITY',
    'com.google.android.gms.permission.TRANSFER_WIFI_CREDENTIAL',
    'com.google.android.ims.providers.ACCESS_DATA',
    'com.google.android.providers.gsf.permission.READ_GSERVICES',
] as const;
/** An ID of a known permission on Android. */
export type AndroidPermission = (typeof androidPermissions)[number];
