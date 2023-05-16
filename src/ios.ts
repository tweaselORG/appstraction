import { createHash } from 'crypto';
import { execa } from 'execa';
import frida from 'frida';
import { readFile } from 'fs/promises';
import { NodeSSH } from 'node-ssh';
import { Certificate } from 'pkijs';
import type { PlatformApi, PlatformApiOptions, Proxy, SupportedCapability, SupportedRunTarget } from '.';
import { asyncUnimplemented, getObjFromFridaScript, isRecord } from './util';

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
    grantLocationPermission: (appId: string, value: 0 | 2 | 3 | 4) =>
        `ObjC.classes.CLLocationManager.setAuthorizationStatusByType_forBundleIdentifier_(${value}, "${appId}");`,
    startApp: (appId: string) =>
        `ObjC.classes.LSApplicationWorkspace.defaultWorkspace().openApplicationWithBundleID_("${appId}");`,
    /**
     * @param options If `options` is falsy, the proxy will be disabled. Otherwise, it will be set according to the
     *   properties and enabled. If both `options.username` and `options.password` are provided, the proxy will be
     *   configured to use authentication.
     */
    setProxy: (options: Proxy | null) => `function setProxySettingsForCurrentWifiNetwork(options) {
    var NSString = ObjC.classes.NSString;
    var NSNumber = ObjC.classes.NSNumber;

    var authenticated = options && options.username && options.password;

    var defaultProxySettings = ObjC.classes.WFSettingsProxy.defaultProxyConfiguration();

    // Sometimes, currentNetwork() returns null, so we have to try a few times.
    // See: https://github.com/tweaselORG/appstraction/issues/25#issuecomment-1447996021
    var ssid;
    for (let i = 0; i < 100; i++) {
        var currentNetwork = ObjC.classes.WFClient.sharedInstance().interface().currentNetwork();
        if (currentNetwork) {
            ssid = currentNetwork.ssid();
            break;
        }
    }

    var newSettingsDict = ObjC.classes.NSMutableDictionary.alloc().initWithDictionary_(defaultProxySettings);
    if (options) {
        newSettingsDict.setObject_forKey_(NSNumber.numberWithInt_(1), NSString.stringWithString_('HTTPEnable'));
        newSettingsDict.setObject_forKey_(NSNumber.numberWithInt_(options.port), NSString.stringWithString_('HTTPPort'));
        newSettingsDict.setObject_forKey_(NSString.stringWithString_(options.host), NSString.stringWithString_('HTTPProxy'));
        newSettingsDict.setObject_forKey_(NSNumber.numberWithInt_(1), NSString.stringWithString_('HTTPSEnable'));
        newSettingsDict.setObject_forKey_(NSNumber.numberWithInt_(options.port), NSString.stringWithString_('HTTPSPort'));
        newSettingsDict.setObject_forKey_(NSString.stringWithString_(options.host), NSString.stringWithString_('HTTPSProxy'));

        if (authenticated) {
            newSettingsDict.setObject_forKey_(NSNumber.numberWithInt_(1), NSString.stringWithString_('HTTPProxyAuthenticated'));
            newSettingsDict.setObject_forKey_(NSString.stringWithString_(options.username), NSString.stringWithString_('HTTPProxyUsername'));
        }
    }

    var newSettings = ObjC.classes.WFSettingsProxy.alloc().initWithDictionary_(newSettingsDict);
    if (authenticated) newSettings.setPassword_(options.password);

    var arrayWithNewSettings = ObjC.classes.NSMutableArray.alloc().init();
    arrayWithNewSettings.addObject_(newSettings);

    var saveSettingsOperation = ObjC.classes.WFSaveSettingsOperation.alloc().initWithSSID_settings_(ssid, arrayWithNewSettings);
    saveSettingsOperation.setCurrentNetwork_(1);
    saveSettingsOperation.start();
}

setProxySettingsForCurrentWifiNetwork(${JSON.stringify(options)});`,
    getProxy: `// Taken from: https://codeshare.frida.re/@dki/ios-app-info/
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

function getProxySettingsForCurrentWifiNetwork() {
    var ssid;
    for (let i = 0; i < 100; i++) {
        var currentNetwork = ObjC.classes.WFClient.sharedInstance().interface().currentNetwork();
        if (currentNetwork) {
            ssid = currentNetwork.ssid();
            break;
        }
    }

    var gso = ObjC.classes.WFGetSettingsOperation.alloc().initWithSSID_(ssid);
    gso.start();
    var settings = gso.settings().proxySettings();

    var dict = dictFromNSDictionary(settings.items());
    if (settings.password()) dict.HTTPProxyPassword = settings.password().toString();

    return dict;
}

send({ name: "get_obj_from_frida_script", payload: getProxySettingsForCurrentWifiNetwork() });`,
} as const;

export const iosApi = <RunTarget extends SupportedRunTarget<'ios'>>(
    options: PlatformApiOptions<'ios', RunTarget, SupportedCapability<'ios'>[]>
): PlatformApi<'ios', 'device', SupportedCapability<'ios'>[]> => ({
    target: { platform: 'ios', runTarget: options.runTarget },
    _internal: {
        ssh: async (...args) => {
            const ssh = await new NodeSSH().connect({
                host: options.targetOptions!.ip,
                username: 'root',
                password: options.targetOptions!.rootPw || 'alpine',
            });
            const res = await ssh.execCommand(...args);
            // Creating and disposing a new SSH connection for each command is not efficient but it replicates the
            // previous behaviour of calling `ssh`. If we wanted to keep the connection open, we would also need a way
            // to dispose of it at the very end, but we don't know when that is (cf. #24).
            ssh.dispose();
            return res;
        },
    },

    resetDevice: asyncUnimplemented('resetDevice') as never,
    waitForDevice: asyncUnimplemented('waitForDevice') as never,
    async ensureDevice() {
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
                const { stdout } = await this._internal.ssh('uname');
                if (stdout !== 'Darwin') throw new Error('Wrong uname output.');
            } catch (err) {
                throw new Error('Cannot connect using SSH.', { cause: err });
            }
        }
    },
    clearStuckModals: asyncUnimplemented('clearStuckModals') as never,

    isAppInstalled: async (appId) => {
        const { stdout } =
            process.platform === 'win32'
                ? await execa('ideviceinstaller', ['-l', '-o', 'list_all'])
                : await execa('ideviceinstaller', ['list', '-o', 'list_all']);
        return (
            stdout
                .split('\n')
                // The first line is the header.
                .slice(1)
                .some((l) => l.startsWith(`${appId},`))
        );
    },
    // We're using `libimobiledevice` instead of `cfgutil` because the latter doesn't wait for the app to be fully
    // installed before exiting.
    installApp: async (ipaPath) => {
        if (process.platform === 'win32') await execa('ideviceinstaller', ['install', ipaPath]);
        else await execa('ideviceinstaller', ['--install', ipaPath]);
    },
    uninstallApp: async (appId) => {
        if (process.platform === 'win32') await execa('ideviceinstaller', ['uninstall', appId]);
        else await execa('ideviceinstaller', ['--uninstall', appId]);
    },
    async setAppPermissions(appId, _permissions) {
        if (!options.capabilities.includes('ssh') || !options.capabilities.includes('frida'))
            throw new Error('SSH and Frida are required for setting app permissions.');

        const permissionValues = { allow: 2, deny: 0 } as const;
        const setPermission = (permission: string, value: 0 | 2) =>
            this._internal.ssh(
                `sqlite3 /private/var/mobile/Library/TCC/TCC.db 'INSERT OR REPLACE INTO access (service, client, client_type, auth_value, auth_reason, auth_version) VALUES("${permission}", "${appId}", 0, ${value}, 2, 1);'`
            );
        const unsetPermission = (permission: string) =>
            this._internal.ssh(
                `sqlite3 /private/var/mobile/Library/TCC/TCC.db 'DELETE FROM access WHERE service="${permission}" AND client="${appId}";'`
            );
        const locationPermissionValues = { ask: 0, never: 2, always: 3, 'while-using': 4 } as const;
        const grantLocationPermission = async (value: 0 | 2 | 3 | 4) => {
            const session = await frida.getUsbDevice().then((f) => f.attach('SpringBoard'));
            const script = await session.createScript(fridaScripts.grantLocationPermission(appId, value));
            await script.load();
            await session.detach();
        };

        type Permissions = Exclude<typeof _permissions, undefined>;
        const permissions =
            _permissions ||
            iosPermissions.reduce<Permissions>((acc, p) => ({ ...acc, [p]: 'allow' }), { location: 'always' });

        for (const [permission, to] of Object.entries(permissions)) {
            if (permission === 'location') {
                if (!(to in locationPermissionValues)) throw new Error(`Invalid location permission value: "${to}"`);
                const value = locationPermissionValues[to as 'always'];
                await grantLocationPermission(value);
                continue;
            }

            if (to === 'unset') await unsetPermission(permission);
            else if (to in permissionValues) await setPermission(permission, permissionValues[to as 'allow']);
            else throw new Error(`Invalid permission value for "${permission}": "${to}"`);
        }
    },
    setAppBackgroundBatteryUsage: asyncUnimplemented('setAppBatteryOptimization') as never,
    async startApp(appId) {
        if (options.capabilities.includes('frida')) {
            const session = await frida.getUsbDevice().then((f) => f.attach('SpringBoard'));
            const script = await session.createScript(fridaScripts.startApp(appId));
            await script.load();
            await session.detach();
        } else if (options.capabilities.includes('ssh')) {
            this._internal.ssh(`open ${appId}`);
        } else {
            throw new Error('Frida or SSH (with the open package installed) is required for starting apps.');
        }
    },
    async stopApp(appId) {
        if (!options.capabilities.includes('frida')) throw new Error('Frida is required for stopping apps.');

        const pid = await this.getPidForAppId(appId);
        if (!pid) return;

        return (await frida.getUsbDevice()).kill(pid);
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

        const { stdout: psJson } = await execa('frida-ps', ['--usb', '--applications', '--json']);
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

    async installCertificateAuthority(path) {
        if (!options.capabilities.includes('ssh'))
            throw new Error('SSH is required for installing a certificate authority.');

        const certPem = await readFile(path, 'utf8');

        // A PEM certificate is just a base64-encoded DER certificate with a header and footer.
        const certBase64 = certPem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\r\n])/g, '');
        const certDer = Buffer.from(certBase64, 'base64');

        const c = Certificate.fromBER(certDer);

        const sha256 = createHash('sha256').update(certDer).digest('hex');
        const subj = Buffer.from(c.subject.toSchema().valueBlock.toBER()).toString('hex');
        const tset = Buffer.from(
            `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array/>
</plist>`
        ).toString('hex');
        const data = certDer.toString('hex');

        await this._internal.ssh(
            `sqlite3 /private/var/protected/trustd/private/TrustStore.sqlite3 "INSERT OR REPLACE INTO tsettings (sha256, subj, tset, data) VALUES(x'${sha256}', x'${subj}', x'${tset}', x'${data}');"`
        );
    },
    async removeCertificateAuthority(path) {
        if (!options.capabilities.includes('ssh'))
            throw new Error('SSH is required for removing a certificate authority.');

        const certPem = await readFile(path, 'utf8');
        const certBase64 = certPem.replace(/(-----(BEGIN|END) CERTIFICATE-----|[\r\n])/g, '');
        const certDer = Buffer.from(certBase64, 'base64');
        const sha256 = createHash('sha256').update(certDer).digest('hex');

        await this._internal.ssh(
            `sqlite3 /private/var/protected/trustd/private/TrustStore.sqlite3 "DELETE FROM tsettings WHERE sha256=x'${sha256}';"`
        );
    },
    setProxy: async (proxy) => {
        if (!options.capabilities.includes('frida')) throw new Error('Frida is required for configuring a proxy.');

        // Set proxy settings.
        const session = await frida.getUsbDevice().then((f) => f.attach('SpringBoard'));
        const script = await session.createScript(fridaScripts.setProxy(proxy));
        await script.load();
        await session.detach();

        // Verify that the proxy settings were set.
        const proxySettings = await getObjFromFridaScript('SpringBoard', fridaScripts.getProxy);
        if (
            !isRecord(proxySettings) ||
            (proxy === null && (proxySettings['HTTPProxy'] || proxySettings['HTTPSProxy'])) ||
            (proxy !== null &&
                (proxySettings['HTTPProxy'] !== proxy?.host ||
                    proxySettings['HTTPPort'] !== proxy?.port + '' ||
                    proxySettings['HTTPSProxy'] !== proxy?.host ||
                    proxySettings['HTTPSPort'] !== proxy?.port + ''))
        )
            throw new Error('Failed to set proxy.');
    },
});

/** The IDs of known permissions on iOS. */
export const iosPermissions = [
    'kTCCServiceLiverpool',
    'kTCCServiceUbiquity',
    'kTCCServiceCalendar',
    'kTCCServiceAddressBook',
    'kTCCServiceReminders',
    'kTCCServicePhotos',
    'kTCCServiceMediaLibrary',
    'kTCCServiceBluetoothAlways',
    'kTCCServiceMotion',
    'kTCCServiceWillow',
    'kTCCServiceExposureNotification',
    'kTCCServiceCamera',
    'kTCCServiceMicrophone',
    'kTCCServiceUserTracking',
] as const;
/** An ID of a known permission on iOS. */
export type IosPermission = (typeof iosPermissions)[number];
