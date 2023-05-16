import { decompress as decompressXz } from '@napi-rs/lzma/xz';
import { runAndroidDevTool } from 'andromatic';
import fetch from 'cross-fetch';
import { execa } from 'execa';
import { fileTypeFromFile } from 'file-type';
import frida from 'frida';
import { open, rm, writeFile } from 'fs/promises';
import pRetry from 'p-retry';
import { basename } from 'path';
import { major as semverMajor, minVersion as semverMinVersion } from 'semver';
import { temporaryFile } from 'tempy';
import type {
    PlatformApi,
    PlatformApiOptions,
    Proxy,
    SupportedCapability,
    SupportedRunTarget,
    WireGuardConfig,
} from '.';
import { dependencies } from '../package.json';
import type { ParametersExceptFirst, XapkManifest } from './util';
import {
    asyncUnimplemented,
    forEachInZip,
    getFileFromZip,
    getObjFromFridaScript,
    isRecord,
    parseAppMeta,
    retryCondition,
    tmpFileFromZipEntry,
} from './util';

const adb = (...args: ParametersExceptFirst<typeof runAndroidDevTool>) => runAndroidDevTool('adb', args[0], args[1]);

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
): PlatformApi<'android', 'device' | 'emulator', SupportedCapability<'android'>[]> => ({
    target: { platform: 'android', runTarget: options.runTarget },
    _internal: {
        objectionProcesses: [],
        async ensureFrida() {
            if (!options.capabilities.includes('frida')) return;

            // Ensure that the correct version of `frida-tools` is installed for our Frida JS bindings.
            if (!dependencies.frida) throw new Error('Frida dependency not found. This should never happen.');
            const { stdout: fridaToolsVersion } = await execa('frida', ['--version']);
            const fridaToolsMajorVersion = semverMajor(fridaToolsVersion);
            // `dependencies.frida` is not a specific version but a range, so we get the minimum possible version.
            const fridaJsMajorVersion = semverMinVersion(dependencies.frida)?.major;
            if (fridaToolsMajorVersion !== fridaJsMajorVersion)
                throw new Error(
                    `frida-tools major version (${fridaToolsMajorVersion}) does not match version of the Frida JS bindings (${fridaJsMajorVersion}). You need to install version ${fridaJsMajorVersion} of frida-tools.`
                );

            // Check whether `frida-server` is already installed on the device and has the correct major version.
            const { stdout: fridaServerVersion } = await adb(['shell', '/data/local/tmp/frida-server --version'], {
                reject: false,
            });
            const fridaServerMajorVersion = fridaServerVersion && semverMajor(fridaServerVersion);

            // Download and install `frida-server` if necessary.
            if (fridaServerMajorVersion !== fridaJsMajorVersion) {
                const releaseMeta = await fetch(
                    `https://api.github.com/repos/frida/frida/releases/tags/${fridaToolsVersion}`
                ).then((r) => r.json());
                if (releaseMeta.message === 'Not Found')
                    throw new Error(
                        `No frida-server found for version ${fridaToolsVersion}. Please install frida-server manually.`
                    );

                const { stdout: androidArch } = await adb(['shell', 'getprop', 'ro.product.cpu.abi']);
                const archMap = {
                    'arm64-v8a': 'arm64',
                    'armeabi-v7a': 'arm',
                    armeabi: 'arm',
                    // eslint-disable-next-line camelcase
                    x86_64: 'x86_64',
                    x86: 'x86',
                };
                const fridaArch = archMap[androidArch as keyof typeof archMap];
                if (!fridaArch)
                    throw new Error(
                        `Unsupported architecture: "${androidArch}". Please install frida-server manually.`
                    );

                const asset = (releaseMeta.assets as { name: string; browser_download_url: string }[]).find((a) =>
                    a.name.match(new RegExp(`frida-server-.+-android-${fridaArch}\\.xz`))
                );
                if (!asset)
                    throw new Error(
                        `No frida-server found for architecture "${fridaArch}". Please install frida-server manually.`
                    );

                const fridaServerTmpPath = temporaryFile();
                const fridaServerXz = await fetch(asset.browser_download_url).then((res) => res.arrayBuffer());
                const fridaServerBinary = await decompressXz(Buffer.from(fridaServerXz));
                await writeFile(fridaServerTmpPath, Buffer.from(fridaServerBinary));

                await adb(['push', fridaServerTmpPath, '/data/local/tmp/frida-server']);
                await adb(['shell', 'chmod', '755', '/data/local/tmp/frida-server']);

                const { stdout: installedFridaServerVersion } = await adb(
                    ['shell', '/data/local/tmp/frida-server --version'],
                    { reject: false }
                );
                if (installedFridaServerVersion !== fridaToolsVersion)
                    throw new Error(`Failed to install frida-server. Please install frida-server manually.`);
            }

            // Start `frida-server` if it's not already running.
            const { stdout: fridaCheck } = await execa('frida-ps', ['-U'], { reject: false });
            if (fridaCheck.includes('frida-server')) return;

            await this.requireRoot('Frida');

            await adb(['shell', 'chmod', '755', '/data/local/tmp/frida-server']);
            await adb(['shell', '-x', '/data/local/tmp/frida-server', '--daemonize']);

            const fridaIsStarted = await retryCondition(
                async () => (await execa('frida-ps', ['-U'], { reject: false })).stdout.includes('frida-server'),
                100
            );
            if (!fridaIsStarted) throw new Error('Failed to start Frida.');
        },
        async hasDeviceBooted(options) {
            const waitForDevice = options?.waitForDevice ?? false;
            const { stdout: devBootcomplete } = await adb(
                [...(waitForDevice ? ['wait-for-device'] : []), 'shell', 'getprop', 'dev.bootcomplete'],
                { reject: false, timeout: 200 }
            );
            const { stdout: sysBootCompleted } = await adb(
                [...(waitForDevice ? ['wait-for-device'] : []), 'shell', 'getprop', 'sys.boot_completed'],
                { reject: false, timeout: 200 }
            );
            const { stdout: bootanim } = await adb(
                [...(waitForDevice ? ['wait-for-device'] : []), 'shell', 'getprop', 'init.svc.bootanim'],
                { reject: false, timeout: 200 }
            );
            return devBootcomplete.includes('1') && sysBootCompleted.includes('1') && bootanim.includes('stopped');
        },
        async requireRoot(action) {
            if (!options.capabilities.includes('root')) throw new Error(`Root access is required for ${action}.`);

            await adb(['root']);
            await adb(['wait-for-device'], { timeout: 2500 }).catch((e) => {
                throw new Error('Failed to require root: Timed out waiting for device.', { cause: e });
            });
        },

        getCertificateSubjectHashOld: (path: string) =>
            execa('openssl', ['x509', '-inform', 'PEM', '-subject_hash_old', '-in', path]).then(
                // The `trim()` is necessary for Windows:
                // https://github.com/tweaselORG/meta/issues/25#issuecomment-1507665763
                ({ stdout }) => stdout.split('\n')[0]?.trim()
            ),
        hasCertificateAuthority: (filename) =>
            adb(['shell', 'ls', `/system/etc/security/cacerts/${filename}`], { reject: false }).then(
                ({ exitCode }) => exitCode === 0
            ),
        overlayTmpfs: async (directoryPath) => {
            const isTmpfsAlready = (await adb(['shell', 'mount'])).stdout
                .split('\n')
                .some((line) => line.includes(directoryPath) && line.includes('type tmpfs'));
            if (isTmpfsAlready) return;

            await adb(['shell', 'mkdir', '-pm', '600', '/data/local/tmp/appstraction-overlay-tmpfs-tmp']);
            await adb([
                'shell',
                'cp',
                '--preserve=all',
                `${directoryPath}/*`,
                '/data/local/tmp/appstraction-overlay-tmpfs-tmp',
            ]);

            await adb(['shell', 'mount', '-t', 'tmpfs', 'tmpfs', directoryPath]);
            await adb([
                'shell',
                'cp',
                '--preserve=all',
                '/data/local/tmp/appstraction-overlay-tmpfs-tmp/*',
                directoryPath,
            ]);

            await adb(['shell', 'rm', '-r', '/data/local/tmp/appstraction-overlay-tmpfs-tmp']);
        },

        // Note that this is only a fairly crude check, cf.
        // https://github.com/tweaselORG/meta/issues/19#issuecomment-1446285561.
        isVpnEnabled: async () => (await adb(['shell', 'ifconfig', 'tun0'], { reject: false })).exitCode === 0,
        installMultiApk: async (apks: string[]) => {
            const apkMeta = await Promise.all(
                apks.map((path) =>
                    parseAppMeta(path as `${string}.apk`).then((m) => {
                        if (!m) throw new Error(`Failed to install app: "${path}" is not a valid APK.`);
                        return { path, ...m };
                    })
                )
            );

            const appIds = new Set(apkMeta.map((m) => m.id));
            if (appIds.size > 1) throw new Error('Failed to install app: Split APKs for different apps provided.');

            const androidArches = await adb(['shell', 'getprop', 'ro.product.cpu.abilist']).then((r) =>
                r.stdout.split(',')
            );
            const androidArchMap = {
                'armeabi-v7a': 'arm',
                armeabi: 'arm',
                'arm64-v8a': 'arm64',
                x86: 'x86',
                // eslint-disable-next-line camelcase
                x86_64: 'x86_64',
                mips: 'mips',
                mips64: 'mips64',
            } as const;
            const arches = androidArches.map((a) => androidArchMap[a as keyof typeof androidArchMap]);

            const apksForArches = apkMeta
                .filter(
                    (m) =>
                        !m.architectures ||
                        m.architectures.length === 0 ||
                        m.architectures.some((a) => arches.includes(a))
                )
                .map((m) => m.path);

            if (apksForArches.length === 0)
                throw new Error(
                    `Failed to install app: App doesn't support device's architectures (${androidArches}).`
                );

            await adb(['install-multiple', ...apksForArches]);
            return appIds.values().next().value;
        },
    },

    async waitForDevice(tries = 20) {
        if (
            !(await retryCondition(() => this._internal.hasDeviceBooted({ waitForDevice: true }), tries, 100).catch(
                (e) => {
                    throw new Error('Failed to wait for device: Error in adb', { cause: e });
                }
            ))
        )
            throw new Error('Failed to wait for device: No booted device found after timeout.');
    },
    async resetDevice(snapshotName) {
        if (options.runTarget !== 'emulator') throw new Error('Resetting devices is only supported for emulators.');

        // Annoyingly, this command doesn't return a non-zero exit code if it fails (e.g. if the snapshot doesn't
        // exist). It only prints to stdout (not even stderr -.-).
        const { stdout } = await adb(['emu', 'avd', 'snapshot', 'load', snapshotName]);
        if (stdout.includes('KO')) throw new Error(`Failed to load snapshot: ${stdout}.`);

        await this.ensureDevice();
    },
    async ensureDevice() {
        if (
            !(await this._internal.hasDeviceBooted().catch((e) => {
                throw new Error('Failed to look for device: Error in adb', { cause: e });
            }))
        )
            throw new Error(
                options.runTarget === 'device' ? 'You need to connect your device.' : 'You need to start the emulator.'
            );

        await pRetry(() => this._internal.ensureFrida());

        if (options.capabilities.includes('wireguard')) {
            // Install app if necessary.
            if (!(await this.isAppInstalled('com.wireguard.android'))) {
                try {
                    const fdroidMeta = await fetch('https://f-droid.org/api/v1/packages/com.wireguard.android').then(
                        (res) => res.json()
                    );
                    const apkUrl = `https://f-droid.org/repo/com.wireguard.android_${fdroidMeta.suggestedVersionCode}.apk`;

                    // `adb` complains if we try to install a file with the wrong extension.
                    const apkTmpPath = temporaryFile({ extension: 'apk' }) as `${string}.apk`;
                    const apk = await fetch(apkUrl).then((res) => res.arrayBuffer());
                    await writeFile(apkTmpPath, Buffer.from(apk));

                    await this.installApp(apkTmpPath);

                    // It doesn't matter if this fails, the OS will clean up the file eventually.
                    // eslint-disable-next-line @typescript-eslint/no-empty-function
                    await rm(apkTmpPath).catch(() => {});
                } catch (err) {
                    throw new Error(
                        'Failed to automatically install WireGuard app. Try again or install it manually.',
                        { cause: err }
                    );
                }
            }

            // Enable remote control in config if necessary.
            const remoteControlEnabled = async () => {
                const { stdout: config } = await adb(
                    ['shell', 'cat /data/data/com.wireguard.android/files/datastore/settings.preferences_pb'],
                    { reject: false }
                );
                return config.includes('allow_remote_control_intents\u0012\u0002\b\u0001');
            };

            if (!(await remoteControlEnabled())) {
                try {
                    this._internal.requireRoot('configuring WireGuard in ensureDevice()');

                    // This is the default config of version v1.0.20220516, but with remote control enabled.
                    const config =
                        '\n\u0015\n\u000frestore_on_boot\u0012\u0002\b\u0000\n\u0010\n\ndark_theme\u0012\u0002\b\u0000\n\u0016\n\u0010multiple_tunnels\u0012\u0002\b\u0000\n"\n\u001callow_remote_control_intents\u0012\u0002\b\u0001';
                    const configAsBase64 = Buffer.from(config).toString('base64');

                    const { stdout: appUser } = await adb([
                        'shell',
                        'stat',
                        '-c',
                        '%U',
                        '/data/data/com.wireguard.android',
                    ]);
                    await adb([
                        'shell',
                        'su',
                        appUser,
                        '/bin/sh',
                        '-c',
                        '"mkdir -p /data/data/com.wireguard.android/files/datastore"',
                    ]);
                    await adb([
                        'shell',
                        'su',
                        appUser,
                        '/bin/sh',
                        '-c',
                        `"echo -n '${configAsBase64}' | base64 -d > /data/data/com.wireguard.android/files/datastore/settings.preferences_pb"`,
                    ]);

                    if (!(await remoteControlEnabled()))
                        throw new Error('Remote control not enabled after writing config.');
                } catch (err) {
                    throw new Error(
                        'Failed to automatically configure the WireGuard app. Try again or manually enable "Allow remote control apps" under "Advanced" in the app\'s settings.',
                        { cause: err }
                    );
                }
            }

            await adb(['shell', 'cmd', 'appops', 'set', 'com.wireguard.android', 'ACTIVATE_VPN', 'allow']);
        }
    },
    clearStuckModals: async () => {
        // Press back button.
        await adb(['shell', 'input', 'keyevent', '4']);
        // Press home button.
        await adb(['shell', 'input', 'keyevent', '3']);
    },

    isAppInstalled: async (appId) => {
        const { stdout } = await adb(['shell', 'cmd', 'package', 'list', 'packages', appId]);
        return stdout.includes(`package:${appId}`);
    },
    async installApp(apkPath, obbPaths) {
        let appId = '';
        if (typeof apkPath === 'string' && apkPath.endsWith('.xapk')) {
            const xapk = await open(apkPath);
            await getFileFromZip(xapk, 'manifest.json').then(async (manifest) => {
                if (!manifest) throw new Error('Failed to install app: manifest.json not found in XAPK.');
                const manifestString = await new Promise<string>((resolve) => {
                    let result = '';
                    manifest.on('data', (chunk) => (result += chunk.toString()));
                    manifest.on('end', () => resolve(result));
                });
                const manifestJson: XapkManifest = JSON.parse(manifestString);

                const expansionFileNames = manifestJson.expansions?.map((expansion) => expansion.file);
                const apkFileNames = manifestJson.split_apks?.map((apk) => apk.file);
                const tmpApks: string[] = [];
                const externalStorageDir = (await adb(['shell', 'echo', '$EXTERNAL_STORAGE'])).stdout;
                const obbPaths: string[] = [];

                if (expansionFileNames?.length && expansionFileNames.length > 0) {
                    await this._internal.requireRoot('writing to external storage in installApp');
                }

                await forEachInZip(xapk, async (entry, zipFile) => {
                    if (apkFileNames?.includes(entry.fileName)) {
                        await tmpFileFromZipEntry(zipFile, entry, 'apk').then((tmpFile) => void tmpApks.push(tmpFile));
                    } else if (expansionFileNames?.includes(entry.fileName)) {
                        const expansion = manifestJson.expansions?.find((exp) => exp.file === entry.fileName);
                        if (expansion && expansion.install_location === 'EXTERNAL_STORAGE')
                            // Since there doesn't seem to be any public schema of XAPKs and Google explicitly says that
                            // extension files are supposed to be stored in the external storage, hardcoding this is the
                            // only way to handle this
                            // (https://github.com/tweaselORG/appstraction/issues/63#issuecomment-1514822176).
                            return tmpFileFromZipEntry(zipFile, entry).then(async (tmpFile) => {
                                await adb(['push', tmpFile, `${externalStorageDir}/${expansion.install_path}`]);
                                obbPaths.push(`${externalStorageDir}/${expansion.install_path}`);
                                await rm(tmpFile);
                            });
                        throw new Error('Failed to install app: Invalid expansion file declaration.');
                    }
                }).then(xapk.close);

                if (tmpApks.length === 0) throw new Error('Failed to install app: No split apks found in XAPK.');
                try {
                    appId = await this._internal.installMultiApk(tmpApks);
                } catch (err) {
                    await Promise.all(obbPaths.map((obbPath) => adb(['shell', 'rm', obbPath])));
                    throw err;
                }

                await Promise.all(tmpApks.map((tmpApk) => rm(tmpApk)));
            });
        } else if (typeof apkPath === 'string' && (apkPath.endsWith('.apkm') || apkPath.endsWith('.apks'))) {
            // APKM and APKS are basically the same format now, see https://github.com/tweaselORG/appstraction/issues/66
            if ((await fileTypeFromFile(apkPath))?.mime !== 'application/zip')
                throw new Error(
                    'Failed to install app: Encrypted apkm files are not supported, use the newer zip format instead.'
                );
            const apkm = await open(apkPath);
            const tmpApks: `${string}.apk`[] = [];

            await forEachInZip(apkm, async (entry, zipFile) => {
                if (entry.fileName.endsWith('.apk')) {
                    await tmpFileFromZipEntry(zipFile, entry, 'apk').then((tmpFile) => void tmpApks.push(tmpFile));
                }
            }).then(apkm.close);

            if (tmpApks.length === 0) throw new Error('Failed to install app: No split apks found in XAPK.');
            appId = await this._internal.installMultiApk(tmpApks);
            await Promise.all(tmpApks.map((tmpApk) => rm(tmpApk)));
        } else {
            appId = await this._internal.installMultiApk(typeof apkPath === 'string' ? [apkPath] : apkPath);
        }

        if (obbPaths && obbPaths.length > 0) {
            await this._internal.requireRoot('writing to external storage in installApp');
            const externalStorageDir = (await adb(['shell', 'echo', '$EXTERNAL_STORAGE'])).stdout;
            await Promise.all(
                obbPaths.map((obbPath) =>
                    adb([
                        'push',
                        obbPath.obb,
                        `${externalStorageDir}/${
                            obbPath.installPath || `Android/obb/${appId}/${basename(obbPath.obb)}`
                        }`,
                    ])
                )
            );
        }
    },
    uninstallApp: async (appId) => {
        await adb(['shell', 'pm', 'uninstall', '--user', '0', appId]).catch((err) => {
            // Don't fail if app wasn't installed.
            if (!err.stdout.includes('not installed for 0')) throw err;
        });
    },
    setAppPermissions: async (appId, _permissions) => {
        const getAllPermissions = () =>
            // The `-g` is required to also get the runtime permissions, see https://github.com/tweaselORG/appstraction/issues/15#issuecomment-1420771931.
            adb(['shell', 'pm', 'list', 'permissions', '-u', '-g'])
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
            await adb(['shell', 'pm', command, appId, permission]).catch((err) => {
                if (
                    err.exitCode === 255 &&
                    (err.stderr.includes('not a changeable permission type') ||
                        err.stderr.includes('has not requested permission') ||
                        err.stderr.includes('Unknown permission'))
                )
                    return;

                throw new Error(`Failed to set permission "${permission}".`, { cause: err });
            });
        }
    },
    setAppBackgroundBatteryUsage: async (appId, state) => {
        switch (state) {
            case 'unrestricted':
                await adb(['shell', 'cmd', 'appops', 'set', appId, 'RUN_ANY_IN_BACKGROUND', 'allow']);
                await adb(['shell', 'dumpsys', 'deviceidle', 'whitelist', `+${appId}`]);
                return;
            case 'optimized':
                await adb(['shell', 'cmd', 'appops', 'set', appId, 'RUN_ANY_IN_BACKGROUND', 'allow']);
                await adb(['shell', 'dumpsys', 'deviceidle', 'whitelist', `-${appId}`]);
                return;
            case 'restricted':
                await adb(['shell', 'cmd', 'appops', 'set', appId, 'RUN_ANY_IN_BACKGROUND', 'ignore']);
                await adb(['shell', 'dumpsys', 'deviceidle', 'whitelist', `-${appId}`]);
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

        adb(['shell', 'monkey', '-p', appId, '-v', '1', '--dbg-no-events']);
        return Promise.resolve();
    },
    stopApp: async (appId) => {
        await adb(['shell', 'am', 'force-stop', appId]);
    },

    // Adapted after: https://stackoverflow.com/a/28573364
    getForegroundAppId: async () => {
        const { stdout } = await adb(['shell', 'dumpsys', 'activity', 'recents']);
        const foregroundLine = stdout.split('\n').find((l) => l.includes('Recent #0'));
        const [, appId] = Array.from(foregroundLine?.match(/A=\d+:(.+?) U=/) || []);
        return appId ? appId.trim() : undefined;
    },
    getPidForAppId: async (appId) => {
        const { stdout } = await adb(['shell', 'pidof', '-s', appId]);
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

        await adb(['push', path, `/system/etc/security/cacerts/${certFilename}`]);
    },
    async removeCertificateAuthority(path) {
        const certFilename = `${await this._internal.getCertificateSubjectHashOld(path)}.0`;

        if (!(await this._internal.hasCertificateAuthority(certFilename))) return;

        await this._internal.requireRoot('removeCertificateAuthority');

        await this._internal.overlayTmpfs('/system/etc/security/cacerts');
        await adb(['shell', 'rm', `/system/etc/security/cacerts/${certFilename}`]);
    },
    async setProxy(_proxy) {
        // We are dealing with a WireGuard tunnel.
        if (options.capabilities.includes('wireguard')) {
            const tunnelName = 'appstraction';

            // Since we're communicating with the WireGuard app through intents, we need to disable battery
            // optimizations. Otherwise, our intents may not actually be delivered to the app.
            await this.setAppBackgroundBatteryUsage('com.wireguard.android', 'unrestricted');

            const config = _proxy as WireGuardConfig | null;

            const deleteConfig = async () => {
                await adb(['shell', 'rm', '-f', `/data/data/com.wireguard.android/files/${tunnelName}.conf`], {
                    reject: false,
                });
                // We need to restart the WireGuard app, otherwise it will still show the deleted config.
                await this.stopApp('com.wireguard.android');
            };

            if (config === null) {
                await adb([
                    'shell',
                    'am',
                    'broadcast',
                    '-a',
                    'com.wireguard.android.action.SET_TUNNEL_DOWN',
                    '-n',
                    // The quotes are necessary, otherwise `adb shell` interprets `$IntentReceiver` as a variable.
                    "'com.wireguard.android/.model.TunnelManager$IntentReceiver'",
                    '-e',
                    'tunnel',
                    tunnelName,
                ]);

                const vpnIsDisabled = await retryCondition(async () => !(await this._internal.isVpnEnabled()));
                if (!vpnIsDisabled) throw new Error('Failed to disable WireGuard tunnel.');

                // This requires root, but I don't think we should require root for disabling a tunnel. It's not really
                // a problem if the config file is left behind.
                await deleteConfig();

                return;
            }

            await this._internal.requireRoot('enabling a WireGuard tunnel');

            const { stdout: appUser } = await adb(['shell', 'stat', '-c', '%U', '/data/data/com.wireguard.android']);
            await adb([
                'shell',
                'su',
                appUser,
                '/bin/sh',
                '-c',
                `"echo -n '${config}' > /data/data/com.wireguard.android/files/${tunnelName}.conf"`,
            ]);

            // We need to restart the WireGuard app for it to recognize our new tunnel config.
            await this.stopApp('com.wireguard.android');

            await adb([
                'shell',
                'am',
                'broadcast',
                '-a',
                'com.wireguard.android.action.SET_TUNNEL_UP',
                '-n',
                // The quotes are necessary, otherwise `adb shell` interprets `$IntentReceiver` as a variable.
                "'com.wireguard.android/.model.TunnelManager$IntentReceiver'",
                '-e',
                'tunnel',
                tunnelName,
            ]);

            const vpnIsStarted = await retryCondition(() => this._internal.isVpnEnabled());
            if (!vpnIsStarted) {
                await deleteConfig();
                throw new Error('Failed to enable WireGuard tunnel.');
            }

            return;
        }

        // We are dealing with a regular global proxy.
        const proxy = _proxy as Proxy | null;

        const putSetting = (key: string, value: string) => adb(['shell', 'settings', 'put', 'global', key, value]);
        const deleteSetting = (key: string) => adb(['shell', 'settings', 'delete', 'global', key]);
        const getSetting = (key: string) => adb(['shell', 'settings', 'get', 'global', key]).then((r) => r.stdout);

        // Regardless of whether we want to set or remove the proxy, we don't want proxy auto-config to interfere.
        await deleteSetting('global_proxy_pac_url');

        if (proxy === null) {
            // Just deleting the settings only works after a reboot, this ensures that the proxy is disabled
            // immediately, see https://github.com/tweaselORG/appstraction/issues/25#issuecomment-1438813160.

            await putSetting('http_proxy', ':0');
            await deleteSetting('global_http_proxy_host');
            await putSetting('global_http_proxy_port', '0');

            // Verify that the proxy settings were set.
            if (
                (await getSetting('http_proxy')) !== ':0' ||
                (await getSetting('global_http_proxy_host')) !== 'null' ||
                (await getSetting('global_http_proxy_port')) !== '0'
            )
                throw new Error('Failed to set proxy.');

            return;
        }

        const proxyString = `${proxy.host}:${proxy.port}`;
        await putSetting('http_proxy', proxyString);
        await putSetting('global_http_proxy_host', proxy.host);
        await putSetting('global_http_proxy_port', proxy.port.toString());

        // Verify that the proxy settings were set.
        if (
            (await getSetting('http_proxy')) !== proxyString ||
            (await getSetting('global_http_proxy_host')) !== proxy.host ||
            (await getSetting('global_http_proxy_port')) !== proxy.port.toString()
        )
            throw new Error('Failed to set proxy.');
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
