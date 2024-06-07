/* eslint-disable no-console */
import { readFile } from 'fs/promises';
import { parseAppMeta, pause, platformApi } from '../src/index';

// You can pass the following command line arguments:
// `npx tsx examples/android-emulator.ts <app ID> <app path> <snapshot name> <CA cert path?> <WireGuard config path?>`

(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'emulator',
        capabilities: ['root', 'frida', 'wireguard', 'certificate-pinning-bypass'],
    });

    const appId = process.argv[2] || 'de.hafas.android.db';
    const appPath = process.argv[3] || '/path/to/app-files';
    const snapshotName = process.argv[4] || 'your-snapshot';
    const caCertPath = process.argv[5];
    const wireguardConfigPath = process.argv[6];

    // Wait until the emulator is completely booted.
    await android.waitForDevice();

    await android.ensureDevice();
    await android.resetDevice(snapshotName);

    const osVersion = await android.getDeviceAttribute('osVersion');
    console.log('OS version:', osVersion);

    const installedApps = await android.listApps();
    console.log('Installed apps:', installedApps);

    if (caCertPath) {
        await android.removeCertificateAuthority(caCertPath);
        await android.installCertificateAuthority(caCertPath);
    }
    if (wireguardConfigPath) await android.setProxy(await readFile(wireguardConfigPath, 'utf8'));

    await android.setClipboard('I copied this.');

    const appMeta = await parseAppMeta(`${appPath}/${appId}/${appId}.apk`);
    if (!appMeta) throw new Error('Invalid app.');
    console.log('App:', appMeta.id, '@', appMeta.version);

    console.log('Installed already?', await android.isAppInstalled(appId));

    await android.installApp(`${appPath}/${appId}/${appId}.apk`);
    await android.setAppBackgroundBatteryUsage(appId, 'unrestricted');
    // First, grant all permissions.
    await android.setAppPermissions(appId);
    // Then, revoke the camera and location permissions.
    await android.setAppPermissions(appId, {
        'android.permission.CAMERA': 'deny',
        'android.permission.ACCESS_FINE_LOCATION': 'deny',
        'android.permission.ACCESS_COARSE_LOCATION': 'deny',
        'android.permission.ACCESS_BACKGROUND_LOCATION': 'deny',
    });
    await android.startApp(appId);

    // Give the app some time to start.
    await pause(5000);

    const prefs = await android.getPrefs(appId);
    console.log(prefs);

    await android.clearStuckModals();
    await android.uninstallApp(appId);

    if (wireguardConfigPath) await android.setProxy(null);
})();
/* eslint-enable no-console */
