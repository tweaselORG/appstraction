/* eslint-disable no-console */
import { parseAppMeta, pause, platformApi } from '../src/index';

// You can pass the following command line arguments:
// `npx tsx examples/android-emulator.ts <app ID> <app path> <snapshot name> <CA cert path?> <proxy host?> <proxy port?>`

(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'emulator',
        capabilities: ['root', 'frida', 'certificate-pinning-bypass'],
    });

    const appId = process.argv[2] || 'de.hafas.android.db';
    const appPath = process.argv[3] || '/path/to/app-files';
    const snapshotName = process.argv[4] || 'your-snapshot';
    const caCertPath = process.argv[5];
    const proxyHost = process.argv[6];
    const proxyPort = process.argv[7];

    await android.ensureDevice();
    await android.resetDevice(snapshotName);

    if (caCertPath) {
        await android.removeCertificateAuthority(caCertPath);
        await android.installCertificateAuthority(caCertPath);
    }
    if (proxyHost && proxyPort) await android.setProxy({ host: proxyHost, port: +proxyPort });

    await android.setClipboard('I copied this.');

    const appMeta = await parseAppMeta(`${appPath}/${appId}/${appId}.apk`);
    if (!appMeta) throw new Error('Invalid app.');
    console.log('App:', appMeta.id, '@', appMeta.version);

    await android.installApp(`${appPath}/${appId}/*.apk`);
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

    if (proxyHost && proxyPort) await android.setProxy(null);
})();
/* eslint-enable no-console */
