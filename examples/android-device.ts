/* eslint-disable no-console */
import { parseAppMeta, pause, platformApi } from '../src/index';

// You can pass the following command line arguments:
// `npx tsx examples/android-device.ts <app ID> <app path> <CA cert path?>`

(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'device',
        capabilities: ['root', 'frida', 'certificate-pinning-bypass'],
    });

    const appId = process.argv[2] || 'de.hafas.android.db';
    const appPath = process.argv[3] || '/path/to/app-files';
    const caCertPath = process.argv[4];

    await android.ensureDevice();

    if (caCertPath) await android.installCertificateAuthority(caCertPath);

    await android.setClipboard('I copied this.');

    const appMeta = await parseAppMeta(`${appPath}/${appId}/${appId}.apk`);
    if (!appMeta) throw new Error('Invalid app.');
    console.log('App:', appMeta.id, '@', appMeta.version);

    await android.installApp(`${appPath}/${appId}/*.apk`);
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

    if (caCertPath) await android.removeCertificateAuthority(caCertPath);
})();
/* eslint-enable no-console */
