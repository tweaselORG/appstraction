/* eslint-disable no-console */
import { homedir } from 'os';
import { join } from 'path';
import { pause, platformApi } from '../src/index';

// You can pass the following command line arguments:
// `npx tsx examples/android-device.ts <app ID> <app path>`

(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'device',
        capabilities: ['frida', 'certificate-pinning-bypass'],
        targetOptions: {
            fridaPsPath: join(homedir(), '.local/bin/frida-ps'),
            objectionPath: join(homedir(), '.local/bin/objection'),
        },
    });

    const appId = process.argv[2] || 'de.hafas.android.db';
    const appPath = process.argv[3] || '/path/to/app-files';

    await android.ensureDevice();

    await android.setClipboard('I copied this.');

    const id = await android.getAppId(`${appPath}/${appId}/${appId}.apk`);
    const version = await android.getAppVersion(`${appPath}/${appId}/${appId}.apk`);
    console.log('App:', id, '@', version);

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
})();
/* eslint-enable no-console */
