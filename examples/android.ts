/* eslint-disable no-console */
import { homedir } from 'os';
import { join } from 'path';
import { pause, platformApi } from '../src/index';

// You can pass the following command line arguments:
// `npx tsm examples/android.ts <app ID> <app path> <snapshot name>`

(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'emulator',
        targetOptions: {
            fridaPsPath: join(homedir(), '.local/bin/frida-ps'),
            objectionPath: join(homedir(), '.local/bin/objection'),
            snapshotName: process.argv[4] || 'your-snapshot',
        },
    });

    const appId = process.argv[2] || 'de.hafas.android.db';
    const appPath = process.argv[3] || '/path/to/app-files';

    await android.ensureDevice();
    await android.resetDevice();

    await android.setClipboard('I copied this.');

    const version = await android.getAppVersion(`${appPath}/${appId}/${appId}.apk`);
    console.log('App version:', version);

    await android.installApp(`${appPath}/${appId}/*.apk`);
    await android.setAppPermissions(appId);
    await android.startApp(appId);

    // Give the app some time to start.
    await pause(5000);

    const prefs = await android.getPrefs(appId);
    console.log(prefs);

    await android.clearStuckModals();
    await android.uninstallApp(appId);
})();
/* eslint-enable no-console */
