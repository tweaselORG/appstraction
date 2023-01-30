/* eslint-disable no-console */
import { platformApi } from '../src/index';

(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'emulator',
        targetOptions: {
            fridaPsPath: '~/.local/bin/frida-ps',
            objectionPath: '~/.local/bin/objection',
            snapshotName: 'your-snapshot',
        },
    });

    const appId = 'de.hafas.android.db';
    const appPath = '/path/to/app-files';

    await android.ensureDevice();
    await android.resetDevice();

    await android.setClipboard('I copied this');

    const version = await android.getAppVersion(`${appPath}/${appId}/${appId}.apk`);
    console.log('App version:', version);

    await android.installApp(`${appPath}/${appId}/*.apk`);
    await android.setAppPermissions(appId);
    await android.startApp(appId);

    const prefs = await android.getPrefs(appId);
    console.log(prefs);

    await android.clearStuckModals();
    await android.uninstallApp(appId);
})();
/* eslint-enable no-console */
