/* eslint-disable no-console */
import { homedir } from 'os';
import { join } from 'path';
import { pause, platformApi } from '../src/index';

// You can pass the following command line arguments:
// `npx tsm examples/ios-device.ts <ip> <app path>`

(async () => {
    const ios = platformApi({
        platform: 'ios',
        runTarget: 'device',
        capabilities: ['frida', 'ssh'],
        targetOptions: {
            fridaPsPath: join(homedir(), '.local/bin/frida-ps'),
            ip: process.argv[2],
        },
    });

    const appPath = process.argv[3] || '/path/to/app-files';

    await ios.ensureDevice();

    await ios.setClipboard('I copied this.');

    const appId = await ios.getAppId(appPath);
    const version = await ios.getAppVersion(appPath);
    console.log('App:', appId, '@', version);
    if (!appId) throw new Error('Invalid app.');

    await ios.installApp(appPath);
    await ios.setAppPermissions(appId);
    await ios.startApp(appId);

    // Give the app some time to start.
    await pause(5000);

    const prefs = await ios.getPrefs(appId);
    console.log(prefs);

    const idfv = await ios.getDeviceAttribute('idfv', { appId });
    console.log('IDFV:', idfv);

    // `clearStuckModals()` is currently broken on iOS (see https://github.com/tweaselORG/appstraction/issues/12).
    // await ios.clearStuckModals();
    await ios.uninstallApp(appId);
})();
/* eslint-enable no-console */
