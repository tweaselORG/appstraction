/* eslint-disable no-console */
import { platformApi } from '../dist/index.js';

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

android
    .ensureDevice()
    .then(() => android.resetDevice())
    .then(() => android.installApp(`${appPath}/${appId}/*.apk`))
    .then(() => android.getAppVersion(`${appPath}/${appId}/${appId}.apk`))
    .then((version) => console.log('App version:', version))
    .then(() => android.startApp(appId))
    .then(() => android.setAppPermissions(appId))
    .then(() => android._internal.ensureFrida())
    .then(() => android.setClipboard('I copied this'))
    .then(() => android.getPrefs(appId))
    .then((prefs) => console.log(prefs))
    .then(() => android.clearStuckModals())
    .then(() => android.uninstallApp(appId));
/* eslint-enable no-console */
