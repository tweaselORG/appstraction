/* eslint-disable no-console */
import { parseAppMeta, pause, platformApi } from '../src/index';

// You can pass the following command line arguments:
// `npx tsx examples/ios-device.ts <ip> <app path> <CA cert path?> <proxy host?> <proxy port?>`

(async () => {
    const ios = platformApi({
        platform: 'ios',
        runTarget: 'device',
        capabilities: ['frida', 'ssh'],
        targetOptions: {
            ip: process.argv[2] || '0.0.0.0',
        },
    });

    const appPath = process.argv[3] || '/path/to/app-files';
    const caCertPath = process.argv[4];
    const proxyHost = process.argv[5];
    const proxyPort = process.argv[6];

    await ios.ensureDevice();

    if (caCertPath) {
        await ios.installCertificateAuthority(caCertPath);
        console.log(
            'Installed CA. Note that it will currently not be automatically trusted unless you have manually trusted any user CA at least once before.'
        );
    }
    if (proxyHost && proxyPort) await ios.setProxy({ host: proxyHost, port: +proxyPort });

    await ios.setClipboard('I copied this.');

    const appMeta = await parseAppMeta(appPath);
    if (!appMeta) throw new Error('Invalid app.');
    const appId = appMeta.id;
    console.log('App:', appId, '@', appMeta.version);

    await ios.installApp(appPath);
    // First, grant all permissions.
    await ios.setAppPermissions(appId);
    // Then, revoke the camera permission and unset the calendar permission.
    await ios.setAppPermissions(appId, { kTCCServiceCamera: 'deny', kTCCServiceCalendar: 'unset' });
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

    if (proxyHost && proxyPort) await ios.setProxy(null);
    if (caCertPath) await ios.removeCertificateAuthority(caCertPath);
})();
/* eslint-enable no-console */
