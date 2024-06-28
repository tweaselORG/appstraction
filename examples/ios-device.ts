/* eslint-disable no-console */
import { parseAppMeta, pause, platformApi } from '../src/index';

// You can pass the following command line arguments:
// `npx tsx examples/ios-device.ts <app path> <CA cert path?> <proxy host?> <proxy port?>`

(async () => {
    const ios = platformApi({
        platform: 'ios',
        runTarget: 'device',
        capabilities: ['frida', 'ssh', 'certificate-pinning-bypass'],
    });

    const appPath = process.argv[2] || '/path/to/app-files';
    const caCertPath = process.argv[3];
    const proxyHost = process.argv[4];
    const proxyPort = process.argv[5];

    await ios.ensureDevice();

    const osVersion = await ios.getDeviceAttribute('osVersion');
    console.log('OS version:', osVersion);

    const installedApps = await ios.listApps();
    console.log('Installed apps:', installedApps);

    if (caCertPath) {
        await ios.installCertificateAuthority(caCertPath);
        console.log(
            'Installed CA. Note that it will currently not be automatically trusted unless you have manually trusted any user CA at least once before.'
        );
    }
    if (proxyHost && proxyPort) await ios.setProxy({ host: proxyHost, port: +proxyPort });

    await ios.setClipboard('I copied this.');
    await ios.addCalendarEvent({
        title: 'Secret meeting',
        startDate: new Date('2024-01-01T12:00:00'),
        endDate: new Date('2024-01-01T12:12:00'),
    });
    await ios.addContact({
        lastName: 'Doe',
        firstName: 'Kim',
        email: 'kim.doe@example.org',
        phoneNumber: '0123456789',
    });
    await ios.setDeviceName('honeypotdontcopy');

    const appMeta = await parseAppMeta(appPath as `${string}.ipa`);
    if (!appMeta) throw new Error('Invalid app.');
    const appId = appMeta.id;
    console.log('App:', appId, '@', appMeta.version);

    console.log('Installed already?', await ios.isAppInstalled(appId));

    await ios.installApp(appPath as `${string}.ipa`);
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
