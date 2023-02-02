# appstraction

> An abstraction layer for common instrumentation functions (e.g. installing and starting apps, setting preferences, etc.) on Android and iOS.

Appstraction provides an abstraction layer for common instrumentation functions on mobile platforms, specifically Android and iOS. This includes installing, uninstalling, and starting apps, managing their permissions, but also managing devices, like resetting to snapshots, setting the clipboard content, etc. Appstraction is built primarily for use in mobile privacy research, but can be used for other purposes as well.

## Installation

You can install appstraction using yarn or npm:

```sh
yarn add appstraction
# or `npm i appstraction`
```

For full capabilities, you also need to install [frida-tools](https://frida.re/docs/installation/) and [objection](https://github.com/sensepost/objection).
You can get the paths to the binaries after installation using `whereis frida-ps`.

For Android, you also need the [Android command line tools](https://developer.android.com/studio/command-line/) installed (the best way to do this is to install [Android Studio](https://developer.android.com/studio)) and included in the `PATH` of the shell in which you are running appstraction, e.g. by including something like this in you `.zshrc`/`.bashrc`:

```sh
# Android SDK
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/build-tools/33.0.0:$ANDROID_HOME/cmdline-tools/latest/bin/:$ANDROID_HOME/emulator"
```

## Supported targets

| Platform  | Target | Tested versions |
| --- | --- | --- |
| Android  | Emulator  | 11 (API level 30), 13 (API level 33) |

## Device preparation

You can only run one device at a time with the current version.

### Android emulator

Some of the functions in appstraction work without any special preparation. You can create the emulator using Android Studio or the command line tools, e.g. like this to create an emulator with Google APIs running Android 13 (API level 33)—we recommend using x86_64 as the architecture (you can still [run ARM apps if you use Android 11 or newer](https://android-developers.googleblog.com/2020/03/run-arm-apps-on-android-emulator.html)):

```sh
# Fetch the system image.
sdkmanager "system-images;android-33;google_apis;x86_64"
# Create the emulator.
avdmanager create avd --abi google_apis/x86_64 --package "system-images;android-33;google_apis;x86_64" --device "pixel_4" --name "<emulator name>"

# Start the emulator (you can also use a different storage size).
emulator -avd "<emulator name>" -partition-size 8192 -wipe-data
```

On subsequent runs, don't include the `-partition-size 8192 -wipe-data` flags, i.e. run:

```sh
emulator -avd "<emulator name>"
```

Some functions require Frida. If you want to use them, you need to [set up Frida](https://frida.re/docs/android/) on the emulator (make sure that the version you're installing matches the version of the Frida tools you're using):

```sh
adb root

adb shell getprop ro.product.cpu.abi # should be x86_64
wget https://github.com/frida/frida/releases/download/16.0.8/frida-server-16.0.8-android-x86_64.xz 
unxz frida-server-16.0.8-android-x86_64.xz

adb push frida-server-16.0.8-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 777 /data/local/tmp/frida-server

# Test that Frida is working. You don't need to start Frida manually in later runs, appstraction will do that for you.
adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
frida-ps -U | grep frida # should have `frida-server`
```

After you have set up the emulator to your liking, you should create a snapshot to later be able to reset the emulator to this state:

```sh
adb emu avd snapshot save "<snapshot name>" # Specify this name in `targetOptions.snapshotName`.
```

## API reference

A full API reference can be found in the [`docs` folder](/docs/README.md).

## Example usage

The following example shows how to reset an Android emulator and then install an app on it:

```ts
import { platformApi } from 'appstraction';

(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'emulator',
        capabilities: [],
        targetOptions: {
            snapshotName: '<snapshot name>',
        },
    });
    
    await android.ensureDevice();
    await android.resetDevice();
    await android.installApp('</path/to/app/files/*.apk>');
})();
```

This example didn't need any capabilities. Resetting the emulator and installing apps can both be done in any emulator, without the need for any special preparation.

Other functions do need capabilities, though, which you would pass to the `capabilities` array in the `targetOptions`. For example, reading the `SharedPreferences` requires the `frida` capability (and you need to set up Frida as described above). And for starting an app, you can optionally pass the `certificate-pinning-bypass`, which will use objection to try and bypass any certificate pinning the app may use.

```ts
(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'emulator',
        capabilities: ['frida', 'certificate-pinning-bypass'],
        targetOptions: {
            fridaPsPath: '</path/to/frida-ps>',
            objectionPath: '</path/to/objection>',
            snapshotName: '<snapshot name>',
        },
    });

    await android.ensureDevice();
    await android.startApp('<app id>');
    const prefs = await android.getPrefs('<app id>');
    console.log(prefs);
})();
```

For more examples, also look at the [`examples`](examples) folder.

## License

This code is licensed under the MIT license, see the [`LICENSE`](LICENSE) file for details. Appstraction builds on [baltpeter/thesis-mobile-consent-dialogs](https://github.com/baltpeter/thesis-mobile-consent-dialogs).

Issues and pull requests are welcome! Please be aware that by contributing, you agree for your work to be licensed under an MIT license.
