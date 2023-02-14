# appstraction

> An abstraction layer for common instrumentation functions (e.g. installing and starting apps, setting preferences, etc.) on Android and iOS.

Appstraction provides an abstraction layer for common instrumentation functions on mobile platforms, specifically Android and iOS. This includes installing, uninstalling, and starting apps, managing their permissions, but also managing devices, like resetting to snapshots, setting the clipboard content, etc. Appstraction is built primarily for use in mobile privacy research, but can be used for other purposes as well.

## Installation

You can install appstraction using yarn or npm:

```sh
yarn add appstraction
# or `npm i appstraction`
```

Additionally, you will need to [prepare the target device/emulator](#device-preparation) and install a few dependencies on the host machine.

### Host dependencies for Android

For Android, you need the [Android command line tools](https://developer.android.com/studio/command-line/) (can also be installed through [Android Studio](https://developer.android.com/studio)). Note that these need to be included in your `PATH`, e.g. by including something like this in your `.zshrc`/`.bashrc`:

```sh
# Android SDK
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/build-tools/33.0.0:$ANDROID_HOME/cmdline-tools/latest/bin/:$ANDROID_HOME/emulator"
```

For the `frida` capability, you need to install [`frida-tools`](https://frida.re/docs/installation/).

For the `certificate-pinning-bypass` capability, you need to install [`objection`](https://github.com/sensepost/objection) in addition to `frida-tools`.

### Host dependencies for iOS

For iOS, you need [`libimobiledevice`](https://libimobiledevice.org/). The distribution packages are fine, you don't need to build from source.

For the `frida` capability, you need to install [`frida-tools`](https://frida.re/docs/installation/).

For the `ssh` capability, you need to install [`sshpass`](https://sourceforge.net/projects/sshpass).

## Supported targets

Appstraction supports the following targets. Note that it will likely also work on other versions of the targets, but these are the ones we have tested.

| Platform | Target | Tested versions |
| --- | --- | --- |
| Android | `device` | 13 (API level 33) |
| Android | `emulator` | 11 (API level 30), 13 (API level 33) |
| iOS | `device` | 15.6.1, 16.0 |

## Device preparation

You can only run one device at a time with the current version.

## Physical Android device

To use appstraction with a physical Android device, you need to enable USB debugging. You can do this by going to Settings -> System -> Developer options -> USB debugging.

Some functions require the device to be rooted. The steps to do this vary depending on the device. We recommend using [Magisk](https://topjohnwu.github.io/Magisk/). After you have rooted the device, you need to enable rooted debugging via Settings -> System -> Developer options -> Rooted debugging.

Some functions require Frida. If you want to use them, you need to [set up Frida](https://frida.re/docs/android/) on the emulator (make sure that the version you're installing matches the version of the Frida tools you're using):

```sh
adb root

# Find out the architecture of the device.
adb shell getprop ro.product.cpu.abi
# Download the correct frida-server, e.g. for ARM64:
wget https://github.com/frida/frida/releases/download/16.0.8/frida-server-16.0.8-android-arm64.xz
unxz frida-server-16.0.8-android-arm64.xz

adb push frida-server-16.0.8-android-arm64 /data/local/tmp/frida-server
adb shell chmod 777 /data/local/tmp/frida-server

# Test that Frida is working. You don't need to start Frida manually in later runs, appstraction will do that for you.
adb shell "/data/local/tmp/frida-server"
frida-ps -U | grep frida # should have `frida-server`
```

### Android emulator

Some of the functions in appstraction work without any special preparation in an emulator. You can create the emulator using Android Studio or the command line tools, e.g. like this to create an emulator with Google APIs running Android 13 (API level 33)—we recommend using x86_64 as the architecture (you can still [run ARM apps if you use Android 11 or newer](https://android-developers.googleblog.com/2020/03/run-arm-apps-on-android-emulator.html)):

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
adb shell "/data/local/tmp/frida-server"
frida-ps -U | grep frida # should have `frida-server`
```

After you have set up the emulator to your liking, you should create a snapshot to later be able to reset the emulator to this state:

```sh
adb emu avd snapshot save "<snapshot name>" # You can later use this name with the `resetDevice` function.
```

### Physical iOS device

Installing and uninstalling apps and querying the metadata of an IPA file work without any preparation on a physical iOS device.

For everything else, the iOS device needs to be jailbroken. For iOS 15 and 16, we have tested [palera1n](https://github.com/palera1n/palera1n). For iOS 14, we have previously successfully used [checkra1n](https://checkra.in/) for other projects, but we have not tested appstraction on iOS 14 (as we don't have a device running iOS 14).

Depending on the capabilities and features you want to use, you need to install the following packages from Cydia/Sileo:

* [OpenSSH](sileo://package/openssh) (for the `ssh` capability)
* [SQLite 3.x](sileo://package/sqlite3) (if you want to set app permissions)
* [Frida](sileo://package/re.frida.server) (for the `frida` capability), you will need to [add the Frida repository to Cydia/Sileo](https://frida.re/docs/ios/#with-jailbreak): `https://build.frida.re`
* [Open](http://cydia.saurik.com/package/com.conradkramer.open/) (if you want to launch apps without the `frida` capability), you will need to add a legacy Cydia repository if you are using Sileo: `https://apt.thebigboss.org/repofiles/cydia/`

You may need to respring after installing the packages.

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
        capabilities: []
    });
    
    await android.ensureDevice();
    await android.resetDevice('<snapshot name>');
    await android.installApp('</path/to/app/files/*.apk>');
})();
```

This example didn't need any capabilities. Resetting the emulator and installing apps can both be done in any emulator, without the need for any special preparation.

Other functions do need capabilities, though, which you would pass to the `capabilities` array in the options. For example, reading the `SharedPreferences` requires the `frida` capability (and you need to set up Frida as described above). And for starting an app, you can optionally pass the `certificate-pinning-bypass`, which will use objection to try and bypass any certificate pinning the app may use.

```ts
(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'emulator',
        capabilities: ['frida', 'certificate-pinning-bypass'],
        targetOptions: {
            fridaPsPath: '</path/to/frida-ps>',
            objectionPath: '</path/to/objection>'
        },
    });

    await android.ensureDevice();
    await android.startApp('<app id>');
    const prefs = await android.getPrefs('<app id>');
    console.log(prefs);
})();
```

For more examples, take a look at the [`examples`](examples) folder.

## License

This code is licensed under the MIT license, see the [`LICENSE`](LICENSE) file for details. Appstraction builds on [baltpeter/thesis-mobile-consent-dialogs](https://github.com/baltpeter/thesis-mobile-consent-dialogs).

Issues and pull requests are welcome! Please be aware that by contributing, you agree for your work to be licensed under an MIT license.
