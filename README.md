# appstraction

> An abstraction layer for common instrumentation functions (e.g. installing and starting apps, setting preferences, etc.) on Android and iOS.

Appstraction provides an abstraction layer for common instrumentation functions on mobile platforms, specifically Android and iOS. This includes installing, uninstalling, and starting apps, managing their permissions, but also managing devices, like resetting to snapshots, setting the clipboard content, configuring the proxy, etc. Appstraction is built primarily for use in mobile privacy research, but can be used for other purposes as well.

## Features

With appstraction, you can perform the following actions programmatically on Android and iOS (for a full list with additional details, see the API reference for the [`PlatformApi` type](docs/README.md#platformapi)):

* Reset an emulator to a snapshot.
* Install and uninstall apps, including split APKs and `.obb`s, apps downloaded from popular unofficial APK mirror sites (`.xapk` by APKPure, `.apkm` by APKMirror), and `.apks` files created by SAI on Android.
* Check whether an app is installed.
* Set an app's permissions, either granting everything or granularly specifying which permissions to grant or deny.
* Configure an app's battery optimization settings.
* Start and stop apps.
* Find the app ID of the app that is currently in the foreground.
* Get the PID of an app by its app ID if it is currently running.
* Fetch an app's preferences (`SharedPreferences` on Android, `NSUserDefaults` on iOS) as JSON.
* Get various device attributes (like OS version, device manufacturer and model, or IDFV on iOS).
* Set the clipboard content.
* Get metadata (app ID, display name, version, architectures) for an app file (`.apk` on Android, `.ipa` on iOS).
* Install and remove root certificate authorities.
* Configure the proxy settings, optionally using WireGuard instead of a regular proxy. WireGuard is automatically installed and configured on the device if enabled.
* Place honeypot data on the device, such as contacts, events, and the device name.

Appstraction is written in TypeScript and provides comprehensive type definitions to make development easy.

## Installation

Make sure you have an up-to-date version of [Node.js](https://nodejs.org) installed. We require and test against v18. You can install that using [nvm](https://github.com/nvm-sh/nvm) or [via your OS’s package manager](https://nodejs.dev/en/download/package-manager/).

Then, you can install appstraction using yarn or npm:

```sh
yarn add appstraction
# or `npm i appstraction`
```

Additionally, you will need to [prepare the target device/emulator](#device-preparation) and install a few dependencies on the host machine. You need to have those in your `PATH`.

### Host dependencies for Android

If you want to work with physical devices, [some setup may be necessary depending on your system](https://developer.android.com/studio/run/device#setting-up). On Ubuntu, you need to be a member of the `plugdev` group (`sudo usermod -aG plugdev <username>`) and have `udev` rules for your device (`sudo apt install android-sdk-platform-tools-common`). For other distributions, see [android-udev-rules](https://github.com/M0Rf30/android-udev-rules).

### Host dependencies for iOS

On Windows, you will need the Apple Device Driver and the Apple Application Support service. You can get those by installing iTunes.

## Supported targets

Appstraction supports the following targets. Note that it will likely also work on other versions of the targets, but these are the ones we have tested.

| Platform | Target | Tested versions |
| --- | --- | --- |
| Android | `device` | 13 (API level 33) |
| Android | `emulator` | 11 (API level 30), 13 (API level 33) |
| iOS | `device` | 15.6.1, 16.0 |

## Device preparation

You can only run one device at a time with the current version.

### Physical Android device

To use appstraction with a physical Android device, you need to enable USB debugging. You can do this by going to Settings -> System -> Developer options -> USB debugging.

Most functions require the device to be rooted. The steps to do this vary depending on the device. We recommend using [Magisk](https://topjohnwu.github.io/Magisk/). After you have rooted the device, you need to allow `com.android.shell` to use super user privileges in Magisk. You can do this in the Magisk app and will be asked to do so the first time you run an analysis. Alternatively, you can also enable rooted debugging via Settings -> System -> Developer options -> Rooted debugging. However, this might not be available to you, depending on the distributuion of Android you run. Stock Android generally does not allow rooted debugging in production builds.

### Android emulator

Appstraction doesn't require any special preparation in an emulator. You can create the emulator using the Device Manager in [Android Studio](https://developer.android.com/studio) or using [our CLI](https://github.com/tweaselORG/cli)—we recommend using x86_64 as the architecture (you can still [run ARM apps if you use Android 11](https://android-developers.googleblog.com/2020/03/run-arm-apps-on-android-emulator.html)):

```sh
tweasel android-emulator:create "<emulator name>"
```

You can then start the emulator like this, for example if you want to place honey data on it:

```sh
tweasel android-emulator:start "<emulator name>"
```

After you have set up the emulator to your liking, you should create a snapshot to later be able to reset the emulator to this state:

```sh
tweasel android-emulator:snapshot:create "<snapshot name>" # You can later use this name with the `resetDevice` function.
```

### Physical iOS device

Installing and uninstalling apps and querying the metadata of an IPA file work without any preparation on a physical iOS device.

For everything else, the iOS device needs to be jailbroken. For iOS 15 and 16, we have tested [palera1n](https://github.com/palera1n/palera1n) in the **rootful mode**. To jailbreak using palera1n, follow [this guide](https://ios.cfw.guide/installing-palera1n/), but then install the jailbreak with `palera1n -fc` to enable the rootful mode and start the iPhone with `palera1n -f` subsequently.
For iOS 14, we have previously successfully used [checkra1n](https://checkra.in/) for other projects, but we have not tested appstraction on iOS 14 (as we don't have a device running iOS 14).

Depending on the capabilities and features you want to use, the following packages from Cydia/Sileo need to be installed:

* [OpenSSH](sileo://package/openssh) (for the `ssh` capability)
* [SQLite 3.x](sileo://package/sqlite3) (if you want to set app permissions)
* [Frida](sileo://package/re.frida.server) version 16.0.11 or greater (for the `frida` capability), you will need to [add the Frida repository to Cydia/Sileo](https://frida.re/docs/ios/#with-jailbreak): `https://build.frida.re`
* [Open](http://cydia.saurik.com/package/com.conradkramer.open/) (if you want to launch apps without the `frida` capability), you will need to add a legacy Cydia repository if you are using Sileo: `https://apt.thebigboss.org/repofiles/cydia/`
* [SSL Kill Switch 2](https://julioverne.github.io/description.html?id=com.julioverne.sslkillswitch2) (for the `certificate-pinning-bypass` capability). Note that this will permanently disable certificate pinning globally, until you uninstall it.

They are installed automatically for each necessary capability if the `ssh` capability is available (meaning all you need to do is set up OpenSSH, allowing root login, and appstraction will do the rest).

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

Note how the first function we call after constructing the API object is `ensureDevice()`. This is important. This function will assert that the device is connected and ready to be used with the selected capabilities. It will also automatically perform various necessary setup steps for you.

This example didn't need any capabilities. Resetting the emulator and installing apps can both be done in any emulator, without the need for any special preparation.

Other functions do need capabilities, though, which you would pass to the `capabilities` array in the options. For example, reading the `SharedPreferences` requires the `frida` capability. And for starting an app, you can optionally pass the `certificate-pinning-bypass`, which will use [httptoolkit/frida-android-unpinning](https://github.com/httptoolkit/frida-android-unpinning) to try and bypass any certificate pinning the app may use.

```ts
(async () => {
    const android = platformApi({
        platform: 'android',
        runTarget: 'emulator',
        capabilities: ['frida', 'certificate-pinning-bypass'],
    });

    // Wait until the emulator is completely booted.
    await android.waitForDevice();
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
