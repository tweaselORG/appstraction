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

```zsh
# Android SDK
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/build-tools/33.0.0:$ANDROID_HOME/cmdline-tools/latest/bin/:$ANDROID_HOME/emulator"
```

## Supported targets

| Platform  | Target | Tested versions |
| --- | --- | --- | --- |
| Android  | Emulator  | API 33.0.0 |

## Device preparation

### Android emulator

Currently, only emulators are supported for use on Android. You can only run one emulator at a time with the current version. For full functionality, you should properly prepare the emulator:

```zsh
# Fetch image.
sdkmanager "system-images;android-33;google_apis;x86_64"
# Create AVD.
avdmanager create avd --abi google_apis/x86_64 --device "pixel_2" --force --name "instrumented-emu" --package "system-images;android-33;google_apis;x86_64"

# Start the emulator for the first time.
emulator -avd "instrumented-emu" -no-audio -no-boot-anim -writable-system -http-proxy 127.0.0.1:8080

# Set up Frida, see also the official docs: https://frida.re/docs/android/
adb shell getprop ro.product.cpu.abi # should be x86_64
wget https://github.com/frida/frida/releases/download/16.0.8/frida-server-16.0.8-android-x86_64.xz 
7z x frida-server-16.0.8-linux-x86_64.xz

adb push frida-server-16.0.8-linux-x86_64 /data/local/tmp/frida-server
adb shell chmod 777 /data/local/tmp/frida-server

adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
frida-ps -U | grep frida # should have `frida-server`

# Create a snapshot to rollback to a neutral state.
adb emu avd snapshot save clean-prepared # You can use this snapshot name in the options.
```

## API reference

A full API reference can be found in the [`docs` folder](/docs/README.md).

## Example usage

The following example shows how to reset an Android emulator and then install an app on it:

```ts
import { platformApi } from 'appstraction';

const android = platformApi({
    platform: 'android',
    runTarget: 'emulator',
    targetOptions: {
        fridaPsPath: '</path/to/frida-ps>',
        objectionPath: '</path/to/objection>',
        snapshotName: '<snapshot name>',
    },
});

android
    .ensureDevice()
    .then(() => android.resetDevice())
    .then(() => android.installApp(`</path/to/app/files/*.apk>`));
```

For more examples, also look at the [`examples`](examples) folder.

## License

This code is licensed under the MIT license, see the [`LICENSE`](LICENSE) file for details. Appstraction builds on [baltpeter/thesis-mobile-consent-dialogs](https://github.com/baltpeter/thesis-mobile-consent-dialogs).

Issues and pull requests are welcome! Please be aware that by contributing, you agree for your work to be licensed under an MIT license.
