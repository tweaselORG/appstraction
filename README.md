# appstraction

> A collection of scripts to interact with mobile platforms.

This is a collection of scripts to interact with mobile platforms, specifically android and iOS, first compiled in [baltpeter/thesis-mobile-consent-dialogs](https://github.com/baltpeter/thesis-mobile-consent-dialogs) for the use of instrumentation for mobile privacy research. You can use it to install, start and uninstall apps, set permissions and similar actions.

## Installation

You can install appstraction using yarn or npm:

```sh
yarn add appstraction
# or `npm i appstraction`
```

For full capability, you also need to install [frida-tools](https://frida.re/docs/installation/) and [objection](https://github.com/sensepost/objection).
You can get the paths to the binaries after installation using `whereis frida-ps`.

For Android, you also need the [Android command line tools](https://developer.android.com/studio/command-line/) installed (the best way to do this is to install [Android Studio](https://developer.android.com/studio)) and included in the `PATH` of the shell in which you are running appstraction. E.g. by including something like this in you `.zshrc`/`.bashrc`:

```zsh
# Android SDK
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/build-tools/33.0.0:$ANDROID_HOME/cmdline-tools/latest/bin/:$ANDROID_HOME/emulator"
```

## Supported Targets

| Platform  | Target | Tested versions | Comment |
| --- | --- | --- | --- |
| Android  | Emulator  | API 33.0.0 | You can only run one emulator at a time. |

## Device preparation

### Android Emulator

Currently, only emulators are supported for usage with Android. You can only run one emulator at a time with the current version. For full functionality, you should properly prepare the emulator:

```zsh
# Fetch image.
sdkmanager "system-images;android-33;google_apis;x86_64"
# Create AVD.
avdmanager create avd --abi google_apis/x86_64 --device "pixel_2" --force --name "instrumented-emu" --package "system-images;android-33;google_apis;x86_64"

# Start the emulator for the first time.
emulator -avd "instrumented-emu" -no-audio -no-boot-anim -writable-system -http-proxy 127.0.0.1:8080

# Set up Frida. You can also follow the docs at https://frida.re/docs/android/
adb shell getprop ro.product.cpu.abi # should be x86_64
wget https://github.com/frida/frida/releases/download/16.0.8/frida-server-16.0.8-android-x86_64.xz 
7z x frida-server-16.0.8-linux-x86_64.xz

adb push frida-server-16.0.8-linux-x86_64 /data/local/tmp/frida-server
adb shell chmod 777 /data/local/tmp/frida-server

adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
frida-ps -U | grep frida # should have `frida-server`

# Create a snapshot to rollback to a neutral state
adb emu avd snapshot save clean-prepared # You can use this snapshot name in the options.
```

## API reference

A full API reference can be found in the [`docs` folder](/docs/README.md).

## Example usage

For more examples, also look at the `examples` folder.

```ts
// Install an app on android
import { platformApi } from 'appstraction';

const android = platformApi({
    platform: 'android',
    runTarget: 'emulator',
    targetOptions: {
        fridaPsPath: '/<path-to>/frida-ps',
        objectionPath: '/<path-to>/objection',
        snapshotName: 'your-snapshot',
    },
});

android
    .ensureDevice()
    .then(() => android.resetDevice())
    .then(() => android.installApp(`/path/to/app/files/*.apk`));
```

## License

This code is licensed under the MIT license, see the [`LICENSE`](LICENSE) file for details.

Issues and pull requests are welcome! Please be aware that by contributing, you agree for your work to be licensed under an MIT license.
