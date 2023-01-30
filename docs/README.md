appstraction

# appstraction

## Table of contents

### Type Aliases

- [DeviceAttribute](README.md#deviceattribute)
- [GetDeviceAttributeOptions](README.md#getdeviceattributeoptions)
- [PlatformApi](README.md#platformapi)
- [PlatformApiOptions](README.md#platformapioptions)
- [RunTargetOptions](README.md#runtargetoptions)
- [SupportedPlatform](README.md#supportedplatform)
- [SupportedRunTarget](README.md#supportedruntarget)

### Functions

- [platformApi](README.md#platformapi-1)

## Type Aliases

### DeviceAttribute

Ƭ **DeviceAttribute**<`Platform`\>: `Platform` extends ``"android"`` ? `never` : `Platform` extends ``"ios"`` ? ``"idfv"`` : `never`

The supported attributes for the `getDeviceAttribute()` function.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |

#### Defined in

[index.ts:170](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L170)

___

### GetDeviceAttributeOptions

Ƭ **GetDeviceAttributeOptions**: `Object`

The options for each attribute available through the `getDeviceAttribute()` function.

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `idfv` | { `appId`: `string`  } | The options for the `idfv` attribute. |
| `idfv.appId` | `string` | The app ID of the app to get the `identifierForVendor` for. |

#### Defined in

[index.ts:176](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L176)

___

### PlatformApi

Ƭ **PlatformApi**<`Platform`\>: `Object`

Functions that are available for the platforms.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |

#### Type declaration

| Name | Type |
| :------ | :------ |
| `clearStuckModals` | () => `Promise`<`void`\> |
| `ensureDevice` | () => `Promise`<`void`\> |
| `getAppVersion` | (`appPath`: `string`) => `Promise`<`string` \| `undefined`\> |
| `getDeviceAttribute` | <Attribute\>(`attribute`: `Attribute`, ...`options`: `Attribute` extends keyof [`GetDeviceAttributeOptions`](README.md#getdeviceattributeoptions) ? [options: GetDeviceAttributeOptions[Attribute]] : [options?: undefined]) => `Promise`<`string`\> |
| `getForegroundAppId` | () => `Promise`<`string` \| `undefined`\> |
| `getPidForAppId` | (`appId`: `string`) => `Promise`<`number` \| `undefined`\> |
| `getPrefs` | (`appId`: `string`) => `Promise`<`Record`<`string`, `unknown`\> \| `undefined`\> |
| `installApp` | (`appPath`: `string`) => `Promise`<`void`\> |
| `resetDevice` | () => `Promise`<`void`\> |
| `setAppPermissions` | (`appId`: `string`) => `Promise`<`void`\> |
| `setClipboard` | (`text`: `string`) => `Promise`<`void`\> |
| `startApp` | (`appId`: `string`) => `Promise`<`void`\> |
| `uninstallApp` | (`appId`: `string`) => `Promise`<`void`\> |

#### Defined in

[index.ts:16](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L16)

___

### PlatformApiOptions

Ƭ **PlatformApiOptions**<`Platform`, `RunTarget`\>: `Object`

The options for the `platformApi()` function.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |
| `RunTarget` | extends [`SupportedRunTarget`](README.md#supportedruntarget)<`Platform`\> |

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `platform` | `Platform` | The platform you want to run on. |
| `runTarget` | `RunTarget` | The target (emulator, physical device) you want to run on. |
| `targetOptions` | [`RunTargetOptions`](README.md#runtargetoptions)[`Platform`][`RunTarget`] | The options for the selected platform/run target combination. |

#### Defined in

[index.ts:128](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L128)

___

### RunTargetOptions

Ƭ **RunTargetOptions**: `Object`

The options for a specific platform/run target combination.

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `android` | { `device`: `never` ; `emulator`: { `fridaPsPath`: `string` ; `objectionPath`: `string` ; `snapshotName`: `string`  }  } | The options for the Android platform. |
| `android.device` | `never` | The options for the Android physical device run target. |
| `android.emulator` | { `fridaPsPath`: `string` ; `objectionPath`: `string` ; `snapshotName`: `string`  } | The options for the Android emulator run target. |
| `android.emulator.fridaPsPath` | `string` | The path to the `frida-ps` binary. |
| `android.emulator.objectionPath` | `string` | The path to the `objection` binary. |
| `android.emulator.snapshotName` | `string` | The name of a snapshot to use for the `resetDevice()` function. |
| `ios` | { `device`: { `fridaPsPath`: `string` ; `ip`: `string` ; `rootPw?`: `string`  } ; `emulator`: `never`  } | The options for the iOS platform. |
| `ios.device` | { `fridaPsPath`: `string` ; `ip`: `string` ; `rootPw?`: `string`  } | The options for the iOS physical device run target. |
| `ios.device.fridaPsPath` | `string` | The path to the `frida-ps` binary. |
| `ios.device.ip` | `string` | The device's IP address. |
| `ios.device.rootPw?` | `string` | The password of the root user on the device. |
| `ios.emulator` | `never` | The options for the iOS emulator run target. |

#### Defined in

[index.ts:138](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L138)

___

### SupportedPlatform

Ƭ **SupportedPlatform**: ``"android"`` \| ``"ios"``

A platform that is supported by this library.

#### Defined in

[index.ts:7](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L7)

___

### SupportedRunTarget

Ƭ **SupportedRunTarget**<`Platform`\>: `Platform` extends ``"android"`` ? ``"emulator"`` : `Platform` extends ``"ios"`` ? ``"device"`` : `never`

A run target that is supported by this library for the given platform.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |

#### Defined in

[index.ts:9](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L9)

## Functions

### platformApi

▸ **platformApi**<`Platform`, `RunTarget`\>(`options`): [`PlatformApi`](README.md#platformapi)<`Platform`\>

Get the API object with the functions for the given platform and run target.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |
| `RunTarget` | extends ``"device"`` \| ``"emulator"`` |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `options` | [`PlatformApiOptions`](README.md#platformapioptions)<`Platform`, `RunTarget`\> | The options for the API object. |

#### Returns

[`PlatformApi`](README.md#platformapi)<`Platform`\>

The API object for the given platform and run target.

#### Defined in

[index.ts:191](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L191)
