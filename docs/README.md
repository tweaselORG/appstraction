appstraction

# appstraction

## Table of contents

### Type Aliases

- [DeviceAttribute](README.md#deviceattribute)
- [GetDeviceAttributeOptions](README.md#getdeviceattributeoptions)
- [PlatformApi](README.md#platformapi)
- [PlatformApiOptions](README.md#platformapioptions)
- [RunTargetOptions](README.md#runtargetoptions)
- [SupportedCapability](README.md#supportedcapability)
- [SupportedPlatform](README.md#supportedplatform)
- [SupportedRunTarget](README.md#supportedruntarget)

### Functions

- [platformApi](README.md#platformapi-1)

## Type Aliases

### DeviceAttribute

Ƭ **DeviceAttribute**<`Platform`\>: `Platform` extends ``"android"`` ? `never` : `Platform` extends ``"ios"`` ? ``"idfv"`` : `never`

A supported attribute for the `getDeviceAttribute()` function, depending on the platform.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |

#### Defined in

[index.ts:222](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L222)

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

[index.ts:228](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L228)

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

[index.ts:15](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L15)

___

### PlatformApiOptions

Ƭ **PlatformApiOptions**<`Platform`, `RunTarget`, `Capabilities`\>: `Object`

The options for the `platformApi()` function.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |
| `RunTarget` | extends [`SupportedRunTarget`](README.md#supportedruntarget)<`Platform`\> |
| `Capabilities` | extends [`SupportedCapability`](README.md#supportedcapability)<`Platform`\>[] |

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `capabilities` | `Capabilities` | The capabilities you want. Depending on what you're trying to do, you may not need or want to root the device, install Frida, etc. In this case, you can exclude those capabilities. This will influence which functions you can run. |
| `platform` | `Platform` | The platform you want to run on. |
| `runTarget` | `RunTarget` | The target (emulator, physical device) you want to run on. |
| `targetOptions` | [`RunTargetOptions`](README.md#runtargetoptions)<`Capabilities`\>[`Platform`][`RunTarget`] | The options for the selected platform/run target combination. |

#### Defined in

[index.ts:146](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L146)

___

### RunTargetOptions

Ƭ **RunTargetOptions**<`Capabilities`, `Capability`\>: `Object`

The options for a specific platform/run target combination.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Capabilities` | extends [`SupportedCapability`](README.md#supportedcapability)<``"android"`` \| ``"ios"``\>[] |
| `Capability` | `Capabilities`[`number`] |

#### Type declaration

| Name | Type | Description |
| :------ | :------ | :------ |
| `android` | { `device`: `never` ; `emulator`: { `snapshotName`: `string`  } & ``"frida"`` extends `Capability` ? { `fridaPsPath`: `string`  } : `unknown` & ``"certificate-pinning-bypass"`` extends `Capability` ? { `objectionPath`: `string`  } : `unknown`  } | The options for the Android platform. |
| `android.device` | `never` | The options for the Android physical device run target. |
| `android.emulator` | { `snapshotName`: `string`  } & ``"frida"`` extends `Capability` ? { `fridaPsPath`: `string`  } : `unknown` & ``"certificate-pinning-bypass"`` extends `Capability` ? { `objectionPath`: `string`  } : `unknown` | The options for the Android emulator run target. |
| `ios` | { `device`: `Record`<`string`, `never`\> & ``"ssh"`` extends `Capability` ? { `ip`: `string` ; `rootPw?`: `string`  } : `unknown` & ``"frida"`` extends `Capability` ? { `fridaPsPath`: `string`  } : `unknown` ; `emulator`: `never`  } | The options for the iOS platform. |
| `ios.device` | `Record`<`string`, `never`\> & ``"ssh"`` extends `Capability` ? { `ip`: `string` ; `rootPw?`: `string`  } : `unknown` & ``"frida"`` extends `Capability` ? { `fridaPsPath`: `string`  } : `unknown` | The options for the iOS physical device run target. |
| `ios.emulator` | `never` | The options for the iOS emulator run target. |

#### Defined in

[index.ts:166](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L166)

___

### SupportedCapability

Ƭ **SupportedCapability**<`Platform`\>: `Platform` extends ``"android"`` ? ``"frida"`` \| ``"certificate-pinning-bypass"`` : `Platform` extends ``"ios"`` ? ``"ssh"`` \| ``"frida"`` : `never`

A capability for the `platformApi()` function.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |

#### Defined in

[index.ts:215](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L215)

___

### SupportedPlatform

Ƭ **SupportedPlatform**: ``"android"`` \| ``"ios"``

A platform that is supported by this library.

#### Defined in

[index.ts:6](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L6)

___

### SupportedRunTarget

Ƭ **SupportedRunTarget**<`Platform`\>: `Platform` extends ``"android"`` ? ``"emulator"`` : `Platform` extends ``"ios"`` ? ``"device"`` : `never`

A run target that is supported by this library for the given platform.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |

#### Defined in

[index.ts:8](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L8)

## Functions

### platformApi

▸ **platformApi**<`Platform`, `RunTarget`, `Capabilities`\>(`options`): [`PlatformApi`](README.md#platformapi)<`Platform`\>

Get the API object with the functions for the given platform and run target.

#### Type parameters

| Name | Type |
| :------ | :------ |
| `Platform` | extends [`SupportedPlatform`](README.md#supportedplatform) |
| `RunTarget` | extends ``"device"`` \| ``"emulator"`` |
| `Capabilities` | extends [`SupportedCapability`](README.md#supportedcapability)<`Platform`\>[] |

#### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `options` | [`PlatformApiOptions`](README.md#platformapioptions)<`Platform`, `RunTarget`, `Capabilities`\> | The options for the API object. |

#### Returns

[`PlatformApi`](README.md#platformapi)<`Platform`\>

The API object for the given platform and run target.

#### Defined in

[index.ts:243](https://github.com/tweaselORG/appstraction/blob/main/src/index.ts#L243)
