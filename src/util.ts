import frida from 'frida';
import fs from 'fs-extra';
import _ipaInfo from 'ipa-extract-info';

// eslint-disable-next-line @typescript-eslint/no-empty-function
export const asyncNop = async () => {};
export const asyncUnimplemented = (action: string) => async () => {
    throw new Error('Unimplemented on this platform: ' + action);
};

export const pause = (durationInMs: number) =>
    new Promise((res) => {
        setTimeout(res, durationInMs);
    });

export const ipaInfo = async (ipaPath: string) => {
    const fd = await fs.open(ipaPath, 'r');
    return await _ipaInfo(fd);
};

export const getObjFromFridaScript = async (pid: number | undefined, script: string) => {
    if (!pid) throw new Error('Must provide pid.');
    const fridaDevice = await frida.getUsbDevice();
    const fridaSession = await fridaDevice.attach(pid);
    const fridaScript = await fridaSession.createScript(script);
    const resultPromise = new Promise<unknown>((res, rej) => {
        fridaScript.message.connect((message) => {
            if (message.type === 'send' && message.payload?.name === 'get_obj_from_frida_script')
                res(message.payload?.payload);
            else rej(message);
        });
    });
    await fridaScript.load();

    await fridaSession.detach();
    return await resultPromise; // We want this to be caught here if it fails, thus the `await`.
};

export const isRecord = (maybeRecord: unknown): maybeRecord is Record<string, unknown> =>
    !!maybeRecord && typeof maybeRecord === 'object';
