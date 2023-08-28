export const venvOptions = {
    name: 'appstraction',
    pythonVersion: '~3.11',
    requirements: [
        { name: 'pip', version: '~=23.1' },
        { name: 'libclang', version: '~=16.0' },
        { name: 'frida-tools', version: '~=12.1' },
        { name: 'pymobiledevice3', version: '~=1.42' },
    ],
};
