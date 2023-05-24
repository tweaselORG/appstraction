import { getVenv } from 'autopy';
import { venvOptions } from './common/python.js';

(async () => {
    await getVenv(venvOptions);
})();
