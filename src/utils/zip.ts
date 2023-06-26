import { createWriteStream } from 'fs';
import type { FileHandle } from 'fs/promises';
import type { Readable } from 'stream';
import { temporaryFile } from 'tempy';
import type { Entry, ZipFile } from 'yauzl';
import { fromFd } from 'yauzl';

/**
 * Promise wrapper for yauzl.fromFd.
 *
 * @param zip FileHandle of the zip file.
 *
 * @returns ZipFile to be used with yauzl.
 */
export const openZipFile = async (zip: FileHandle) =>
    new Promise<ZipFile>((resolve) => {
        fromFd(zip.fd, { lazyEntries: true }, (err, zipFile) => {
            if (err) throw err;
            resolve(zipFile);
        });
    });

/**
 * Run a function on each entry in a zip file. Resolves if all entries have been processed.
 *
 * @param zip FileHandle of the zip file.
 * @param callback Function to run on each entry, it will receive the entry and a reference to the current ZipFile.
 */
export const forEachInZip = async (zip: FileHandle, callback: (entry: Entry, zipFile: ZipFile) => Promise<void>) =>
    openZipFile(zip).then(
        (zipFile) =>
            new Promise<void>((resolve) => {
                zipFile.readEntry();
                zipFile.on('entry', (entry: Entry) => {
                    callback(entry, zipFile).then(() => zipFile.readEntry());
                });
                zipFile.on('end', () => resolve());
            })
    );

/**
 * Get a Readable stream of a file entry in a zip file.
 *
 * @param zip FileHandle of the zip file.
 * @param filename Name of the file entry in the zip.
 *
 * @returns A Readable stream of the file entry, or void if the file entry was not found.
 */
export const getFileFromZip = async (zip: FileHandle, filename: string) =>
    openZipFile(zip).then(
        (zipFile) =>
            new Promise<Readable | void>((resolve) => {
                zipFile.readEntry();
                zipFile.on('entry', (entry: Entry) => {
                    if (entry.fileName !== filename) {
                        zipFile.readEntry();
                        return;
                    }
                    zipFile.openReadStream(entry, (err, stream) => {
                        if (err) throw err;
                        resolve(stream);
                    });
                });
                zipFile.on('end', () => resolve());
            })
    );

export const writeFileFromZipToTmp = async (zip: FileHandle, filename: string) =>
    openZipFile(zip).then(
        (zipFile) =>
            new Promise<string | void>((resolve) => {
                zipFile.readEntry();
                zipFile.on('entry', (entry: Entry) => {
                    if (entry.fileName !== filename) {
                        zipFile.readEntry();
                        return;
                    }
                    tmpFileFromZipEntry(zipFile, entry).then((tmpFile) => resolve(tmpFile));
                });
                zipFile.on('end', () => resolve());
            })
    );

/**
 * Write the contents of a zip entry to a temporary file.
 *
 * @param zipFile Yauzl ZipFile to read from.
 * @param entry Entry in the zip file.
 * @param extension Optional file extension to use for the temporary file.
 *
 * @returns The file name of the temporary file.
 */
export const tmpFileFromZipEntry = async <Extension extends string>(
    zipFile: ZipFile,
    entry: Entry,
    extension?: Extension
) =>
    new Promise<`${string}.${Extension}`>((resolve) => {
        zipFile.openReadStream(entry, (err, stream) => {
            if (err) throw Error;
            const tmpFile = temporaryFile({ extension }) as `${string}.${Extension}`;
            stream.pipe(createWriteStream(tmpFile).on('finish', () => resolve(tmpFile)));
        });
    });
