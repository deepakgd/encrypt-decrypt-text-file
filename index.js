const crypto = require("crypto"),
  fsPromises = require("fs").promises,
  to = require("await-to-js").to;

const OPTIONS = ["encrypt", "decrypt"];
// 100 kb in bytes
const LIMIT = 100000;
const ALGORITHM = "aes-256-cbc";

// for production, store it in .env file
const ENCRYPTION_KEY = Buffer.from(
  "FoCKvdLslUuB4y3EZlKate7XGottHski1LmyqJHvUhs=",
  "base64"
);

/**
 * init - app initialization
 * @returns {File} - encrypted/decrypted dataa
 */
async function init() {
  // validate command
  let { valid, option, filepath } = validateCliCmd();
  if (!valid) return logErrorAndExit("Invalid input");

  // variable decalaration
  let error, result;

  // encrypt or decrypt
  if(option === "encrypt") [error, result] = await to(encryption(filepath));
  else [error, result] = await to(decryption(filepath));

  // error logger
  if(error) return logErrorAndExit(error);

  // print result
  console.log(`TASK - ${option} - Completed. Output file is - ${result}`)
}

/**
 * encryption - encrypt text file and resolve output path
 * @param {String} - input file path for encryption
 * @returns {String} - output file path
 */
function encryption(filepath) {
  return new Promise(async (resolve, reject) => {
    let error, response, encrypted, data, outputPath = `${filepath}.encrypted`;

    // read the given file
    [error, data] = await to(readFile(filepath));
    if (error) return reject(error);

    // encrypt part of file
    [error, encrypted] = await to(encrypt(data.partOfFile));
    if (error) return reject(error);

    // context encrypted text to buffer
    let bufData = Buffer.from(encrypted);
    // merge encrypted buffer and other part of file;
    bufData = bufData + data.entireFile.slice(100000, data.entireFile.length);

    // write entire bufData to file
    [error, response] = await to(
      fsPromises.writeFile(outputPath, bufData)
    );
    if (error) return reject(error);

    resolve(outputPath)
  });
}


/**
 * encrypt - encrypt given data
 * @param {Buffer} data  - some part of file
 * @returns {String} return encrypted string
 */
function encrypt(data) {
  return new Promise((resolve, reject) => {
    try {
      // Initialization vector.
      const iv = Buffer.alloc(16, 0);

      // create cipher for encryption using given algorithm
      let cipher = crypto.createCipheriv(
        ALGORITHM,
        Buffer.from(ENCRYPTION_KEY, "hex"),
        iv
      );
      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      resolve(iv.toString("hex") + ":" + encrypted.toString("hex"));
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * decrypt - decrypt the given text 
 * @param {String} text 
 * @returns {String} return decrypted text
 */
function decrypt(text) {
  return new Promise((resolve, rejects) => {
    // split text parts 
    let textParts = text.split(':');
    // create buffer for initialization vector
    let iv = Buffer.from(textParts.shift(), 'hex');

    // decrypt the data
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return resolve(decrypted.toString());
  });
}

/**
 * encryption - encrypt text file and resolve output path
 * @param {String} - input file path for encryption
 * @returns {String} - output file path
 */
 function decryption(filepath) {
  return new Promise(async (resolve, reject) => {
    let error, response, data, outputPath = `./${Date.now()}.txt`;

    console.log(filepath);
    // read the given encrypted file
    [error, data] = await to(fsPromises.readFile(filepath, "utf8"));
    if (error) return reject(error);

    // decrypt the given file
    [error, data] = await to(decrypt(data));
    if (error) return reject(error);

    // write entire data to file
    [error, response] = await to(
      fsPromises.writeFile(outputPath, data)
    );
    if (error) return reject(error);

    resolve(outputPath)
  });
}

/**
 * validateCliCmd - validate command
 * @returns {Object} - return encrypt/descrypt option and file path
 */
function validateCliCmd() {
  let args = process.argv.slice(2);
  let argLength = args.length;
  if (argLength != 2) return { valid: false };
  let [option, filepath] = args;
  if (!OPTIONS.includes(option)) return { valid: false };
  return { valid: true, option, filepath };
}

/**
 * readFile - read the given file
 * @param {String} filepath - file path
 * @returns {Object} return entire file and part of file for encrytion
 */
function readFile(filepath) {
  return new Promise(async (resolve, reject) => {
    // read file
    let [error, data] = await to(fsPromises.readFile(filepath));
    if (error) return reject(error);

    // take only part of file for encryption
    let partOfFile = getPartOfFile(data);

    resolve({ entireFile: data, partOfFile });
  });
}

/**
 * getPartOfFile - get part of file from encryption
 * @param {Buffer} bufData - input file data
 * @returns {Buffer} return part of file for encryption
 */
function getPartOfFile(bufData) {
  return bufData.slice(0, LIMIT);
}

/**
 * logErrorAndExit - log error message and exit process
 * @param {String} error
 */
function logErrorAndExit(error) {
  console.log(error);
  process.exit();
}

init();
