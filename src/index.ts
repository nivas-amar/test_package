import { createHash, createCipheriv, createDecipheriv } from 'crypto';
const SECRET_IV = "secretIV";
const ECNRYPTION_METHOD = "aes-128-gcm";
const expiryTime = 1; // in minutes
type response = {
  error: string,
  data: string,
  time: string
};

const encryptionIV = createHash('sha512')
  .update(SECRET_IV)
  .digest('hex')
  .substring(0, 16);

const generateKey = (secret_key: string) => {
  const key = createHash('sha512')
    .update(secret_key)
    .digest('hex')
    .substring(0, 16);
  return key;
};

function minFromNow(ms: number) {
  const millis = ((new Date().getTime())) - ms;
  var minutes = Math.floor(millis / 60000);
  return minutes;
}

const calPerformance = (startTime: number) => {
  const endTime = performance.now();
  return ((Math.round(((endTime - startTime)) + Number.EPSILON) * 100) / 100) + "ms";
}

// Encrypt data
export function encryptData(key: string, data: any): response {
  const start = performance.now();
  let response: response;
  try {
    const newData = { token: (new Date().getTime()), data: data };
    const cipher = createCipheriv(ECNRYPTION_METHOD, generateKey(key), encryptionIV);
    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(newData), 'utf8'),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag().toString('hex');
    response = { error: '', data: `${encrypted.toString('hex')}:${authTag}`, time: "" };
  } catch (error) {
    response = { error: "Something went wrong in encryption process.", data: "", time: "" };
  }
  response.time = calPerformance(start);
  return response;
}

// Decrypt data
export function decryptData(key: string, data: any): response {
  const start = performance.now();
  let response: response;
  try {
    const [encryptedData, authTag] = data.split(':');
    const decipher = createDecipheriv(ECNRYPTION_METHOD, generateKey(key), encryptionIV);
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let res: any = Buffer.concat([
      decipher.update(Buffer.from(encryptedData, 'hex')),
      decipher.final()
    ]).toString('utf8');
    res = JSON.parse(res);

    if (minFromNow(res.token) > expiryTime) {
      response = { error: "Data has been expired.", data: "", time: "" };
    } else {
      response = { data: res.data, error: '', time: '' };
    }
  } catch (error) {
    console.log(error);
    response = { error: "Something went wrong in decryption process.", time: "", data: "" };
  }

  response.time = calPerformance(start);
  return response;
}


// let requests = [1, 10, 100, 1000, 10000, 100000];

// import fs from 'fs';
// let jsonData = JSON.parse(fs.readFileSync('temp.json', 'utf-8'));

// requests.forEach((request) => {
//   console.time("niwas");
//   for (let i = 0; i < request; i++) {
//     const en = encryptData("nivas", jsonData);
//     const dn = decryptData("nivas", en.data);
//   }
//   console.timeEnd("niwas");
// });