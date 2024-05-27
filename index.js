const crypto = require('crypto');
const SECRET_IV = "secretIV";
const ECNRYPTION_METHOD = "aes-256-cbc";
const expiryTime = 1;//in minutes's
const encryptionIV = crypto
  .createHash('sha512')
  .update(SECRET_IV)
  .digest('hex')
  .substring(0, 16);

const generateKey = (secret_key) =>{
  const key = crypto
  .createHash('sha512')
  .update(secret_key)
  .digest('hex')
  .substring(0, 32);
  return key;
}

function minFromNow(ms) {
  const millis = ((new Date().getTime())) - ms;
  var minutes = Math.floor(millis / 60000);
 return minutes;
}

const calPerformance = (startTime)=>{
  const endTime = performance.now();
  console.log("Completed in",(Math.round(((endTime - startTime)) + Number.EPSILON) * 100) / 100,"ms");
}

  // Encrypt data
 const encryptData = (message) => {
    const start = performance.now();
    let response = {}; 
    try {
      const {key,data}  = message;
      const newData = {token:(new Date().getTime()),data:data};
      const cipher = crypto.createCipheriv(ECNRYPTION_METHOD, generateKey(key), encryptionIV)
      const encrypted = Buffer.from(
        cipher.update(JSON.stringify(newData), 'utf8', 'hex') + cipher.final('hex')
      ).toString('base64');
      response =  {error:'',data:encrypted};
    } catch (error) {
      response =  {error :"Something went wrong in encryption process.",code:error}
    }
    calPerformance(start);
    return response;

  }
  
  // Decrypt data
const  decryptData = (message)=> {   
    const start = performance.now();
    let response = {}; 
    try {
      const {key,data}  = message;
      const buff = Buffer.from(data, 'base64')
      const decipher = crypto.createDecipheriv(ECNRYPTION_METHOD, generateKey(key), encryptionIV)
      let res = (decipher.update(buff.toString('utf8'), 'hex', 'utf8') + decipher.final('utf8') ) // Decrypts data and converts to utf8
      res = JSON.parse(res);
      console.log("Recieved after >> ",minFromNow(res.token)," Min")
      if(minFromNow(res.token)>expiryTime){
        response = {error:"Data has been expired.",data:""};
      }else{
        response = {data :res.data,error:''};
      }
      
    } catch (error) {
      response = {code :error,error:"Something went wrong in decryption process."}
    }
    calPerformance(start);
    return response;
  }

  module.exports = {encryptData,decryptData}
