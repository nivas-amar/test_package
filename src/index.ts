import { createHash, createCipheriv, createDecipheriv } from 'crypto';
const SECRET_IV = "secretIV";
const ECNRYPTION_METHOD = "aes-256-cbc";
const expiryTime = 1;//in minutes's
type response = {
  error:string,
  data:string,
  time:string
}
const encryptionIV = createHash('sha512')
  .update(SECRET_IV)
  .digest('hex')
  .substring(0, 16);

const generateKey = (secret_key:string) =>{
  const key = createHash('sha512')
  .update(secret_key)
  .digest('hex')
  .substring(0, 32);
  return key;
}

function minFromNow(ms:number) {
  const millis = ((new Date().getTime())) - ms;
  var minutes = Math.floor(millis / 60000);
 return minutes;
}

const calPerformance = (startTime:number)=>{
  const endTime = performance.now();
  return ((Math.round(((endTime - startTime)) + Number.EPSILON) * 100) / 100)+"ms";
}

  // Encrypt data
  export function encryptData(message:{key:string,data:any}):response{
    const start = performance.now();
    let response:response; 
    try {
      const {key,data}  = message;
      const newData = {token:(new Date().getTime()),data:data};
      const cipher = createCipheriv(ECNRYPTION_METHOD, generateKey(key), encryptionIV)
      const encrypted = Buffer.from(
        cipher.update(JSON.stringify(newData), 'utf8', 'hex') + cipher.final('hex')
      ).toString('base64');
      response =  {error:'',data:encrypted,time:""};
    } catch (error) {
      response =  {error :"Something went wrong in encryption process.",data:"",time:""}
    }
    response.time = calPerformance(start);
    return response;
  }
  
  // Decrypt data
  export function decryptData(message:{key:string,data:any}):response {
    const start = performance.now();
    let response :response; 
    try {
      const {key,data}  = message;
      const buff = Buffer.from(data, 'base64')
      const decipher = createDecipheriv(ECNRYPTION_METHOD, generateKey(key), encryptionIV)
      let res:any = (decipher.update(buff.toString('utf8'), 'hex', 'utf8') + decipher.final('utf8') ) // Decrypts data and converts to utf8
      res = JSON.parse(res);
      if(minFromNow(res.token)>expiryTime){
        response = {error:"Data has been expired.",data:"",time:""};
      }else{
        response = {data :res.data,error:'',time:''};
      }
    } catch (error) {
      response = {error:"Something went wrong in decryption process.",time:"",data:""};
    }
    response.time = calPerformance(start);
    return response;
  }
