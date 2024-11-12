const crypto = require("crypto");
 
var secret = "secret";
 
function generateToken(payload)
{
    let header =
    {
        alg: "HS256",
        typ: "JWT"
    }
 
    let encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
    let encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
    
 
    let hmac = crypto.createHmac("sha256", secret);
    hmac.update(encodedHeader + "." + encodedPayload);
 
    let encodedSignature = hmac.digest("base64url");
 
    return [encodedHeader,encodedPayload,encodedSignature].join(".");
}
 
function decodeToken(token)
{
    let [encodedHeader,encodedPayload,encodedSignature] = token.split(".");
 
    let header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString());
    let payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString());
 
    let hmac = crypto.createHmac("sha256", secret);
    hmac.update(encodedHeader + "." + encodedPayload);
 
    let verified = encodedSignature === hmac.digest("base64url");
 
    return {header,payload,verified};
}
 
console.log(decodeToken(generateToken({a:5})));