import UIKit
//import GZIP
import CommonCrypto

private let LEN_IV_AES_256_CBC = 16
private let LEN_SHA256 = 32
private let defaultIV = "drowssa1drowssap"

class EncryptService: NSObject {
    
    private static let SERVER_KEY = "En9VDeQH085KzKW4Wp/IbtJQl6QDyKMLZPjcTNAamTw="
    
    static func obKey(key: String = SERVER_KEY) -> String {
        do {
            guard let keyData = Data(base64Encoded: key, options: .ignoreUnknownCharacters) else {
                return ""
            }
            var decryptKey = NSStringFromClass(NSMutableString.self)
            for i in 1...8 {
                decryptKey += "j\(i)"
            }
            decryptKey += "k"
            guard let  decryptKeyData = decryptKey.data(using: .utf8) else{
                return ""
            }
            guard let ivKeyData = defaultIV.data(using: .utf8) else {
                return ""
            }
            let aes = try AES256.init(key: decryptKeyData, iv: ivKeyData)

            let ciphertext = try aes.decrypt(keyData).base64EncodedString(options: [])
            //let ciphertext = try aes.encrypt(keyData).base64EncodedString(options: [])
            return ciphertext

        } catch {
            return ""
        }
    }
        
    static func unpackBagsToData(message:Data?) -> Data? {
        if let encryptoData = message {
            
            //未能取到iv + key data长度
            guard encryptoData.count >= LEN_IV_AES_256_CBC + LEN_SHA256 else {
                return nil
            }
            
            do {
                //
                let ivData = encryptoData.subdata(in: Range.init(NSMakeRange(0, LEN_IV_AES_256_CBC))!)
                let hashData = encryptoData.subdata(in: Range.init(NSMakeRange(LEN_IV_AES_256_CBC, LEN_SHA256))!)
                let messsageData = encryptoData.subdata(in: Range.init(NSMakeRange(LEN_IV_AES_256_CBC + LEN_SHA256, encryptoData.count - LEN_IV_AES_256_CBC - LEN_SHA256))!)

                guard let  keyData = obKey().data(using: .utf8) else{
                    return nil
                }
                
                let aes = try AES256.init(key: keyData, iv: ivData)
                
                let plainData = try aes.decrypt(messsageData)

                let plainText = String.init(data: Data.init(plainData), encoding: .utf8)
                
                if hashData == hmacForData(data: Data.init(plainData), key: keyData) {
                    return plainData
                } else {
                    return nil
                }
            } catch {
                //AppLoggerService.applog(message: "unpackBagsInBase64 dec failed", module: "unpackBagsInBase64", level: AppLogLevel.FATAL)
                return nil
            }
            //AppLoggerService.applog(message: "unpackBagsInBase64 base64 failed", module: "unpackBagsInBase64", level: AppLogLevel.FATAL)
            //return nil
        } else {
            //AppLoggerService.applog(message: "unpackBagsInBase64 no message failed", module: "unpackBagsInBase64", level: AppLogLevel.FATAL)
            return nil
        }
    }
    
    static func packBagsToEncryptoData(message:Data) -> Data? {
        do {
            //16位随机偏移量
            let iv = randomStringWithLength(length: UInt(LEN_IV_AES_256_CBC))

            //16位随机偏移量Data
            guard let ivData = iv.data(using: .utf8) else {
                return nil
            }
            
            //Key的Data
            guard let  keyData = obKey().data(using: .utf8) else{
                return nil
            }
            
            //使用key和偏移量AES256加密
            let cipher = try AES256.init(key: keyData, iv: ivData).encrypt(message)
            let cipherTextData = Data.init(cipher)
            
            //用keyData对message进行加密
            let sha = hmacForData(data: message, key: keyData)
            
            //return 偏移量Data + 加密MessageData + cipherData
            var totalData = Data.init()
            totalData.append(ivData)
            totalData.append(sha)
            totalData.append(cipherTextData)
            return totalData
        } catch {
            //AppLoggerService.applog(message: "packBagsToBase64 failed", module: "packBagsToBase64", level: AppLogLevel.FATAL)
            return nil
        }
    }
    
    static func encrypt(message: String, password: String) -> String? {
        do {
            guard let  keyData = password.data(using: .utf8) else{
                return nil
            }
            guard let ivKeyData = "drowssa2drowssap".data(using: .utf8) else {
                return nil
            }

            guard let messageData = message.data(using: .utf8) else {
                return nil
            }
            let aes = try AES256.init(key: keyData, iv: ivKeyData)
            let ciphertext = try aes.encrypt(messageData)
            let rk = ciphertext.base64EncodedString()
            return rk
        } catch {
            return nil
        }
    }
    
    private class func hmacForData(data:Data, key:Data) -> Data {
        let digestLength = Int(CC_SHA256_DIGEST_LENGTH)
        var cHMAC = [UInt8](repeating: 0, count: digestLength)
        key.withUnsafeBytes { (cKey)  in
            data.withUnsafeBytes({ (cData) in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), cKey, key.count, cData, data.count, &cHMAC)
            })
        }
        return Data.init(cHMAC)
    }
    
    class func randomStringWithLength(length:UInt) -> String {
        let letters:NSString = "abcdefghijklmnopqrstuvwxyz0123456789"
        var randomString:NSMutableString = ""
        for _ in 0..<length {
            let index:Int = Int(arc4random_uniform(UInt32(letters.length)))
            randomString = NSMutableString.init(string: randomString.appendingFormat("%c", letters.character(at: index)))
        }
        return String(randomString)
    }
}

enum HMACAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    func digestLength() -> Int {
        var result: CInt = 0
        switch self {
        case .MD5:
            result = CC_MD5_DIGEST_LENGTH
        case .SHA1:
            result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:
            result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:
            result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:
            result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:
            result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
    
}
