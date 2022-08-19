import UIKit
//import GZIP
import CommonCrypto

public enum CryptoError: Error {
    case encryptBodyEncodingError
    case unspecfiedCipherText
    case createIVDataError
    case decryptKeyError
    case aes256Error(Error)
    case decryptedDataVerificationFailed
}

extension CryptoError {
    var errorMessage: String {
        switch self {
        case .unspecfiedCipherText:
            return ""
        case .createIVDataError:
            return "Can not Create Random IV String Data"
        case .decryptKeyError:
            return "Failed to Decrypt Cipher Key"
        case .aes256Error(let error):
            return "AES256 Crypto Eroror: \(error)"
        case .decryptedDataVerificationFailed:
            return "Decrypt Cipher Text Failed To Verify by HMAC"
        case .encryptBodyEncodingError:
            return "Encrypt Http Body Error"
        }
    }
}

public final class EncryptService: Cryptoable {
    
    private var cipherKey: String
    private static let LEN_IV_AES_256_CBC = 16
    private static let LEN_SHA256 = 32
    private static let defaultIV = "drowssa1drowssap"
    
    public init(key: String) {
        self.cipherKey = key
    }
    
    public func seal(_ digest: Data) throws -> Data {
        do {
            //16位随机偏移量
            let iv = String.getRandomStringWithLength(length: UInt(EncryptService.LEN_IV_AES_256_CBC))

            //16位随机偏移量Data
            guard let ivData = iv.data(using: .utf8) else {
                throw CryptoError.createIVDataError
            }
            
            //Key的Data
            guard let keyData = EncryptService.obKey(key: self.cipherKey).data(using: .utf8) else{
                throw CryptoError.decryptKeyError
            }
            
            //使用key和偏移量AES256加密
            let cipher = try AES256.init(key: keyData, iv: ivData).encrypt(digest)
            let cipherTextData = Data.init(cipher)
            
            //用keyData对message进行加密
            let sha = hmacForData(data: digest, key: keyData)
            
            //return 偏移量Data + 加密MessageData + cipherData
            var totalData = Data.init()
            totalData.append(ivData)
            totalData.append(sha)
            totalData.append(cipherTextData)
            
            return totalData
        } catch {
            throw CryptoError.aes256Error(error)
        }
    }
    
    public func open(_ digest: Data) throws -> Data {
        //未能取到iv + key data长度
        guard digest.count >= EncryptService.LEN_IV_AES_256_CBC + EncryptService.LEN_SHA256 else {
            throw CryptoError.unspecfiedCipherText
        }
        
        do {
            let ivData = digest.subdata(in: Range.init(NSMakeRange(0, EncryptService.LEN_IV_AES_256_CBC))!)
            let hashData = digest.subdata(in: Range.init(NSMakeRange(EncryptService.LEN_IV_AES_256_CBC, EncryptService.LEN_SHA256))!)
            let messsageData = digest.subdata(in: Range.init(NSMakeRange(EncryptService.LEN_IV_AES_256_CBC + EncryptService.LEN_SHA256, digest.count - EncryptService.LEN_IV_AES_256_CBC - EncryptService.LEN_SHA256))!)

            guard let  keyData = EncryptService.obKey(key: self.cipherKey).data(using: .utf8) else{
                throw CryptoError.decryptKeyError
            }
            
            let aes = try AES256.init(key: keyData, iv: ivData)
            
            let plainData = try aes.decrypt(messsageData)

            //let plainText = String.init(data: Data.init(plainData), encoding: .utf8)
            
            if hashData == hmacForData(data: Data.init(plainData), key: keyData) {
                return plainData
            } else {
                throw CryptoError.decryptedDataVerificationFailed
            }
        } catch {
            throw CryptoError.aes256Error(error)
        }
       
    }
        
    private static func encrypt(message: String, password: String) -> String? {
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
    
    private func hmacForData(data:Data, key:Data) -> Data {
        let digestLength = Int(CC_SHA256_DIGEST_LENGTH)
        var cHMAC = [UInt8](repeating: 0, count: digestLength)
        key.withUnsafeBytes { (cKey)  in
            data.withUnsafeBytes({ (cData) in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), cKey, key.count, cData, data.count, &cHMAC)
            })
        }
        return Data.init(cHMAC)
    }
    
    public static func obKey(key: String) -> String {
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
    
}

extension String {
    static func getRandomStringWithLength(length:UInt) -> String {
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
