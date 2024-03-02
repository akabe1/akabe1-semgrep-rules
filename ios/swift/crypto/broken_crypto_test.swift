import example



class CryptoViewController: UIViewController { 
// Check CCKeyDerivationPBKDF ///////////////////////////////////////////////////////////

    func foo1(salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        let password = "asd123"
        let passwordData = password.data(using:String.Encoding.utf8)!
        var derivedKeyData = Data(repeating:0, count:keyByteCount)
        let count = derivedKeyData.count
        let derivationStatus = derivedKeyData.withUnsafeMutableBytes {derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    // ruleid: vuln static hardcoded key
                    password, passwordData.count,
                    saltBytes, salt.count,
                    CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1),
                    UInt32(rounds),
                    derivedKeyBytes, count)
            }
        }
        if (derivationStatus != 0) {
            print("Error: \(derivationStatus)")
            return nil;
        }
        return derivedKeyData
    }



    func foo2(salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        var derivedKeyData = Data(repeating:0, count:keyByteCount)
        let count = derivedKeyData.count
        let derivationStatus = derivedKeyData.withUnsafeMutableBytes {derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                // ruleid: vuln nil key
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    nil, 0,
                    saltBytes, salt.count,
                    CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1),
                    UInt32(rounds),
                    derivedKeyBytes, count)
            }
        }
        if (derivationStatus != 0) {
            print("Error: \(derivationStatus)")
            return nil;
        }
        return derivedKeyData
    }



    func foo3(salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        var derivedKeyData = Data(repeating:0, count:keyByteCount)
        let count = derivedKeyData.count
        let derivationStatus = derivedKeyData.withUnsafeMutableBytes {derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                //ruleid: vuln empty key
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    "", 0,
                    saltBytes, salt.count,
                    CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1),
                    UInt32(rounds),
                    derivedKeyBytes, count)
            }
        }
        if (derivationStatus != 0) {
            print("Error: \(derivationStatus)")
            return nil;
        }       
        return derivedKeyData
    }
    
    

    func foo4() {
        let keyArray: [Character] = ["a4", "56", "bc", "7f", "41"]
        let keyString = String(keyArray, encoding: .ascii)
    	// ruleid: vuln key generation with static hardcoded passphrase
        let status : Int32 = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), keyString, keyString.lengthOfBytes(using: String.Encoding.utf8), salt, salt.lengthOfBytes(using: String.Encoding.utf8), prf.nativeValue(), rounds, &derivedKey, derivedKey.count)
        return status
    }



    func foo5() {
        let keyString = "12345678901234567890123456789012"
	let keyData: NSData! = (keyString as NSString).dataUsingEncoding(NSUTF8StringEncoding) as NSData!
	let message = "Top Secret Message"
	let data: NSData! = (message as NSString).dataUsingEncoding(NSUTF8StringEncoding) as NSData!
	let cryptData = NSMutableData(length: Int(data.length) + kCCBlockSizeAES128)!
	let keyLength = size_t(kCCKeySizeAES256)
	let operation: CCOperation = UInt32(kCCEncrypt)
	let algoritm: CCAlgorithm = UInt32(kCCAlgorithmAES128)
	let options: CCOptions = UInt32(kCCOptionECBMode + kCCOptionPKCS7Padding)
	var numBytesEncrypted :size_t = 0
	// ruleid: vuln static hardcoded key
	var cryptStatus = CCCrypt(operation,
    		algoritm,
    		options,
    		keyData.bytes, keyLength,
    		nil,
    		data.bytes, data.length,
    		cryptData.mutableBytes, cryptData.length,
    		&numBytesEncrypted)
    }
    
    
    
    func foo6() {
        let keyBytes = UnsafeMutableRawPointer.allocate(byteCount: 128, alignment: 1)
        let keyData = Data(bytes: keyBites, count: 128)
        let ivBytes = UnsafeMutableRawPointer.allocate(byteCount: 16, alignment: 1)
        let ivData = Data(bytes: keyBites, count: 16)
	let message = "Top Secret Message"
	let data: NSData! = (message as NSString).dataUsingEncoding(NSUTF8StringEncoding) as NSData!
	let cryptData = NSMutableData(length: Int(data.length) + kCCBlockSizeAES128)!
	let keyLength = size_t(kCCKeySizeAES256)
	let operation: CCOperation = UInt32(kCCEncrypt)
	let algoritm: CCAlgorithm = UInt32(kCCAlgorithmAES128)
	let options: CCOptions = UInt32(kCCOptionECBMode + kCCOptionPKCS7Padding)
	var numBytesEncrypted :size_t = 0
	// ok: good random key 
	var cryptStatus = CCCrypt(operation,
    		algoritm,
    		options,
    		keyData.bytes, keyLength,
    		ivData.bytes,
    		data.bytes, data.length,
    		cryptData.mutableBytes, cryptData.length,
    		&numBytesEncrypted)
    }



    func foo7() throws -> Data {
    	let key = "asd123"
    	let iv = "12345678"
    	let message = "Top Secret Message"
	let data: NSData! = (message as NSString).dataUsingEncoding(NSUTF8StringEncoding) as NSData!
	let cryptData = NSMutableData(length: Int(data.length) + kCCBlockSizeAES128)!
    	var outputBuffer = Array<UInt8>(repeating: 0, 
                                    count: cipherTextLength)
    	var numBytesDecrypted = 0
    	// ruleid: vuln static hardcoded key
    	let status = CCCrypt(CCOperation(kCCDecrypt),
                         CCAlgorithm(kCCAlgorithmAES),
                         CCOptions(kCCOptionPKCS7Padding),
                         Array(key),
                         kCCKeySizeAES256,
                         Array(iv),
                         Array(data),
                         data.length,
                         &outputBuffer,
                         cipherTextLength,
                         &numBytesDecrypted)
    	guard status == kCCSuccess else {
        	throw Error.decryptionError(status: status)
    	}
    	// Read output discarding any padding
    	let outputBytes = outputBuffer.prefix(numBytesDecrypted)
    	return Data(bytes: outputBytes)
    }
    
    

}




class CryptoViewController: UIViewController { 
// Check RNCrypto ///////////////////////////////////////////////////////////

    func foo8(_ textField: UITextField) -> Bool {
        let dataPath = URL(fileURLWithPath: NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first!).appendingPathComponent("/secret-data").absoluteURL
        if textField == passwordTextField {
            textField.resignFirstResponder()
            if textField.text == nil {
                DVIAUtilities.showAlert(title: "Oops", message: "Please enter a password", viewController: self)
            } else {
                let data = passwordTextField.text?.data(using: String.Encoding.utf8)
                // ruleid: vuln RNCrypto static hardcoded key
                let encryptedData = try? RNEncryptor.encryptData(data, with: kRNCryptorAES256Settings, password: "@daloq3as$qweasdlasasjdnj")
                try? encryptedData?.write(to: dataPath, options: .atomic)
                UserDefaults.standard.set(true, forKey: "loggedIn")
                UserDefaults.standard.synchronize()
                firstTimeUserView.isHidden = true
            }
        } else if textField == returningUserPasswordTextField {
            let data = returningUserPasswordTextField.text?.data(using: String.Encoding.utf8)
            let encryptedData = try? Data(contentsOf: dataPath)
            // ruleid: vuln RNCrypto hardcoded key
            let decryptedData = try? RNDecryptor.decryptData(encryptedData, withPassword: nil)
            if data == decryptedData {
                loggedInLabel.isHidden = false
                returningUserPasswordTextField.isHidden = true
                welcomeReturningUserLabel.isHidden = true
            } else {
                DVIAUtilities.showAlert(title: "Oops", message: "Password is incorrect", viewController: self)
                return false
            }
        }
        return false
    }



    func foo9() {
        let encryptKey = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f".dataFromHexEncoding!
        let hmacKey = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00".dataFromHexEncoding!
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03000203 04050607 08090a0b 0c0d0e0f 0001981b 22e7a644 8118d695 bd654f72 e9d6ed75 ec14ae2a a067eed2 a98a56e0 993dfe22 ab5887b3 f6e3cdd4 0767f519 5eb5".dataFromHexEncoding!
        // ruleid: vuln static hardcoded key 
        let decryptor = RNCryptor.DecryptorV3(encryptionKey: encryptKey, hmacKey: hmacKey)
        do {
            let decrypted = try decryptor.decrypt(data: ciphertext)
            XCTAssertEqual(decrypted, plaintext)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }



    func foo10() {
        let password = "thepassword"
        let encryptionSalt = "0001020304050607".dataFromHexEncoding!
        let hmacSalt = "0102030405060708".dataFromHexEncoding!
        let iv = "02030405060708090a0b0c0d0e0f0001".dataFromHexEncoding!
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8".dataFromHexEncoding!
	// ruleid: vuln static hardcoded key and IV
        let encryptor = RNCryptor.EncryptorV3(password: password, encryptionSalt: encryptionSalt, hmacSalt: hmacSalt, iv: iv)
        let encrypted = encryptor.encrypt(data: plaintext)
        XCTAssertEqual(encrypted, ciphertext)
    }



    func foo11() {
        let password = nil
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8".dataFromHexEncoding!
	// ruleid: vuln nil key
        let decryptor = RNCryptor.Decryptor(password: password)
        do {
            let decrypted = try decryptor.decrypt(data: ciphertext)
            XCTAssertEqual(decrypted, plaintext)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }


    func foo12() {
        let encryptionKey = RNCryptor.randomData(ofLength: V3.keySize)
        let hmacKey = RNCryptor.randomData(ofLength: V3.keySize)
        let data = randomData()
	// ok: good crypto key
        let ciphertext = RNCryptor.EncryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey).encrypt(data: data)
        let plaintext: Data
        do {
            // ok: good crypto key
            plaintext = try RNCryptor.DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey).decrypt(data: ciphertext)
        } catch {
            plaintext = Data([0xaa])
            XCTFail("Caught: \(error)")
        }
        XCTAssertEqual(plaintext, data)
    }


    func foo13() {
        let password = "thepassword"
        let data = randomData()
	// ruleid: vuln static hardcoded key
        let ciphertext = RNCryptor.Encryptor(password: password).encrypt(data: data)
        let plaintext: Data
        do {
            plaintext = try RNCryptor.Decryptor(password: password).decrypt(data: ciphertext)
        } catch {
            plaintext = Data([0])
            XCTFail("Caught: \(error)")
        }
        XCTAssertEqual(plaintext, data)
    }



    func foo14() {
        let password = "thepassword"
        let datas = (0..<10).map{ _ in randomData() }
        let fullData = Data(datas.joined())
	// ruleid: vuln static hardcoded key
        let encryptor = RNCryptor.Encryptor(password: password)
        var ciphertext = Data()
        for data in datas {
            ciphertext.append(encryptor.update(withData: data))
        }
        ciphertext.append(encryptor.finalData())
        do {
            //vuln hardcoded key
            let decrypted = try RNCryptor.Decryptor(password: password).decrypt(data: ciphertext)
            XCTAssertEqual(fullData, decrypted)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }


    func foo15() {
        let data = NSMutableData(length: randomLength())!
        do {
            // ruleid: vuln static hardcoded key
            try aa_a = RNCryptor.Decryptor(password: "password").decrypt(data: data as Data)
            XCTFail("Should have thrown")
        } catch let error as RNCryptor.Error {
            XCTAssertEqual(error, RNCryptor.Error.unknownHeader)
        } catch {
            XCTFail("Threw wrong thing \(error)")
        }
    }



    func foo16() {
        let data = NSMutableData(length: randomLength())!
        do {
            // ruleid: vuln static hardcoded key
            try aa_a = RNCryptor.DecryptorV3(password: "").decrypt(data: data as Data)
            XCTFail("Should not thrown")
        } catch let error as RNCryptor.Error {
            XCTAssertEqual(error, RNCryptor.Error.unknownHeader)
        } catch {
            XCTFail("Threw wrong thing \(error)")
        }
    }



    func foo17() {
        let password = "thepassword"
        let data = randomData()
	// ruleid: vuln static hardcoded key
        let ciphertext = RNCryptor.Encryptor(password).encrypt(data)
        do {
            // ruleid: vuln static hardcoded key
            let _ = try RNCryptor.Decryptor("wrongpassword").decrypt(data: ciphertext)
            XCTFail("Should have failed to decrypt")
        } catch let err as RNCryptor.Error {
            XCTAssertEqual(err, RNCryptor.Error.hmacMismatch)
        } catch {
            XCTFail("Wrong error: \(error)")
        }
    }
    
    
    
    func foo18() {
        let password = "thepassword"
        let data = randomData()
	// ruleid: vuln static hardcoded key
        let ciphertext = RNCryptor.encrypt(data: data, withPassword: password)
        do {
            // ruleid: vuln static hardcoded key
            let decrypted = try RNCryptor.decrypt(data: ciphertext, withPassword: password)
            XCTAssertEqual(decrypted, data)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }
    
}    



class CryptoViewController: UIViewController {
// Check SwiftyRSA /////////////////////////////////////////////
    func foo19() {
        // ok: good crypto keys
        let publicKey = try! TestUtils.publicKey(name: "swiftyrsa-public") 
        let privateKey = try! TestUtils.privateKey(name: "swiftyrsa-private") 
    	let str = "Clear Text"
        let clearMessage = try ClearMessage(string: str, using: .utf8)
        let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
        let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }
    

    func foo20() {
    	let data = TestUtils.randomData(count: 2048)
        let clearMessage = ClearMessage(data: data)
        let publicKey = "qwertyuiopub" 
        let privateKey = "qwertyuiopriv"
        // ruleid: vuln static hardcoded keys
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
    }
  
    
    
// Check Arcane //////////////////////////////////////////////////
    func foo21() {
        let key = "test123"
        // ruleid: vuln static hardcoded key
        let encrypted = AES.encrypt(string, key: key)
        let decrypted = AES.decrypt(encrypted!, key: key)
        XCTAssertEqual(decrypted, string)
    }
    
    
    
    func foo22() {
        let key = nil
        // ruleid: vuln nil key 
    	let data = AES.encrypt(
            string.data(using: String.Encoding.utf8)!,
            key: key.data(using: String.Encoding.utf8)!
        )
        let decrypted = AES.decrypt(
            data!,
            key: key.data(using: String.Encoding.utf8)!
        )!

        XCTAssertEqual(String(data: decrypted, encoding: String.Encoding.utf8), string)
    }
} 
    



class CryptoViewController: UIViewController {    
// Check IDZSwiftCommonCrypto ///////////////////////////////////////////////////////////

    func foo23() {
    	var aesKey1Bytes = arrayFrom(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
    	// ruleid: vuln static hardcoded key 
        let aesEncrypt = Cryptor(operation:.encrypt, algorithm:.aes, options:.ECBMode,
            key:aesKey1Bytes, iv:Array<UInt8>())
        var dataOut = Array<UInt8>(repeating: UInt8(0), count: aesCipherText1Bytes.count)
        let (c, status) = aesEncrypt.update(byteArrayIn: aesPlaintext1Bytes, byteArrayOut: &dataOut)
        XCTAssert(status == .success);
        XCTAssert(aesCipherText1Bytes.count == Int(c) , "Counts are as expected")
        XCTAssertEqual(dataOut, aesCipherText1Bytes, "Obtained expected cipher text")
    }
    
    
    
    func foo24() {
    	var aesKey1Bytes = arrayFrom("2b7e151628aed2a6abf7158809cf4f3c")
    	// ruleid: vuln static hardcoded key 
        let aesEncrypt = Cryptor(.encrypt, .aes, .ECBMode,
            aesKey1Bytes, Array<UInt8>())
        var dataOut = Array<UInt8>(repeating: UInt8(0), count: aesCipherText1Bytes.count)
        let (c, status) = aesEncrypt.update(byteArrayIn: aesPlaintext1Bytes, byteArrayOut: &dataOut)
        XCTAssert(status == .success);
        XCTAssert(aesCipherText1Bytes.count == Int(c) , "Counts are as expected")
        XCTAssertEqual(dataOut, aesCipherText1Bytes, "Obtained expected cipher text")
    }
    
    
    
    func foo25() {
        var key = arrayFrom(hexString: "")
        let iv = arrayFrom(hexString: "00000000000000000000000000000000")
        let plainText = arrayFrom(hexString: "6bc1bee22e409f96e93d7e117393172a")
        let expectedCipherText = arrayFrom(hexString: "3ad77bb40d7a3660a89ecaf32466ef97")
        // ruleid: vuln static hardcoded empty key and static hardcoded IV 
        let cipherText = Cryptor(operation:.encrypt, algorithm:.aes, options:.None, key:key, iv:iv)
            .update(byteArray: plainText)?
            .final()
        XCTAssert(expectedCipherText.count == cipherText!.count , "Counts are as expected")
        XCTAssert(expectedCipherText == cipherText!, "Obtained expected cipher text")
        print(hexString(fromArray: cipherText!))
        let decryptedText = Cryptor(operation:.decrypt, algorithm:.aes, options:.None, key:key, iv:iv).update(byteArray: cipherText!)?.final()
        XCTAssertEqual(decryptedText!, plainText, "Recovered plaintext.")
    }
    
  
    
    func foo26() {
        let key = arrayFrom(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
        let imagePath = NSBundle.mainBundle().pathForResource("Riscal", ofType:"jpg")!
	var imageInputStream = NSInputStream(fileAtPath: imagePath)
	// ruleid: vuln static hardcoded key
	var aesenc = StreamCryptor(operation:.encrypt, algorithm:.aes, options:.PKCS7Padding, key:key, iv:Array<UInt8>())
	let (byteCount, _) = aesenc.update(byteArrayIn: imageInputStream, byteArrayOut: &dataOut)
	
	encrypt(aesenc, imageInputStream, encryptedFileOutputStream, 1024)
    }
    
    
    
    func foo27() {
    	// ruleid: vuln key generation with static hardcoded passphrase
        let idz_key = PBKDF.deriveKey(password: "passphrase", salt: "salt", prf: .SHA1, rounds: 1, derivedKeyLength: 20)
        return idz_key
    }
    
    
    
    func foo28() {
    	// ruleid: vuln key generation with static hardcoded passphrase
        let idz_key = PBKDF.deriveKey("passphrase", "salt", .SHA1, 1, 20)
        return idz_key
    }
    
    
    
    func foo29() {
        let keyArray: Array<UInt8> = [0xa4, 0x56, 0xbc, 0x7f, 0x41]
        let keyString = String(keyArray, encoding: .ascii)
    	// ruleid: vuln key generation with static hardcoded passphrase
        let idz_key = PBKDF.deriveKey(keyString, "salt", .SHA1, 1, 20)
        return idz_key
    }
         
} 
   
    
 
   
class CryptoViewController: UIViewController { 
// Check CryptoSwift //////////////////////////////////////////////    

    func foo30() {
        let password: Array<UInt8> = [0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64]
        let salt: Array<UInt8> = [0x78, 0x57, 0x8e, 0x5a, 0x5d, 0x63, 0xcb, 0x06]
        // ruleid: vuln static hardcoded key
        let value = try PKCS5.PBKDF1(salt: salt, password: password, iterations: 1000, keyLength: 16).calculate()
        XCTAssertEqual(value.toHexString(), "dc19847e05c64d2faf10ebfb4a3d2a20")
    }
    
    
    func foo31() {
        var password = arrayFrom(hexstring: "2b7e151628aed2a6abf7158809cf4f3c")
        let salt: Array<UInt8> = [0x78, 0x57, 0x8e, 0x5a, 0x5d, 0x63, 0xcb, 0x06]
        // ruleid: vuln static hardcoded key
        let value = PKCS5.PBKDF2(password: password, salt: salt, iterations: 1000, variant: .SHA1, keyLength: 16).calculate()
        XCTAssertEqual(value.toHexString(), "dc19847e05c64d2faf10ebfb4a3d2a20")
    } 
    
    
    
    func foo32() {
        let password: Array<UInt8> = [0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64]
        let salt: Array<UInt8> = [0x78, 0x57, 0x8e, 0x5a, 0x5d, 0x63, 0xcb, 0x06]
        // ruleid: vuln static hardcoded key
        let value = try PKCS5.PBKDF1(salt: salt, password: password, iterations: 1000, keyLength: 16).calculate()
        XCTAssertEqual(value.toHexString(), "dc19847e05c64d2faf10ebfb4a3d2a20")
    }
    
    
    func foo33() {
        var password = arrayFrom("2b7e151628aed2a6abf7158809cf4f3c")
        let salt: Array<UInt8> = [0x78, 0x57, 0x8e, 0x5a, 0x5d, 0x63, 0xcb, 0x06]
        // ruleid: vuln static hardcoded key
        let value = try PKCS5.PBKDF1(password, salt, 1000, 16).calculate()
        XCTAssertEqual(value.toHexString(), "dc19847e05c64d2faf10ebfb4a3d2a20")
    }
    
    
    
    func foo34() {
        let salt: Array<UInt8> = Array("saltsalt".utf8)
        // ruleid: vuln static hardcoded key
        let value = PKCS5.PBKDF1(password: Array("secretpass".utf8), salt: salt, iterations: 1000, keyLength: 16).calculate()
	return value
    }
    
    
    func foo35(salt: Data) {
        // ruleid: vuln static hardcoded key
        let value = try PKCS5.PBKDF2(password: nil, salt: salt, iterations: 1000, variant: .SHA1, keyLength: 16).calculate()
        XCTAssertEqual(value.toHexString(), "dc19847e05c64d2faf10ebfb4a3d2a20")
    }
    
    
    func foo36() {
        // ruleid: vuln static hardcoded key
        let value = PKCS5.PBKDF1(salt: Array("saltsalt".utf8), iterations: 1000, password: Array("secretpass"), keyLength: 16).calculate()
	return value
    }
    
    
    func foo37() {
        // ruleid: vuln static hardcoded key
        let value = PKCS5.PBKDF1(Array("secretpass"), Array("saltsalt".utf8), 1000, 16).calculate()
	return value
    }
    
        
    
    func foo38() {
        let key = "secretpass"
        let iv = "123456"
        // ruleid: vuln static hardcoded key and iv
        let aesenc = try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
        let encryptedBytes = try aesenc.encrypt(inputData.bytes)
        let encryptedData = Data(encryptedBytes)
	return encryptedData
    }


    func foo39() {
        let key = "secretpass"
        let iv = AES.randomIV(AES.blockSize)
        // ruleid: vuln static hardcoded key
        let aesenc = AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
        let encryptedBytes = try aesenc.encrypt(inputData.bytes)
        let encryptedData = Data(encryptedBytes)
	return encryptedData
    }


    func foo40() {
        let plaintext = "test"
        let key: Array<UInt8> = [0x78, 0x57, 0x8e, 0x5a, 0x5d, 0x63, 0xcb, 0x06]
        let iv: Array<UInt8> = [0x78, 0x57, 0x8e, 0x5a]
        // ruleid: vuln static hardcoded key and iv
        let encrypted = try AEADChaCha20Poly1305.encrypt(plaintext, key: key, iv: nonce, authenticationHeader: header)
        return encrypted
    }

    
    func foo41() {
        let plaintext = "test"
        let key: Array<UInt8> = [0x78, 0x57, 0x8e, 0x5a, 0x5d, 0x63, 0xcb, 0x06]
        let iv: Array<UInt8> = [0x78, 0x57, 0x8e, 0x5a]
        // ruleid: vuln static hardcoded key and iv
        let cipher = try ChaCha20(key: key, iv: iv)
        return try self.encrypt(cipher: cipher, plainText, key: key, iv: iv, authenticationHeader: authenticationHeader)
    }


    func foo42() {
        var key = arrayFrom(hexstring: "2b7e151628aed2a6abf7158809cf4f3c")
        var counter: Array<UInt8> = [1, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 74, 0, 0, 0, 0]
        let input = Array<UInt8>.init(repeating: 0, count: 129)
        // ruleid: vuln static hardcoded key 
        let chacha = try! ChaCha20(key: key, iv: Array(key[4..<16]))
        let result = chacha.process(bytes: input.slice, counter: &counter, key: key)
    }

    
    func foo43() {
        var key = arrayFrom("2b7e151628aed2a6abf7158809cf4f3c")
        let plainText = Array<UInt8>(repeating: 0, count: 48)
        // ruleid: vuln static hardcoded key
        let rabbit = try! Rabbit(key: key, iv: Array(key[4..<16]))
        let cipherText = try! rabbit.encrypt(plainText)
    }


    func foo44() {
        var key = arrayFrom(hexstring: "2b7e151628aed2a6abf7158809cf4f3c")
        let plainText = Array<UInt8>(repeating: 0, count: 48)
        // ruleid: vuln static hardcoded key
        let rabbit = try! Rabbit(key, Array(key[4..<16]))
        let cipherText = try! rabbit.encrypt(plainText)
    }
    

    func foo45(key: String) {
        var iv = arrayFrom(hexstring: "2b7e151628aed2a6abf7158809cf4f3c")
        let plainText = Array<UInt8>(repeating: 0, count: 48)
        // ruleid: vuln static hardcoded iv
        let rabbit = try! Rabbit(key, iv)
        let cipherText = try! rabbit.encrypt(plainText)
    }
    
}   


class CryptoViewController: UIViewController { 
// Check Apple-Swift-Crypto and Swift-Sodium /////////////////////////  

    func foo46() {        
        let message = Data("this is a message".utf8)
        // ruleid: vuln static hardcoded key
        let skey = arrayFrom(hexString: "pass123") 
        let sealed = try AES.GCM.seal(message, using: skey)
	XCTAssertThrowsError(try AES.GCM.open(sealed, using: skey))
    }
    
    
    func foo47() {        
        let message = Data("this is a message".utf8)
        // ruleid: vuln static hardcoded key
        let skey = arrayFrom(hexString: "pass123") 
        let sealed = try ChaChaPoly.open(message, using: skey)
	XCTAssertThrowsError(try AES.GCM.open(sealed, using: skey))
    }


    func foo48() {
        let sodium = Sodium()
        // ruleid: vuln static hardcoded key
        let pass = "pass123"
        let key = sodium.keyDerivation.derive(secretKey: pass,
                                          index: 0, length: 32,
                                          context: "Test 123 test!") 
    }


   
   func foo49() {
        let sodium = Sodium()
        let message1 = "Message 1".bytes
	let message2 = "Message 2".bytes
	let message3 = "Message 3".bytes
        // ruleid: vuln static hardcoded key
	let key = "Secretkey".bytes
	let stream_enc = sodium.secretStream.xchacha20poly1305.initPush(secretKey: key)!
	let encrypted1 = stream_enc.push(message: message1)!
	let encrypted2 = stream_enc.push(message: message2)!
	let encrypted3 = stream_enc.push(message: message3, tag: .FINAL)!
   } 
   
   
}
    


