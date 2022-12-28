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
                //vuln hardcoded key
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
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
                //vuln nil key
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
                //vuln empty key
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


}
    ////////////////////////////////////////////////////////////////////////////



class CryptoViewController: UIViewController { 
    // Check RNCrypto ///////////////////////////////////////////////////////////

    func foo4(_ textField: UITextField) -> Bool {
        let dataPath = URL(fileURLWithPath: NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first!).appendingPathComponent("/secret-data").absoluteURL
        if textField == passwordTextField {
            textField.resignFirstResponder()
            if textField.text == nil {
                DVIAUtilities.showAlert(title: "Oops", message: "Please enter a password", viewController: self)
            } else {
                let data = passwordTextField.text?.data(using: String.Encoding.utf8)
                //vuln RNCrypto hardcoded key
                let encryptedData = try? RNEncryptor.encryptData(data, with: kRNCryptorAES256Settings, password: "@daloq3as$qweasdlasasjdnj")
                try? encryptedData?.write(to: dataPath, options: .atomic)
                UserDefaults.standard.set(true, forKey: "loggedIn")
                UserDefaults.standard.synchronize()
                firstTimeUserView.isHidden = true
            }
        } else if textField == returningUserPasswordTextField {
            let data = returningUserPasswordTextField.text?.data(using: String.Encoding.utf8)
            let encryptedData = try? Data(contentsOf: dataPath)
            
            //vuln RNCrypto hardcoded key
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







 func foo5() {
        let encryptKey = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f".dataFromHexEncoding!
        let hmacKey = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00".dataFromHexEncoding!
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03000203 04050607 08090a0b 0c0d0e0f 0001981b 22e7a644 8118d695 bd654f72 e9d6ed75 ec14ae2a a067eed2 a98a56e0 993dfe22 ab5887b3 f6e3cdd4 0767f519 5eb5".dataFromHexEncoding!
        //vuln hardcoded key (false negative)
        let decryptor = RNCryptor.DecryptorV3(encryptionKey: encryptKey, hmacKey: hmacKey)
        do {
            let decrypted = try decryptor.decrypt(data: ciphertext)
            XCTAssertEqual(decrypted, plaintext)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }



    func foo6() {
        let password = "thepassword"
        let encryptionSalt = "0001020304050607".dataFromHexEncoding!
        let hmacSalt = "0102030405060708".dataFromHexEncoding!
        let iv = "02030405060708090a0b0c0d0e0f0001".dataFromHexEncoding!
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8".dataFromHexEncoding!
	//vuln hardcoded key
        let encryptor = RNCryptor.EncryptorV3(password: password, encryptionSalt: encryptionSalt, hmacSalt: hmacSalt, iv: iv)

        let encrypted = encryptor.encrypt(data: plaintext)
        XCTAssertEqual(encrypted, ciphertext)
    }



    func foo7() {
        let password = "thepassword"
        let plaintext = "01".dataFromHexEncoding!
        let ciphertext = "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8".dataFromHexEncoding!
	//vuln hardcoded key
        let decryptor = RNCryptor.Decryptor(password: password)
        do {
            let decrypted = try decryptor.decrypt(data: ciphertext)
            XCTAssertEqual(decrypted, plaintext)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }


    func foo8() {
        let encryptionKey = RNCryptor.randomData(ofLength: V3.keySize)
        let hmacKey = RNCryptor.randomData(ofLength: V3.keySize)
        let data = randomData()
	//good crypto key
        let ciphertext = RNCryptor.EncryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey).encrypt(data: data)
        let plaintext: Data
        do {
            //good crypto key
            plaintext = try RNCryptor.DecryptorV3(encryptionKey: encryptionKey, hmacKey: hmacKey).decrypt(data: ciphertext)
        } catch {
            plaintext = Data([0xaa])
            XCTFail("Caught: \(error)")
        }
        XCTAssertEqual(plaintext, data)
    }


    func foo9() {
        let password = "thepassword"
        let data = randomData()
	//vuln hardcoded key
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



    func foo10() {
        let password = "thepassword"
        let datas = (0..<10).map{ _ in randomData() }
        let fullData = Data(datas.joined())
	//vuln hardcoded key
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


    func foo11() {
        let data = NSMutableData(length: randomLength())!
        do {
            //vuln hardcoded key
            try aa_a = RNCryptor.Decryptor(password: "password").decrypt(data: data as Data)
            XCTFail("Should have thrown")
        } catch let error as RNCryptor.Error {
            XCTAssertEqual(error, RNCryptor.Error.unknownHeader)
        } catch {
            XCTFail("Threw wrong thing \(error)")
        }
    }


    func foo12() {
        let data = NSMutableData(length: randomLength())!
        do {
            //vuln hardcoded key
            try aa_a = RNCryptor.DecryptorV3(password: "").decrypt(data: data as Data)
            XCTFail("Should not thrown")
        } catch let error as RNCryptor.Error {
            XCTAssertEqual(error, RNCryptor.Error.unknownHeader)
        } catch {
            XCTFail("Threw wrong thing \(error)")
        }
    }


    func foo13() {
        let password = "thepassword"
        let data = randomData()
	//vuln hardcoded key
        let ciphertext = RNCryptor.Encryptor(password: password).encrypt(data: data)
        do {
            //vuln hardcoded key
            let _ = try RNCryptor.Decryptor(password: "wrongpassword").decrypt(data: ciphertext)
            XCTFail("Should have failed to decrypt")
        } catch let err as RNCryptor.Error {
            XCTAssertEqual(err, RNCryptor.Error.hmacMismatch)
        } catch {
            XCTFail("Wrong error: \(error)")
        }
    }
    
    
    

    func foo14() {
        let password = "thepassword"
        let data = randomData()
	//vuln hardcoded key
        let ciphertext = RNCryptor.encrypt(data: data, withPassword: password)
        do {
            //vuln hardcoded key
            let decrypted = try RNCryptor.decrypt(data: ciphertext, withPassword: password)
            XCTAssertEqual(decrypted, data)
        } catch {
            XCTFail("Caught: \(error)")
        }
    }
    
}    
    ///////////////////////////////////////////////////////////////////////////
    


class CryptoViewController: UIViewController {    
    // Check IDZSwiftCommonCrypto ///////////////////////////////////////////////////////////
    func foo15() {
    	var aesKey1Bytes = arrayFrom(hexString: "2b7e151628aed2a6abf7158809cf4f3c")
    	// vuln hardcoded key (false negative TODO)
        let aesEncrypt = Cryptor(operation:.encrypt, algorithm:.aes, options:.ECBMode,
            key:aesKey1Bytes, iv:Array<UInt8>())
        var dataOut = Array<UInt8>(repeating: UInt8(0), count: aesCipherText1Bytes.count)
        let (c, status) = aesEncrypt.update(byteArrayIn: aesPlaintext1Bytes, byteArrayOut: &dataOut)
        XCTAssert(status == .success);
        XCTAssert(aesCipherText1Bytes.count == Int(c) , "Counts are as expected")
        XCTAssertEqual(dataOut, aesCipherText1Bytes, "Obtained expected cipher text")
    }
    
    
    

    func foo16() {
        var key = arrayFrom(hexString: "")
        let iv = arrayFrom(hexString: "00000000000000000000000000000000")
        let plainText = arrayFrom(hexString: "6bc1bee22e409f96e93d7e117393172a")
        let expectedCipherText = arrayFrom(hexString: "3ad77bb40d7a3660a89ecaf32466ef97")
        // vuln empty key (false negative)
        let cipherText = Cryptor(operation:.encrypt, algorithm:.aes, options:.None, key:key, iv:iv)
            .update(byteArray: plainText)?
            .final()
    
        XCTAssert(expectedCipherText.count == cipherText!.count , "Counts are as expected")
        XCTAssert(expectedCipherText == cipherText!, "Obtained expected cipher text")
    
        print(hexString(fromArray: cipherText!))
    
        let decryptedText = Cryptor(operation:.decrypt, algorithm:.aes, options:.None, key:key, iv:iv).update(byteArray: cipherText!)?.final()
        XCTAssertEqual(decryptedText!, plainText, "Recovered plaintext.")
    }
    
    ///////////////////////////////////////////////////////////////////////////  
}   
    
    
class CryptoViewController: UIViewController {
    // Check SwiftyRSA ///////////////////////////////////////////////////////////
    func foo17() {
        //good crypto keys
        let publicKey = try! TestUtils.publicKey(name: "swiftyrsa-public") 
        let privateKey = try! TestUtils.privateKey(name: "swiftyrsa-private") 
    	let str = "Clear Text"
        let clearMessage = try ClearMessage(string: str, using: .utf8)
        
        let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
        let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
        
        XCTAssertEqual(try? decrypted.string(encoding: .utf8), str)
    }
    

    func foo18() {
    	let data = TestUtils.randomData(count: 2048)
        let clearMessage = ClearMessage(data: data)
        let publicKey = "qwertyuiopub" 
        let privateKey = "qwertyuiopriv"
        // vuln hardcoded keys
        do {
            let encrypted = try clearMessage.encrypted(with: publicKey, padding: .PKCS1)
            let decrypted = try encrypted.decrypted(with: privateKey, padding: .PKCS1)
            XCTAssertEqual(decrypted.data, data)
        }
    }
    
    
    ///////////////////////////////////////////////////////////////////////////  
    
    
    // Check Arcane ///////////////////////////////////////////////////////////
    func foo17() {
        let key = "test123"
        //vuln hardcoded key
        let encrypted = AES.encrypt(string, key: key)
        let decrypted = AES.decrypt(encrypted!, key: key)
        XCTAssertEqual(decrypted, string)
    }
    
    

    func foo18() {
        let key = nil
        //vuln null key 
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
    ///////////////////////////////////////////////////////////////////////////      
    
class CryptoViewController: UIViewController { 

    // Check CryptoSwift ///////////////////////////////////////////////////////////    
    func foo19() {
        let password: Array<UInt8> = [0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64]
        let salt: Array<UInt8> = [0x78, 0x57, 0x8e, 0x5a, 0x5d, 0x63, 0xcb, 0x06]
        // vuln hardcoded key
        let value = try PKCS5.PBKDF1(password: password, salt: salt, iterations: 1000, keyLength: 16).calculate()
        XCTAssertEqual(value.toHexString(), "dc19847e05c64d2faf10ebfb4a3d2a20")
    }
    
    ///////////////////////////////////////////////////////////////////////////      
    
    
    
    // Check Apple-Swift-Crypto ///////////////////////////////////////////////////////////    
    func foo20() {
        let skey = arrayFrom(hexString: "pass123") 
        // vuln hardcoded key
        let message = Data("this is a message".utf8)
        let sealed = try AES.GCM.seal(message, using: skey)
	XCTAssertThrowsError(try AES.GCM.open(sealed, using: skey))
    }
    
    ///////////////////////////////////////////////////////////////////////////      
    
        
}
