import example



// Check weak keychain protection
class keychainController: keychainViewController {

    func foo1() {
        // ok: good keychain (default kSecAttrAccessible is kSecAttrAccessibleWhenUnlocked)
        let keychainItemQuery = [
            kSecValueData: "test123".data(using: .utf8)!,
            kSecClass: kSecClassGenericPassword
        ] as CFDictionary

        let status = SecItemAdd(keychainItemQuery, nil)
        print("Operation finished with status: \(status)")
    }


    
    func foo2() {
        let token = "secret"
        var query = [String : AnyObject]()
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecValueData as String] = token as AnyObject?
        // ruleid: vuln keychain (weak protection)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAlwaysThisDeviceOnly
        SecItemAdd(query as CFDictionary, nil)
    }
    
    
    
    func foo3() {
        let token = "secret"
        var query = [String : AnyObject]()
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecValueData as String] = token as AnyObject?
        // ruleid: vuln keychain (weak protection)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAlways
        SecItemAdd(query as CFDictionary, nil)
    }
    
    
    
    func foo4() {
        // ok: good keychain
        let keychainItemQuery = [
            kSecValueData: "test123".data(using: .utf8)!,
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        ] as CFDictionary
        
        let status = SecItemAdd(keychainItemQuery, nil)
        print("Operation finished with status: \(status)")
    }
    
   
    
    func foo5() {
        // ruleid: vuln keychain (weak protection)
        var query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrAccount as String: account,
                                    kSecAttrServer as String: server,
                                    kSecValueData as String: password,
                                    kSecAttrAccessible as String: kSecAttrAccessibleAlways]
        SecItemAdd(query,r)
    }
    
    
    
    func foo6() {
        // ruleid: vuln keychain (weak protection)
        let keychainItemQuery = [
            kSecValueData: "test123".data(using: .utf8)!,
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccessible: kSecAttrAccessibleAlwaysThisDeviceOnly
        ] as CFDictionary

        let status = SecItemAdd(keychainItemQuery, nil)
        print("Operation finished with status: \(status)")
    }
    
    
    
    func foo7(_ data: Data, forKey key: String) {
        let query: [NSString: Any] = [
            kSecClass: secClass,
            kSecAttrAccount: key,
            kSecAttrAccessGroup: accessGroup
        ]
        // ok: good keychain
        let attributes: [NSString: Any] = [
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ] 
    }
       
}
