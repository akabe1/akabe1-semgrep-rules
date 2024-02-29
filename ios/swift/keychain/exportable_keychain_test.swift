import example



// Check exportable keychain 
class keychainController: keychainViewController {

    func foo1() {
        // False Negative vuln keychain (default kSecAttrAccessible is kSecAttrAccessibleWhenUnlocked)
        // At the moment this is a false negative with this rules
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
        // ruleid: vuln keychain
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(query as CFDictionary, nil)
    }
    
    
    func foo3() {
        let token = "secret"
        var query = [String : AnyObject]()
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecValueData as String] = token as AnyObject?
        // ruleid: vuln keychain
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAlways
        SecItemAdd(query as CFDictionary, nil)
    }
    
    
    
    func foo4() {
        let token = "secret"
        var query = [String : AnyObject]()
        query[kSecClass as String] = kSecClassGenericPassword
        query[kSecValueData as String] = token as AnyObject?
        // ok: good keychain
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        SecItemAdd(query as CFDictionary, nil)
    }  
    
    
    func foo5() {
        // ruleid: vuln keychain
        var query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrAccount as String: account,
                                    kSecAttrServer as String: server,
                                    kSecValueData as String: password,
                                    kSecAttrAccessible as String: kSecAttrAccessibleAlways]
        SecItemAdd(query,r)
    }
    
    
    func foo6() {
        // ruleid: vuln keychain
        let keychainItemQuery = [
            kSecValueData: "test123".data(using: .utf8)!,
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock
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
    
    
    func foo8(_ data: Data, forKey key: String) {
        let query: [NSString: Any] = [
            kSecClass: secClass,
            kSecAttrAccount: key,
            kSecAttrAccessGroup: accessGroup
        ]
        // ruleid: vuln keychain
        let attributes: [NSString: Any] = [
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock
        ] 
    }  
    
}
