import example
import LocalAuthentication


// Check biometric authentication for LocalAuthentication framework
class BiometricAuth_Test { 

    func foo1() {
        private let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
           // Could not evaluate policy error
        }

        // vuln biometric auth using LocalAuthentication framework
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authenticate with biometrics, please.") { success, error in
            guard success else {
                // Authentication failed
            }
            // Authentication success
            enterToApp()
        }
            
    }
    
    
    
    func foo2() {
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        if canEvaluate {
            if context.biometryType != .none {
                // vuln biometric auth using LocalAuthentication framework
                context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authenticate with biometrics, please.") { success, error in
                if success {
                    // Authentication success
                    enterToApp()
                }}    
             }
        }
    }
    
    
    
    
    
    
    func foo3() {
        var error: Unmanaged<CFError>?
        // vuln biometric auth using Security framework with Keychain not completely secure flag "kSecAccessControlBiometryAny"
        let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAccessControlBiometryAny, &error)
        
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: "com.test.exampleapp",
            kSecAttrAccount: "test account",
            kSecValueData: "test_psw".data(using: .utf8)!,
            kSecAttrAccessControl: accessControl
        ] as CFDictionary
    
        var result: AnyObject?
        let status = SecItemAdd(query, &result)
        
        let searchQuery = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: "com.test.exampleapp",
            kSecAttrAccount: "test account",
            kSecUseOperationPrompt: "Please, pass authorisation to enter this area",
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ] as CFDictionary
        
        var queryResult: AnyObject?
        let queryStatus = SecItemCopyMatching(searchQuery, &item)
        
        if queryStatus == noErr {
            let password = String(data: queryResult as! Data, encoding: .utf8)!
            // Authentication success
            enterToApp()
        } else {
            // Authentication failed
        }
    }
    
    
    
    
    
    func foo4() {
        var error: Unmanaged<CFError>?
        // good biometric auth using Security framework with Keychain secure flags "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly" and "SecAccessControlCreateFlags.biometryCurrentSet"
        guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, SecAccessControlCreateFlags.biometryCurrentSet, &error) else {
            // failed to create AccessControl object
            return
        }
        
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: "com.test.exampleapp",
            kSecAttrAccount: "test account",
            kSecValueData: "test_psw".data(using: .utf8)!,
            kSecAttrAccessControl: accessControl
        ] as CFDictionary
    
        var result: AnyObject?
        let status = SecItemAdd(query, &result)
        
        let searchQuery = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: "com.test.exampleapp",
            kSecAttrAccount: "test account",
            kSecUseOperationPrompt: "Please, pass authorisation to enter this area",
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ] as CFDictionary
        
        var queryResult: AnyObject?
        let queryStatus = SecItemCopyMatching(searchQuery, &item)
        
        if queryStatus == noErr {
            let password = String(data: queryResult as! Data, encoding: .utf8)!
            // Authentication success
            enterToApp()
        } else {
            // Authentication failed
        }
    }
    
    
    
    func foo5() {
        var error: Unmanaged<CFError>?
        // good biometric auth using Security framework with Keychain secure flags "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly" and "touchIDCurrentSet" 
        let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .touchIDCurrentSet, &error)!
        
        let query = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: "com.test.exampleapp",
            kSecAttrAccount: "test account",
            kSecValueData: "test_psw".data(using: .utf8)!,
            kSecAttrAccessControl: accessControl
        ] as CFDictionary
    
        var result: AnyObject?
        let status = SecItemAdd(query, &result)
        
        let searchQuery = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: "com.test.exampleapp",
            kSecAttrAccount: "test account",
            kSecUseOperationPrompt: "Please, pass authorisation to enter this area",
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ] as CFDictionary
        
        var queryResult: AnyObject?
        let queryStatus = SecItemCopyMatching(searchQuery, &item)
        
        if queryStatus == noErr {
            let password = String(data: queryResult as! Data, encoding: .utf8)!
            // Authentication success
            enterToApp()
        } else {
            // Authentication failed
        }
    }
    

}


