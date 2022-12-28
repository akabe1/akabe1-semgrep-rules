import example


// Check pinning for AlamoFire old versions (ver < 5.x)
public class NetworkManager_oldAlamoFire {
    fileprivate (set) var requestsDictionary: [String : [NetworkRequest]] = [ : ]
    
    
    public static let manager: Alamofire.SessionManager_1 = {
   
        let configuration = URLSessionConfiguration.default
        configuration.httpAdditionalHeaders = Alamofire.SessionManager.defaultHTTPHeaders
        configuration.timeoutIntervalForRequest = Configuration.defaultTimeout
        
        
        // vuln pinning AlamoFire old version 
        let serverTrustPolicies: [String: ServerTrustPolicy] = [
            "pin.test.net": trustPolicyPinning,
            "insecure.example.net": .disableevaluation,
            "insecure.test.com": .disableEvaluation,
            "pin.example.com": trustPolicyPinning,
            "pin.test.net": trustPolicyPinning,
            "insecure.asd.gov": .disableEvaluation,
        ]

        return Alamofire.SessionManager(configuration: configuration, serverTrustPolicyManager: ServerTrustPolicyManager(policies: serverTrustPolicies))
    }()


    public static let manager: Alamofire.SessionManager_2 = {
        // vuln pinning AlamoFire old version 
        let serverTrustPolicies: [String: ServerTrustPolicy] = [
            "test.example.com": .PinCertificates(
                certificates: ServerTrustPolicy.certificatesInBundle(),
                validateCertificateChain: false, 
                validateHost: true
            ),
            "insecure.expired-apis.com": trustPolicyPinning
        ]
        return Alamofire.SessionManager(configuration: configuration, serverTrustPolicyManager: ServerTrustPolicyManager(policies: serverTrustPolicies))
    }()



    public static let manager: Alamofire.SessionManager_3 = {
        // vuln pinning AlamoFire old version 
        let serverTrustPolicies: [String: ServerTrustPolicy] = [
            "test.example.com": .PinCertificates(
                certificates: ServerTrustPolicy.certificatesInBundle(),
                validateCertificateChain: true, 
                validateHost: false
            ),
            "pin.example-apis.com": trustPolicyPinning
        ]
        return Alamofire.SessionManager(configuration: configuration, serverTrustPolicyManager: ServerTrustPolicyManager(policies: serverTrustPolicies))
    }()        
        

    public static let manager: Alamofire.SessionManager_4 = {
        // vuln pinning AlamoFire old version 
        let serverTrustPolicies: [String: ServerTrustPolicy] = [
            "test.example.com": .PinPublicKeys(
                keys: ServerTrustPolicy.keysInBundle(),
                validateCertificateChain: true, 
                validateHost: false
            ),
            "pin.example-apis.com": trustPolicyPinning
        ]
        return Alamofire.SessionManager(configuration: configuration, serverTrustPolicyManager: ServerTrustPolicyManager(policies: serverTrustPolicies))
    }()


    public static let manager: Alamofire.SessionManager_5 = {
        // vuln pinning AlamoFire old version 
        let serverTrustPolicies: [String: ServerTrustPolicy] = [
            "test.example.com": .PinPublicKeys(
                keys: ServerTrustPolicy.keysInBundle(),
                validateCertificateChain: false, 
                validateHost: true
            ),
            "pin.example-apis.com": trustPolicyPinning
        ]
        return Alamofire.SessionManager(configuration: configuration, serverTrustPolicyManager: ServerTrustPolicyManager(policies: serverTrustPolicies))
    }()

    public static let manager: Alamofire.SessionManager_6 = {
        // good pinning AlamoFire old version 
        let serverTrustPolicies: [String: ServerTrustPolicy] = [
            "test.example.com": .PinPublicKeys(
                keys: ServerTrustPolicy.keysInBundle(),
                validateCertificateChain: true, 
                validateHost: true
            ),
            "pin.example-apis.com": trustPolicyPinning
        ]

        return Alamofire.SessionManager(configuration: configuration, serverTrustPolicyManager: ServerTrustPolicyManager(policies: serverTrustPolicies))
    }()
    
}  

//////////////////////////////////////////////////////////////////



// Check pinning for AlamoFire v5.x
class class_newAlamoFire: ServerTrustPolicyTestCase {
    // MARK: Validate Certificate Chain Without Validating Host


    // vuln pinning AlamoFire v5.x
    func foo1() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let certificates = [TestCertificates.leafValidDNSName]
        // vuln AlamoFire 5.x pinning
        let serverTrustPolicy = PinnedCertificatesTrustEvaluator(certificates: certificates,
                                                                 performDefaultValidation: false,
                                                                 validateHost: false)

        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }


    func foo2() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let certificates = [TestCertificates.leafValidDNSName]
        // vuln AlamoFire 5.x pinning
        let serverTrustPolicy = PinnedCertificatesTrustEvaluator(certificates: certificates, acceptSelfSignedCertificates: true)

        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }



    func foo3() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let keys = [TestCertificates.leafValidDNSName].af.publicKeys
        // vuln AlamoFire 5.x pinning
        let serverTrustPolicy = PublicKeysTrustEvaluator(keys: keys, validateHost: false)

        setRootCertificateAsLoneAnchorCertificateForTrust(serverTrust)
        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }


    func foo4() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafExpired.trust
        let certificates = [TestCertificates.rootCA]
        // vuln AlamoFire 5.x pinning
        let serverTrustPolicy = PinnedCertificatesTrustEvaluator(certificates: certificates,
                                                                 performDefaultValidation: false,
                                                                 acceptSelfSignedCertificates: true,
                                                                 validateHost: true)

        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }



    func foo5() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafExpired.trust
        let certificates = [TestCertificates.rootCA]
        // good AlamoFire 5.x pinning
        let serverTrustPolicy = PinnedCertificatesTrustEvaluator(certificates: certificates,
                                                                 performDefaultValidation: false)

        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }



    func foo6() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let keys = [TestCertificates.leafValidDNSName].af.publicKeys
        // good AlamoFire 5.x pinning
        let serverTrustPolicy = PublicKeysTrustEvaluator(keys: keys)

        setRootCertificateAsLoneAnchorCertificateForTrust(serverTrust)
        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }



    func foo7() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let keys = [TestCertificates.leafValidDNSName].af.publicKeys
        // good AlamoFire 5.x pinning
        let serverTrustPolicy = PublicKeysTrustEvaluator(keys: keys, validateHost: true)

        setRootCertificateAsLoneAnchorCertificateForTrust(serverTrust)
        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }




    func foo8() {
        let evaluators: [String: ServerTrustEvaluating] = [
                "your.domain.com": PublicKeysTrustEvaluator(
                performDefaultValidation: false,
                validateHost: true)
        ]
        // vuln AlamoFire 5.x pinning
        let serverTrustManager = ServerTrustManager(evaluators: evaluators, [ "demo.test.com": DisabledEvaluator()])
        let session = Session(serverTrustManager: serverTrustManager)
    }




    func foo9() {
        // vuln AlamoFire 5.x pinning       
        let session = Session(configuration: configuration, serverTrustManager: ServerTrustManager(evaluators: [ "demo.test.com": DisabledTrustEvaluator()]))
    }


}

////////////////////////////////////////////////////////////////////////



// Check pinning for TrustKit
final class TrustKitService: NSObject, ApplicationService {
    static let kMyDomain = "test.example.com"

    func footrust1(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]? = nil) -> Bool {
	// good Trustkit pinning
        let trustKitConfig = [
            kTSKPinnedDomains: [
                TrustKitService.kMyDomain: [
                    kTSKEnforcePinning: true,
                    kTSKIncludeSubdomains: true,
                    kTSKPublicKeyAlgorithms: [kTSKAlgorithmRsa2048],
                    kTSKPublicKeyHashes: [
                        "public key 1",
                        "public key 2"
                    ]]
            ]] as [String: Any]

        TrustKit.initSharedInstance(withConfiguration: trustKitConfig)

        return true
    }


    func footrust2(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]? = nil) -> Bool {
	// vuln Trustkit pinning
        let trustKitConfig = [
            kTSKPinnedDomains: [
                TrustKitService.kMyDomain: [
                    kTSKEnforcePinning: false,
                    kTSKIncludeSubdomains: true,
                    kTSKPublicKeyAlgorithms: [kTSKAlgorithmRsa2048],
                    kTSKPublicKeyHashes: [
                        "public key 1",
                        "public key 2"
                    ]]
            ]] as [String: Any]

        TrustKit.initSharedInstance(withConfiguration: trustKitConfig)

        return true
    }
    
    
        func footrust3(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]? = nil) -> Bool {
	   // vuln Trustkit pinning         
           let trustKitConfig: [String: Any] = [
               kTSKSwizzleNetworkDelegates: false,
               kTSKPinnedDomains: [
                       "test.example.com": [
                           kTSKEnforcePinning: true,
                           kTSKIncludeSubdomains: false,
                           kTSKPublicKeyHashes: [
                              "ZCv/DWs7Y/6OPAoRMqopsFj77y+a/mCD4DRZuhTtXwg=",
                              "AAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBCCC="
                          ],
                          kTSKReportUris: ["https://website.net/trustkit/report"],
                       ]
               ]]
              
               TrustKit.initSharedInstance(withConfiguration: trustKitConfig)

               return true
        }

}

////////////////////////////////////////////////////////////////////////////////////

// Check pinning for AFSecurityPolicy 
class class_AFNetworking: SecPolicyTestCase {

        func fooAFNetworking1() {
            var uploadSessionManager = self.uploadSessionManager
            // vuln AFSecurityPolicy 
            let securityPolicy = AFSecurityPolicy(pinningMode: AFSSLPinningMode.none)
                securityPolicy.validatesDomainName = true
                securityPolicy.validatesCertificateChain = true
                securityPolicy.allowInvalidCertificates = false
            uploadSessionManager.securityPolicy = securityPolicy


        }



        func fooAFNetworking2() {
           let certificatePath = NSBundle.mainBundle().pathForResource("pinned-certificate", ofType: "cer")! 
           let certificateData = NSData(contentsOfFile: certificatePath)! 
           // vuln AFSecurityPolicy
           let securityPolicy = AFSecurityPolicy(pinningMode: AFSSLPinningMode.Certificate) 
           securityPolicy.pinnedCertificates = [certificateData]; 
           securityPolicy.validatesCertificateChain = false 
           self.securityPolicy = securityPolicy 
        }



        func fooAFNetworking3() {
           let certificatePath = NSBundle.mainBundle().pathForResource("pinned-certificate", ofType: "cer")! 
           let certificateData = NSData(contentsOfFile: certificatePath)! 
           // vuln AFSecurityPolicy
           let securityPolicy = AFSecurityPolicy(pinningMode: AFSSLPinningMode.PublicKey) 
           securityPolicy.pinnedCertificates = [certificateData]; 
           securityPolicy.allowInvalidCertificates = true 
           self.securityPolicy = securityPolicy 
        }
        
        
        
        func fooAFNetworking4() {
           let certificatePath = NSBundle.mainBundle().pathForResource("pinned-certificate", ofType: "cer")! 
           let certificateData = NSData(contentsOfFile: certificatePath)! 
           // good AFSecurityPolicy
           let securityPolicy = AFSecurityPolicy(pinningMode: AFSSLPinningMode.Certificate) 
           securityPolicy.pinnedCertificates = [certificateData]; 
           securityPolicy.validatesDomainName = true
           securityPolicy.validatesCertificateChain = true
           securityPolicy.allowInvalidCertificates = false
           self.securityPolicy = securityPolicy 
        }


        func fooAFNetworking5() {
           let manager = AFHTTPSessionManager()
           // vuln AFSecurityPolicy
           let securityPolicy = AFSecurityPolicy.default()
           securityPolicy.allowInvalidCertificates = false
           securityPolicy.validatesDomainName = true
           manager.securityPolicy = securityPolicy
        }


}


