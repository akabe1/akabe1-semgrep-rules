import example


// Check pinning for AlamoFire old versions (ver < 5.x)
public class NetworkManager_oldAlamoFire {
    fileprivate (set) var requestsDictionary: [String : [NetworkRequest]] = [ : ]
    
    public static let manager: Alamofire.SessionManager_1 = {
   
        let configuration = URLSessionConfiguration.default
        configuration.httpAdditionalHeaders = Alamofire.SessionManager.defaultHTTPHeaders
        configuration.timeoutIntervalForRequest = Configuration.defaultTimeout
        
        
        // ruleid: vuln pinning AlamoFire old version 
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
        // ruleid: vuln pinning AlamoFire old version 
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
        // ruleid: vuln pinning AlamoFire old version 
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
        // ruleid: vuln pinning AlamoFire old version 
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
        // ruleid: vuln pinning AlamoFire old version 
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
        // ok: good pinning AlamoFire old version 
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




// Check pinning for AlamoFire v5.x
class class_newAlamoFire: ServerTrustPolicyTestCase {
    // MARK: Validate Certificate Chain Without Validating Host


    func foo1() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let certificates = [TestCertificates.leafValidDNSName]
        // ruleid: vuln AlamoFire 5.x pinning without certificate and host validation
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
        // ruleid: vuln AlamoFire 5.x pinning accepting self-signed certificates
        let serverTrustPolicy = PinnedCertificatesTrustEvaluator(certificates: certificates, acceptSelfSignedCertificates: true)
        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }



    func foo3() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let keys = [TestCertificates.leafValidDNSName].af.publicKeys
        // ruleid: vuln AlamoFire 5.x pinning without host validation
        let serverTrustPolicy = PublicKeysTrustEvaluator(keys: keys, validateHost: false)
        setRootCertificateAsLoneAnchorCertificateForTrust(serverTrust)
        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }


    func foo4() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafExpired.trust
        let certificates = [TestCertificates.rootCA]
        // ruleid: vuln AlamoFire 5.x pinning without certificate chain validation and accepting self-signed certificates
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
        // ruleid: vuln AlamoFire 5.x pinning without certificate chain validation
        let serverTrustPolicy = PinnedCertificatesTrustEvaluator(certificates: certificates,
                                                                 performDefaultValidation: false)

        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }



    func foo6() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let keys = [TestCertificates.leafValidDNSName].af.publicKeys
        // ok: good AlamoFire 5.x pinning
        let serverTrustPolicy = PublicKeysTrustEvaluator(keys: keys)
        setRootCertificateAsLoneAnchorCertificateForTrust(serverTrust)
        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }



    func foo7() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let keys = [TestCertificates.leafValidDNSName].af.publicKeys
        // ok: good AlamoFire 5.x pinning
        let serverTrustPolicy = PublicKeysTrustEvaluator(keys: keys, validateHost: true)
        setRootCertificateAsLoneAnchorCertificateForTrust(serverTrust)
        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }




    func foo8() {
        // ok: good AlamoFire 5.x pinning
        let evaluators: [String: ServerTrustEvaluating] = [
                "your.domain.com": PublicKeysTrustEvaluator(
                performDefaultValidation: true,
                acceptSelfSignedCertificates: false,
                validateHost: true)
        ]
        // ruleid: vuln AlamoFire 5.x pinning disabled evaluator
        let serverTrustManager = ServerTrustManager(evaluators: evaluators, [ "demo.test.com": DisabledEvaluator()])
        let session = Session(serverTrustManager: serverTrustManager)
    }




    func foo9() {
        // ruleid: vuln AlamoFire 5.x pinning disabled trust-evaluator     
        let session = Session(configuration: configuration, serverTrustManager: ServerTrustManager(evaluators: [ "demo.test.com": DisabledTrustEvaluator()]))
    }
    
    
    func foo10() {
        let host = "test.alamofire.org"
        let serverTrust = TestTrusts.leafValidDNSName.trust
        let keys = [TestCertificates.leafValidDNSName].af.publicKeys
        // ok: good AlamoFire 5.x pinning
        let serverTrustPolicy = PublicKeysTrustEvaluator(keys: keys, performDefaultValidation: true, validateHost: true, acceptSelfSignedCertificates: false)
        setRootCertificateAsLoneAnchorCertificateForTrust(serverTrust)
        let result = Result { try serverTrustPolicy.evaluate(serverTrust, forHost: host) }
        XCTAssertTrue(result.isSuccess, "server trust should pass evaluation")
    }


}





// Check pinning for TrustKit
final class TrustKitService: NSObject, ApplicationService {
    static let kMyDomain = "test.example.com"

    func footrust1(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]? = nil) -> Bool {
        let trustKitConfig = [
            kTSKPinnedDomains: [
                TrustKitService.kMyDomain: [
                    // ok: good Trustkit pinning
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
        let trustKitConfig = [
            kTSKPinnedDomains: [
                TrustKitService.kMyDomain: [
                    // ruleid: vuln Trustkit pinning disabled
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
                           // ruleid: vuln Trustkit pinning enabled but not including subdomains via kTSKIncludeSubdomains
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



// Check pinning for AFSecurityPolicy 
class class_AFNetworking: SecPolicyTestCase {

        func fooAFNetworking1() {
            var uploadSessionManager = self.uploadSessionManager
            // ruleid: vuln AFSecurityPolicy 
            let securityPolicy = AFSecurityPolicy(pinningMode: AFSSLPinningMode.none)
                securityPolicy.validatesDomainName = true
                securityPolicy.validatesCertificateChain = true
                securityPolicy.allowInvalidCertificates = false
            uploadSessionManager.securityPolicy = securityPolicy
        }



        func fooAFNetworking2() {
           let certificatePath = NSBundle.mainBundle().pathForResource("pinned-certificate", ofType: "cer")! 
           let certificateData = NSData(contentsOfFile: certificatePath)! 
           // ruleid: vuln AFSecurityPolicy
           let securityPolicy = AFSecurityPolicy(pinningMode: AFSSLPinningMode.Certificate) 
           securityPolicy.pinnedCertificates = [certificateData]; 
           securityPolicy.validatesCertificateChain = false 
           self.securityPolicy = securityPolicy 
        }



        func fooAFNetworking3() {
           let certificatePath = NSBundle.mainBundle().pathForResource("pinned-certificate", ofType: "cer")! 
           let certificateData = NSData(contentsOfFile: certificatePath)! 
           // ruleid: vuln AFSecurityPolicy
           let securityPolicy = AFSecurityPolicy(pinningMode: AFSSLPinningMode.PublicKey) 
           securityPolicy.pinnedCertificates = [certificateData]; 
           securityPolicy.allowInvalidCertificates = true 
           self.securityPolicy = securityPolicy 
        }
        
        
        
        func fooAFNetworking4() {
           let certificatePath = NSBundle.mainBundle().pathForResource("pinned-certificate", ofType: "cer")! 
           let certificateData = NSData(contentsOfFile: certificatePath)! 
           // ok: good AFSecurityPolicy
           let securityPolicy = AFSecurityPolicy(pinningMode: AFSSLPinningMode.Certificate) 
           securityPolicy.pinnedCertificates = [certificateData]; 
           securityPolicy.validatesDomainName = true
           securityPolicy.validatesCertificateChain = true
           securityPolicy.allowInvalidCertificates = false
           self.securityPolicy = securityPolicy 
        }


        func fooAFNetworking5() {
           let manager = AFHTTPSessionManager()
           // ruleid: vuln AFSecurityPolicy
           let securityPolicy = AFSecurityPolicy.default()
           securityPolicy.allowInvalidCertificates = false
           securityPolicy.validatesDomainName = true
           manager.securityPolicy = securityPolicy
        }


}


