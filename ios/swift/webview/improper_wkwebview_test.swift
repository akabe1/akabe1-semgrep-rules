import example


// Check WKWebView 
class WKViewController: WKViewController {


    func foo1() -> Bool {
        // vuln WKWebView
        let webView = WKWebView(frame: view.bounds)
        let url = URL(string: "https://www.test.com/test.js")!
        webView.loadData(URLRequest(url: url))
        webView.allowsBackForwardNavigationGestures = true
    }
    
    
    // False Negative at the moment "func $FUNC(...) {" is yet not supported in semgrep 
    func foo2(app: UIApplication, openURL url: NSURL, options: [String : AnyObject]) -> Bool {
        let name = inUrlName
        let html = "Hi \(name)"
        // vuln WKWebView
        let webView = WKWebView()
        webView.loadHTMLString(html, baseURL:nil)
    }

    
    
    func foo3() {
        let preferences = WKPreferences()
        preferences.javaScriptEnabled = false
        let config = WKWebViewConfiguration()
        config.preferences = preferences
        // good WKWebView
        let webView = WKWebView(frame: view.bounds, configuration: config)
        let url = URL(string: "https://www.test.com/test.js")!
        webView.loadData(URLRequest(url: url))
        webView.allowsBackForwardNavigationGestures = true
    }
    
    
     func foo4() {
        let preferences = WKWebpagePreferences()
        preferences.allowsContentJavaScript = false
        // good WKWebView
        let webView = WKWebView()
        let url = URL(string: "https://www.test.com/test.js")!
        webView.configuration.defaultWebpagePreferences = preferences
        webView.loadData(URLRequest(url: url))
    }



    func foo5() {
        let preferences = WKWebpagePreferences()
        preferences.allowsContentJavaScript = false
        preferences.allowUniversalAccessFromFileURLs = true
        let config = WKWebViewConfiguration()
        config.preferences = preferences
        // vuln WKWebView
        let webView = WKWebView(frame: view.bounds, configuration: config)       
        let url = NSURL(string: "http://www.test.com/test.js")
        let urlRequest = NSURLRequest(URL: url!)
        webView.loadRequest(urlRequest)
        webView.navigationDelegate = self
        view.addSubview(webView)
    }
    
    
    
    
    func foo6() {
        // vuln WKWebView
        let webView = WKWebView()       
        let url = NSURL(string: "http://www.test.com/test.js")
        let urlRequest = NSURLRequest(URL: url!)
        webView.configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        webView.loadRequest(urlRequest)
    }
    
    
    
}



// Check Javascript to Native bridge
class JavaScriptBridgeMessageHandler: NSObject, WKScriptMessageHandler {
    func invokeNativeOperation() {
        let javaScriptCallBack = "javascriptBridgeCallBack('\(functionFromJS)','\(result)')"
        // bad practice JavaScript to Native bridge
        message.webView.evaluateJavaScript(javaScriptCallBack, completionHandler: nil)
    }
    
}



