import example



// Check Log Injection
class LogViewController: UIViewController {
    var name: String = ""
    @IBOutlet weak var labelName: UILabel!
    @IBOutlet weak var textFieldName: UITextField!
    
    @IBAction func foo1(sender: UIButton) {
        let name = textFieldName.text!
        // ruleid: vuln log injection (false negative because $FUNC(...) at the moment is not correctly supported by semgrep Swift
        NSLog("Input value = %@", textFieldName.text)
        labelName.text = "Hello \(name)"
    }
}



class LogViewController: UIViewController {
    @IBOutlet weak var label: NSTextField!
    
    @IBAction func foo2(sender: UIButton) {
        // ruleid: vuln log injection (false negative because $FUNC(...) at the moment is not correctly supported by semgrep Swift
        NSLog("Input value = %@", label.stringValue)
    }
    
    
    @IBAction func foo3() {
        // ruleid: vuln log injection
        NSLog("Input value = %@", label.stringValue)
    }
    
}




class LogViewController: UIViewController {  
    @IBOutlet weak var txtUserInput: UITextField!

    override func viewDidLoad() {
        super.viewDidLoad()
    }

    func foo4() {
        //Read untrusted user input
        let injParam = txtUserInput.text
        //Try to conver user input to into integer 
        let num = Int(injParam)
        //Then log unvalidated user input in case of failure
        if num == nil {
            // vuln log injection (false negative)
            NSLog("Input value = %@", injParam)
        }         
    }
        
}


class LogViewController: UIViewController { 

    func foo5(_ webView: UIWebView) {
        // ruleid: vuln log injection
        let html = webView.stringByEvaluatingJavaScript(from: "document.body.innerHTML")
        NSLog("Input value = %@", html)
    }
    
    
    func foo6(_ webView: UIWebView) {
        // ruleid: vuln log injection
        let passwordNameValue = webview.stringByEvaluatingJavaScript(from: "document.getElementById('password').value").value
        NSLog("Input value = %@", passwordNameValue)
    }



    func foo7(webView: WKWebView, navigationAction: WKNavigationAction) {
        let urlStr = navigationAction.request.url?.absoluteString
        let components = URLComponents(url: urlStr, resolvingAgainstBaseURL: false)
        // ruleid: vuln log injection
        NSLog("Query value = %@", components.query)
        NSLog("Host value = %@", components.host)
    }


    func foo8(webView: WKWebView, navigationAction: WKNavigationAction) {
        let urlStr = navigationAction.request.url?.absoluteString
        let components = URLComponents(url: urlStr, resolvingAgainstBaseURL: false)
        if let components = components {
            components.host
            components.query
            components.percentEncodedQuery
            let queryItems = components.queryItems
                for queryItem in queryItems {
                    // ruleid: vuln log injection
                    NSLog("Input nmae = %@", queryItem.name)
                    NSLog("Input value = %@", queryItem.value)
                }
       }
    }



    func foo9(webView: WKWebView) {
        let urlString = webView.request!.url!.absoluteString
        // ruleid: vuln log injection
        NSLog("Input value = %@", urlString)
    }


    func foo10(webView: WKWebView, navigationAction: WKNavigationAction) {
        // Get the current URL
        let urlStr = navigationAction.request.url?.absoluteString
        // ruleid: vuln log injection
        NSLog("Input value = %@", urlStr)
    }
    
    
    func foo11(webView: UIWebView) {
        // Get the current URL
        let url = WebView.request?.mainDocumentURL
        // ruleid: vuln log injection
        NSLog("Input value = %@", url)
    }  
    
    
    func foo12(webView: UIWebView) {
        // Get the current URL    
        let url = webView.stringByEvaluatingJavaScriptFromString("window.location.href")!
        // ruleid: vuln log injection
        NSLog("Input value = %@", url)
    }
}

