import example
import UIKit
import SafariServices


// Check UIWebView 
class UIViewController: UIViewController {

    // vuln UIWebView
    @IBOutlet weak var webView: UIWebView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        
        let url = NSURL (string: "https://www.test.net");
        let request = NSURLRequest(URL: url!);
        webView.loadRequest(request);
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}


class UIWebViewController: UIViewController {
   
    func foo() {
        // vuln UIWebView
        let webView1 = UIWebView()
        webView1.loadHTMLString("<html><body><p>Hello World!</p></body></html>", baseURL: nil)
    }
}





// Check SFSafariViewController
class SafariViewController_test: SafariViewController {
    func foo(_ which: Int) {
        if let url = URL(string: "https://www.test.net/read/\(which + 1)") {
            let config = SFSafariViewController.Configuration()
            config.entersReaderIfAvailable = true
	    // vuln SFSafariViewController
            let vc = SFSafariViewController(url: url, configuration: config)
            present(vc, animated: true)
        }
    }
    
}





