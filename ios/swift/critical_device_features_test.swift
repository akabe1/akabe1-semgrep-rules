import example

class Critical_Device_Features_Test { 

    func foo1() {
        // ruleid: vuln sms sending
        let messageComposeVC = MFMessageComposeViewController()
        messageComposeVC.messageComposeDelegate = self
        messageComposeVC.body = "Hello World!"
        messageComposeVC.recipients = ["+12345678910"]
        presentViewController(messageComposeVC, animated: true, completion: nil)
        
        // ruleid: vuln mail sending       
        let mail = MFMailComposeViewController()
        mail.mailComposeDelegate = self
        mail.setToRecipients(["you@yoursite.com"])
        mail.setMessageBody("<p>You are so awesome!</p>", isHTML: true)
        present(mail, animated: true)
            
    }

    func foo2(number: String) {
        // ruleid: vuln tel call
        let tel = URL(string: "tel://\(number)")
        UIApplication.shared.canOpenURL(tel) {
            UIApplication.shared.open(tel, options: [:], completionHandler: nil)
        }
        // ruleid: vuln mail sending       
        let mail = URL(string: "mailto://" + "you@yoursite.com") 
        // ruleid: vuln sms sending             
        UIApplication.sharedApplication().openURL(NSURL(string: "sms:+1234567890"))
    }
    
    
    func foo3() {    
        let messageBody = "hello"
        let urlSafeBody =  messageBody.stringByAddingPercentEncodingWithAllowedCharacters(NSCharacterSet.URLHostAllowedCharacterSet())
        let urlSafeBody = urlSafeBody
        url = NSURL(string: "sms:&body=\(urlSafeBody)")
        // ruleid: vuln sms sending 
        WKExtension.sharedExtension().openSystemURL(url)
    }

}
