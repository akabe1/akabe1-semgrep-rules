import example


// Check NoSql Injection
class NoSqlViewController: UIViewController {  

    func foo1(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        let emailId = message.body as? String
        // vuln realm NoSQL injection
        let email = realm.objects(Email.self).filter("id == '" + emailId + "'")
    }

    
    func foo2() {
        // good realm NoSQL 
        let email = realm.objects(Email.self).filter("id == '" + "1234" + "'")
    }


}


