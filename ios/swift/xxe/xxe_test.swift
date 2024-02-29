import example


// Check XXE 
class XXEViewController: ViewController {

    func foo1() {
        var success: Bool
        var rawXmlConvToData: NSData = rawXml.data(using: NSUTF8StringEncoding)
        var myParser: XMLParser = NSXMLParser(data: rawXmlConvToData)
        // ruleid: vuln xxe
        myParser.shouldResolveExternalEntities = true
        myParser.delegate = self
        myParser.parse()
    }
    
    


    func foo2(xml: String) {
        parser = NSXMLParser(data: rawXml.dataUsingEncoding(NSUTF8StringEncoding)!)
        parser.delegate = self
        // ruleid: vuln xxe
        parser.shouldResolveExternalEntities = true
        parser.parse()
    }
    
    
    
    func foo3(xml: String) {
        parser = NSXMLParser(data: rawXml.dataUsingEncoding(NSUTF8StringEncoding)!)
        parser.delegate = self
        // ok: good xxe (external entities resolution disabled by default)
        parser.parse()
    }
    
    
    func foo4(xml: String) {
        parser = NSXMLParser(data: rawXml.dataUsingEncoding(NSUTF8StringEncoding)!)
        parser.delegate = self
        // ok: good xxe (external entities resolution explicitly disabled)
        parser.shouldResolveExternalEntities = false
        parser.parse()
    }
    
}



