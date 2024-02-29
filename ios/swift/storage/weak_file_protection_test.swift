import example



// Check Weak File Protection 
class FPViewController: FPViewController {

    
    func foo1() {
        let documentsPath = NSURL(fileURLWithPath:   NSSearchPathForDirectoriesInDomains(.DocumentDirectory, .UserDomainMask, true)[0])
        let filename = "\(documentsPath)/tmp_activeTrans.txt"
        // ruleid: vuln File Protection        
        let protection = [NSFileProtectionKey: NSFileProtectionCompleteUnlessOpen]
        do {
            try NSFileManager.defaultManager().setAttributes(protection, ofItemAtPath: filename)
        } catch let error as NSError {
            NSLog("Unable to change attributes: \(error.debugDescription)")
        }
        try textToWrite.write(filename, atomically:true)
    }
    
    
    
    func foo2() {    
        let documentsPath = NSURL(fileURLWithPath: NSSearchPathForDirectoriesInDomains(.DocumentDirectory, .UserDomainMask, true)[0])
        let filename = "\(documentsPath)/tmp_activeTrans.txt"
        // ruleid: vuln File Protection 
        try textData.writeToFile(filepath, options: FileProtectionType.DataWritingFileProtectionCompleteUntilFirstUserAuthentication);
    }
    
    
    
    func foo3() {
        try FileManager.default.setAttributes([FileAttributeKey.protectionKey: FileProtectionType.complete], ofItemAtPath: fileURL.path)
        // ok: good File Protection 
        try (fileURL as NSURL).setResourceValue(URLFileProtection.complete, forKey: .fileProtectionKey)
    }
    
    
    
    func foo4() { 
        // ruleid: vuln File Protection   
        FileManager.default.createFile(atPath: filePath, contents: "secret text".data(using: .utf8), attributes: [FileAttributeKey.protectionKey: FileProtectionType.completeUnlessOpen]
)
    }
    
    
    
    
    func foo5() {
        // ruleid: vuln File Protection 
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUnlessOpen], ofItemAtPath: fileURL.path)
        try (fileURL as NSURL).setResourceValue(URLFileProtection.completeUnlessOpen, forKey: .fileProtectionKey)
    }
    
    
    
    func foo6() {    
        let documentsPath = NSURL(fileURLWithPath: NSSearchPathForDirectoriesInDomains(.DocumentDirectory, .UserDomainMask, true)[0])
        let filename = "\(documentsPath)/tmp_activeTrans.txt"
        // ruleid: vuln File Protection 
        try textData.writeToURL(filepath, atomically: false, encoding: NSUTF8StringEncoding, options: .DataWritingFileProtectionCompleteUnlessOpen);

    }
    
    
    func foo7() {
        let documentsPath = NSURL(fileURLWithPath:   NSSearchPathForDirectoriesInDomains(.DocumentDirectory, .UserDomainMask, true)[0])
        let filename = "\(documentsPath)/tmp_activeTrans.txt"
        // ruleid: vuln File Protection        
        do {
            try NSFileManager.defaultManager().setAttributes([NSFileProtectionKey: NSFileProtectionCompleteUnlessOpen], ofItemAtPath: filename)
        } catch let error as NSError {
            NSLog("Unable to change attributes: \(error.debugDescription)")
        }
        try textToWrite.write(filename, atomically:true)
    }
    
    
    func foo8() {
        // ruleid: vuln File Protection
        try NSFileManager.defaultManager().setAttributes([FileAttributeKey.protectionKey: FileProtectionType.completeUnlessOpen], ofItemAtPath: fileURL.path)
        try (fileURL as NSURL).setResourceValue(URLFileProtection.complete, forKey: .fileProtectionKey)
    }
    
    
    func foo9() { 
        // ruleid: vuln File Protection
        let attr = [FileAttributeKey.protectionKey: FileProtectionType.completeUnlessOpen, FileAttributeKey.creationDate: NSDate()]
        FileManager.default.createFile(atPath: filePath, contents: "secret text".data(using: .utf8), attributes: attr )
    }
    
    
    func foo10() { 
        // ruleid: vuln File Protection
        FileManager().createFile(atPath: filePath, contents: "secret text".data(using: .utf8), attributes: [FileAttributeKey.protectionKey: FileProtectionType.completeUnlessOpen, FileAttributeKey.creationDate: NSDate()] )
    }
    
    
}




