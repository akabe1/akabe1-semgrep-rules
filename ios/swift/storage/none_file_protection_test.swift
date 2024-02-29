import example


// Check None File Protection 
class FPViewController: FPViewController {

    
    func foo1() {
        let documentsPath = NSURL(fileURLWithPath:   NSSearchPathForDirectoriesInDomains(.DocumentDirectory, .UserDomainMask, true)[0])
        let filename = "\(documentsPath)/tmp_activeTrans.txt"
        // ruleid: vuln File Protection        
        let protection = [NSFileProtectionKey: NSFileProtectionNone]
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
        try textData.writeToFile(filepath, options: FileProtectionType.DataWritingFileProtectionNone);
    }
    
    
    
    func foo3() {
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: fileURL.path)
        // ok: good File Protection 
        try (fileURL as NSURL).setResourceValue(URLFileProtection.complete, forKey: .fileProtectionKey)
    }
    
  
      func foo4() { 
        // ruleid: vuln File Protection   
        FileManager.default.createFile(atPath: filePath, contents: "secret text".data(using: .utf8), attributes: [FileAttributeKey.protectionKey: FileProtectionType.none]
)
    }
  
    

    
}




