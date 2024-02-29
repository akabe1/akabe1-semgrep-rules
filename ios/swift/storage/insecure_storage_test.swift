import example

// ruleid: vuln hardcoded secret
fileprivate let aesKey = "superSecretKey"
// ruleid: vuln hardcoded secret
fileprivate let iv = "superSecretIV"


class StorageViewController: UIViewController {


    func foo1(picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [NSObject : AnyObject]) {
        if let pickedImage = info[UIImagePickerControllerOriginalImage] as? UIImage {
            imageView.contentMode = .ScaleAspectFit
            imageView.image = pickedImage
        }
        // ruleid: vuln cleartext storage via UIImageWriteToSavedPhotosAlbum
        UIImageWriteToSavedPhotosAlbum(pickedImage!, self, nil, nil)
        dismissViewControllerAnimated(true, completion: nil)
    }
     
     
    func foo2() {
        let plistName = "secretfile.plist"
        // ruleid: potential vuln cleartext storage
        let filePath = URL(fileURLWithPath: Bundle.main.resourcePath! + "/" + plistName)
        let encodedData = try PropertyListEncoder().encode(self)
        let succeed = encodedData.write(to: filePath)
    
    }
     
     
    func foo3() {
        var myDict: NSDictionary?
        // ruleid: potential vuln cleartext storage
        let path = NSBundle.mainBundle().pathForResource("Config", ofType: "plist") 
        myDict = NSDictionary(contentsOfFile: path)
    }
  
  
  
    func foo4() {
        // ruleid: vuln cleartext storage NSUserDefaults
        var test = "secret_test"
        UserDefaults.standard.set(test, forKey: "PIN")
    }

       
}
