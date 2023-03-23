package example

public class VulnClass {

  protected void BadCrypto1() {     
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()); 
    byte[] input = "qwertyuiop".getBytes(); 
    byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
    SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
    Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding", "BC");
    System.out.println("input : " + new String(input));
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
    int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
    ctLength += cipher.doFinal(cipherText, ctLength);
    System.out.println("cipher: " + new String(cipherText).getBytes("UTF-8").toString() + " bytes: " + ctLength);
  }



  protected void BadCrypto2() {     
    try {
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES"); 
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv); 
        byte[] encrypted = cipher.doFinal(value.getBytes());
        return Base64.encodeBase64String(encrypted);
    } catch (Exception ex) {
        ex.printStackTrace();
    }
    return null;
  }



}

