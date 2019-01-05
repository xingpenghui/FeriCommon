package cn.feri.common.test;

import cn.feri.common.convert.Base64Util;
import cn.feri.common.convert.ScaleUtil;
import cn.feri.common.encrypt.EncryptUtil;
import org.junit.jupiter.api.Test;

import java.util.Map;

/**
 *@Author feri
 *@Date Created in 2018/12/18 10:11
 */
public class Pass_Test {
    @Test
    public void pass() throws Exception {
//        System.out.println("MD5:"+EncryptUtil.md5Enc("123456"));
//        System.out.println("SHA1:"+EncryptUtil.shaEnc(EncryptUtil.SHA1,"123456"));
//        System.out.println("SHA256:"+EncryptUtil.shaEnc(EncryptUtil.SHA256,"123456"));
//        System.out.println("SHA512:"+EncryptUtil.shaEnc(EncryptUtil.SHA512,"123456"));
//        String key=EncryptUtil.createAESKeyHex();
//        System.out.println("AES-KEY:"+key);
//        String mw=EncryptUtil.AESEnc(key,"123456");
//        System.out.println("AES加密:"+mw);
//        System.out.println("AES解密:"+EncryptUtil.AESDec(key,mw));
        Map<String,String> keys=EncryptUtil.createKeys(1024);
        String mw=EncryptUtil.privateEncrypt("123456",EncryptUtil.getPrivateKey(keys.get("privateKey")));
        System.out.println("RSA:"+mw);
        System.out.println("RSA:"+EncryptUtil.publicDecrypt(mw,EncryptUtil.getPublicKey(keys.get("publicKey"))));

    }
}
