package cn.feri.common.encrypt;

import cn.feri.common.convert.Base64Util;
import cn.feri.common.convert.ScaleUtil;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 *@Author feri
 *@Date Created in 2018/12/18 10:06
 * 密码加解密
 */
public class EncryptUtil {
    public static final String SHA1="SHA-1";//SHA-1，SHA-224和SHA-256适用于长度不超过2^64二进制位的消息
    public static final String SHA256="SHA-256";
    public static final String SHA512="SHA-512";//SHA-384和SHA-512适用于长度不超过2^128二进制位的消息
    public static final String ENCODING="UTF-8"; //编码格式
    //MD5
    public static String md5Enc(String content){
        // 生成一个MD5加密计算摘要
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
            // 计算md5函数
            md.update(content.getBytes());
            // digest()最后确定返回md5 hash值，返回值为8位字符串。因为md5 hash值是16位的hex值，实际上就是8位的字符
            // BigInteger函数则将8位的字符串转换成16位hex值，用字符串来表示；得到字符串形式的hash值
            //一个byte是八位二进制，也就是2位十六进制字符（2的8次方等于16的2次方）
            return new BigInteger(1, md.digest()).toString(16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    //SHA
    /**
     * @Author Feri
     * @param type SHA的类型 SHA1 SHA256 SHA512
     * */
    public static String shaEnc(String type,String content){
        // 生成一个SHA加密计算摘要
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(type);
            // 计算md5函数
            md.update(content.getBytes());
            // digest()最后确定返回hash值，返回值为8位字符串。因为hash值是16位的hex值，实际上就是8位的字符
            // BigInteger函数则将8位的字符串转换成16位hex值，用字符串来表示；得到字符串形式的hash值
            //一个byte是八位二进制，也就是2位十六进制字符（2的8次方等于16的2次方）
            return new BigInteger(1, md.digest()).toString(16);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    //AES
    //生成秘钥
    public static byte[] createAESKey(){
        KeyGenerator kgen = null;// 创建AES的Key生产者
        try {
            kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            // kgen.init(128, new SecureRandom(password.getBytes()));
            // 128位的key生产者
            //加密没关系，SecureRandom是生成安全随机数序列，password.getBytes()是种子，只要种子相同，序列就一样，所以解密只要有password就行
            SecretKey secretKey = kgen.generateKey();// 根据用户密码，生成一个密钥
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    public static String createAESKeyHex(){
        KeyGenerator kgen = null;// 创建AES的Key生产者
        try {
            kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            // kgen.init(128, new SecureRandom(password.getBytes()));
            // 128位的key生产者
            //加密没关系，SecureRandom是生成安全随机数序列，password.getBytes()是种子，只要种子相同，序列就一样，所以解密只要有password就行
            SecretKey secretKey = kgen.generateKey();// 根据用户密码，生成一个密钥
            return ScaleUtil.parseByte2HexStr(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    //AES加密
    public static String AESEnc(byte[] key,String content){
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = null;// 创建密码器
        try {
            cipher = Cipher.getInstance("AES");
            byte[] byteContent = content.getBytes(ENCODING);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);// 初始化
            byte[] result = cipher.doFinal(byteContent);
            return ScaleUtil.parseByte2HexStr(result); // 加密
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    //AES解密
    public static String AESDec(byte[] key,String content){
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = null;// 创建密码器
        try {
            cipher = Cipher.getInstance("AES");
            byte[] byteContent =ScaleUtil.parseHexStr2Byte(content);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);// 初始化
            byte[] result = cipher.doFinal(byteContent);
            return new String(result,ENCODING); // 解密
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    //AES加密
    public static String AESEnc(String key,String content){
       return AESEnc(ScaleUtil.parseHexStr2Byte(key),content);
    }
    //AES解密
    public static String AESDec(String key,String content){
      return AESDec(ScaleUtil.parseHexStr2Byte(key),content);
    }
    //RSA
    //生成秘钥
    public static Map<String, String> createKeys(int keySize){
        //为RSA算法创建一个KeyPairGenerator对象
        KeyPairGenerator kpg;
        try{
            kpg = KeyPairGenerator.getInstance("RSA");
            //初始化KeyPairGenerator对象,密钥长度
            kpg.initialize(keySize);
            //生成密匙对
            KeyPair keyPair = kpg.generateKeyPair();
            //得到公钥
            Key publicKey = keyPair.getPublic();
            String publicKeyStr = Base64Util.base64Enc(publicKey.getEncoded());
            //得到私钥
            Key privateKey = keyPair.getPrivate();
            String privateKeyStr =Base64Util.base64Enc(privateKey.getEncoded());
            Map<String, String> keyPairMap = new HashMap<String, String>();
            keyPairMap.put("publicKey", publicKeyStr);
            keyPairMap.put("privateKey", privateKeyStr);
            return keyPairMap;
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 得到公钥
     * @param publicKey 密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //通过X509编码的Key指令获得公钥对象
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64Util.base64Dec(publicKey));
        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
        return key;
    }

    /**
     * 得到私钥
     * @param privateKey 密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static RSAPrivateKey getPrivateKey(String privateKey) throws Exception {
        //通过PKCS#8编码的Key指令获得私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64Util.base64Dec(privateKey));
        RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        return key;
    }
    //公钥加密
    public static String publicEncrypt(String content, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(content.getBytes(ENCODING));
        return Base64Util.base64Enc(bytes);
    }
    //私钥解密
    public static String privateDecrypt(String content, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = cipher.doFinal(Base64Util.base64Dec(content));
        return new String(bytes,ENCODING);
    }

    //私钥加密
    public static String privateEncrypt(String content, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] bytes = cipher.doFinal(content.getBytes(ENCODING));
        return Base64Util.base64Enc(bytes);
    }

    //公钥解密
    public static String publicDecrypt(String content, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(Base64Util.base64Dec(content));
        return new String(bytes,ENCODING);
    }
}
