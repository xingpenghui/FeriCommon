package cn.feri.common.convert;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import java.io.IOException;
/**
 *@Author feri
 *@Date Created in 2018/12/18 11:04
 */
public class Base64Util {
    //base64转码
    public static String base64Enc(byte[] content){
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(content);
    }
    //base64解码
    public static byte[] base64Dec(String content){
        BASE64Decoder decoder = new BASE64Decoder();
        try {
            return decoder.decodeBuffer(content);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}