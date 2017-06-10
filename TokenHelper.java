import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Created by IbeeSaas on 2017/6/10.
 */
public class TokenHelper {
    static Logger log = LoggerFactory.getLogger(TokenHelper.class);

    private String accessKey;

    private String secretKey;

    private static final String TOKEN_VERSION = "v2";

    private final List<String> allowedMethods = Arrays.asList("GET", "POST", "PUT", "DELETE", "HEAD");

    private static final char[] DIGITS_LOWER =
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    public TokenHelper() {
    }

    public TokenHelper(String ak, String sk) {
        this.accessKey = ak;
        this.secretKey = sk;
    }

    /**
     * generate the token according the request or response contents
     *
     * @param urlPath    the url of request
     * @param method     request method, must be one of 'GET', 'POST', 'DELETE', 'HEAD', 'PUT'
     * @param queryParam the query string of request
     * @param body       the post body for request, or response body
     * @param expireTime the token expired time
     * @return the token
     */
    public String generateToken(String urlPath, String method, String queryParam, String body, int expireTime) {
        if (accessKey == null || accessKey.isEmpty() || secretKey == null || secretKey.isEmpty()) {
            log.debug("generateToken Invalid AK or SK ! ");
            throw new IllegalArgumentException("Invalid AK or SK");
        }
        if (urlPath == null || urlPath.isEmpty()) {
            log.debug("generateToken Empty url path ");
            throw new IllegalArgumentException("Empty url path");
        }
        if (!allowedMethods.contains(method)) {
            log.debug("generateToken invalid request method ");
            throw new IllegalArgumentException("invalid request method");
        }
        String token;
        try {
            // |v2-{AK}-{ExpireTime}|{SK}|
            StringBuffer sbSign = new StringBuffer(String.format("|%s-%s-%d|%s|", TOKEN_VERSION,
                    accessKey, expireTime, secretKey));

            // {UrlPath}|
            sbSign.append(this.decodeUtf8(urlPath)).append("|");

            // {Method}|
            sbSign.append(method).append("|");

            // {QueryParam}|
            if (queryParam != null && !queryParam.isEmpty()) {
                List<String> qsArray = new ArrayList<String>();
                for (String kv : queryParam.split("&")) {
                    String[] t = kv.split("=");
                    if (t.length > 1) {
                        qsArray.add(String.format("%s=%s", this.decodeUtf8(t[0]), this.decodeUtf8(t[1])));
                    } else {
                        qsArray.add(String.format("%s=", this.decodeUtf8(t[0])));
                    }
                }
                Collections.sort(qsArray);
                boolean first = true;
                for (String s : qsArray) {
                    if (first) {
                        first = false;
                    } else {
                        sbSign.append("&");
                    }
                    sbSign.append(s);
                }
            }
            sbSign.append("|");

            // {body}|
            if (body != null && !body.isEmpty()) {
                sbSign.append(body);
            }
            sbSign.append("|");

            log.info("sbSign info: {}", sbSign);
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.reset();
            digest.update(sbSign.toString().getBytes("UTF-8"));

            //  v2-{AK}-{ExpireTime}-{Signature}
            token = String.format("%s-%s-%s-%s", TOKEN_VERSION, accessKey, expireTime,
                    new String(this.encodeHex(digest.digest())));
        } catch (Exception e) {
            log.debug("generateToken IllegalStateException! "+e);
            throw new IllegalStateException("Bad encoded url path or query string");

        }
        return token;
    }

    private static String decodeUtf8(String url) {
        try {
            return URLDecoder.decode(url, "UTF-8");
        } catch (UnsupportedEncodingException var2) {
            return url;
        }
    }

    private static char[] encodeHex(final byte[] data) {
        final int l = data.length;
        final char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS_LOWER[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS_LOWER[0x0F & data[i]];
        }
        return out;
    }
}
