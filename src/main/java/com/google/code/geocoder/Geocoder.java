package com.google.code.geocoder;

import com.google.code.geocoder.model.*;
import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.EnumMap;
import java.util.Map;

/**
 * @author <a href="mailto:panchmp@gmail.com">Michael Panchenko</a>
 */
public class Geocoder {
    private static final Logger logger = LoggerFactory.getLogger(Geocoder.class);

    private static final String GEOCODE_REQUEST_HOST = "maps.googleapis.com";
    private static final String GEOCODE_REQUEST_SERVER_HTTP = "http://" + GEOCODE_REQUEST_HOST;
    private static final String GEOCODE_REQUEST_SERVER_HTTPS = "https://" + GEOCODE_REQUEST_HOST;
    private static final String GEOCODE_REQUEST_QUERY_BASIC = "/maps/api/geocode/json?sensor=false";
    private static final String ENCODING = "UTF-8";

    protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    static {
        OBJECT_MAPPER.configure(DeserializationConfig.Feature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private final String clientId;
    private final Mac mac;
    private final String apiKey;

    public Geocoder() {
        this(null,null,null);
    }

    protected Geocoder(String clientId, Mac mac, String apiKey) {
        this.clientId = clientId;
        this.mac = mac;
        this.apiKey = apiKey;
    }

    public static Geocoder createFromApiKey(String apiKey) {
        return new Geocoder(null,null,apiKey);
    }

    public static Geocoder createFromClientId(String clientId, String clientKey) throws InvalidKeyException {
        return new Geocoder(
                checkNotNullOrEmpty(clientId, "clientId"),
                getMAC(checkNotNullOrEmpty(clientKey, "clientKey")),
                null);
    }

    protected static String checkNotNullOrEmpty(String value, String fieldName) {
        if (value == null || value.length() == 0) {
            throw new IllegalArgumentException(fieldName+" is not defined");
        }
        return value;
    }

    public GeocodeResponse geocode(final GeocoderRequest geocoderRequest) throws IOException {

        final String urlString = getURL(geocoderRequest);

        return request(urlString);
    }

    protected GeocodeResponse request(String urlString) throws IOException {
        final URL url = new URL(urlString);
        final Reader reader = new BufferedReader(new InputStreamReader(url.openStream(), ENCODING));
        try {
            return OBJECT_MAPPER.readValue(reader, GeocodeResponse.class);
        } finally {
            reader.close();
        }
    }

    public static String getGeocoderHost() {
        return GEOCODE_REQUEST_HOST;
    }

    protected String getURL(final GeocoderRequest geocoderRequest) throws UnsupportedEncodingException {
        logger.trace("Request {}", geocoderRequest);
        final StringBuilder url = getURLQuery(geocoderRequest);

        if (mac == null) {
            // add server name to URL
            url.insert(0, GEOCODE_REQUEST_SERVER_HTTP);
        } else {
            addClientIdAndSignURL(url);

            // add server name to URL
            url.insert(0, GEOCODE_REQUEST_SERVER_HTTPS);
        }

        logger.trace("FULL Request URL: {}", url);
        return url.toString();
    }

    protected StringBuilder getURLQuery(GeocoderRequest geocoderRequest) throws UnsupportedEncodingException {
        final String channel = geocoderRequest.getChannel();
        final String address = geocoderRequest.getAddress();
        final LatLngBounds bounds = geocoderRequest.getBounds();
        final String language = geocoderRequest.getLanguage();
        final String region = geocoderRequest.getRegion();
        final LatLng location = geocoderRequest.getLocation();
        final EnumMap<GeocoderComponent, String> components = geocoderRequest.getComponents();

        final StringBuilder url = new StringBuilder(GEOCODE_REQUEST_QUERY_BASIC);

        if(apiKey != null) {
            url.append("&key=").append(URLEncoder.encode(apiKey, ENCODING));
        }

        if (channel != null && channel.length() > 0) {
            url.append("&channel=").append(URLEncoder.encode(channel, ENCODING));
        }
        if (address != null && address.length() > 0) {
            url.append("&address=").append(URLEncoder.encode(address, ENCODING));
        } else if (location != null) {
            url.append("&latlng=").append(URLEncoder.encode(location.toUrlValue(), ENCODING));
        } else {
            throw new IllegalArgumentException("Address or location must be defined");
        }
        if (language != null && language.length() > 0) {
            url.append("&language=").append(URLEncoder.encode(language, ENCODING));
        }
        if (region != null && region.length() > 0) {
            url.append("&region=").append(URLEncoder.encode(region, ENCODING));
        }
        if (bounds != null) {
            url.append("&bounds=").append(URLEncoder.encode(bounds.getSouthwest().toUrlValue() + "|" + bounds.getNortheast().toUrlValue(), ENCODING));
        }
        if (!components.isEmpty()) {
            url.append("&components=");
            boolean isFirstLine = true;
            for (Map.Entry<GeocoderComponent, String> entry : components.entrySet()) {
                if (isFirstLine) {
                    isFirstLine = false;
                } else {
                    url.append(URLEncoder.encode("|", ENCODING));
                }
                url.append(URLEncoder.encode(entry.getKey().value(), ENCODING));
                url.append(':');
                url.append(URLEncoder.encode(entry.getValue(), ENCODING));
            }

        }
        logger.trace("URL query: {}", url);
        return url;
    }

    protected void addClientIdAndSignURL(StringBuilder url) throws UnsupportedEncodingException {
        url.append("&client=").append(URLEncoder.encode(clientId, ENCODING));

        logger.trace("URL query to Sign: {}", url);

        byte[] sigBytes;
        synchronized (mac) {
            mac.update(url.toString().getBytes());
            sigBytes = mac.doFinal();
        }

        String signature = new String(Base64.encodeBase64(sigBytes));
        signature = signature.replace('+', '-');
        signature = signature.replace('/', '_');

        if (logger.isTraceEnabled()) {
            logger.trace("Signature: [{}] for URL query {}", signature, url);
        }
        url.append("&signature=").append(signature);
    }

    protected static Mac getMAC(String clientKey) throws InvalidKeyException {
        try {
            byte[] key = clientKey.replace('-', '+').replace('_', '/').getBytes();

            byte[] decodedKey = Base64.decodeBase64(key);

            // Get an HMAC-SHA1 signing key from the raw key bytes
            final SecretKeySpec sha1Key = new SecretKeySpec(decodedKey, "HmacSHA1");

            // Get an HMAC-SHA1 Mac instance and initialize it with the HMAC-SHA1 key
            final Mac result = Mac.getInstance("HmacSHA1");
            result.init(sha1Key);

            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}