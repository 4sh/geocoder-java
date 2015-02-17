package com.google.code.geocoder;

import com.google.code.geocoder.model.GeocodeResponse;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.methods.GetMethod;

import javax.crypto.Mac;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.InvalidKeyException;

/**
 * @author <a href="mailto:panchmp@gmail.com">Michael Panchenko</a>
 */
public class AdvancedGeoCoder extends Geocoder {
    private final HttpClient httpClient;

    public AdvancedGeoCoder(final HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public AdvancedGeoCoder() {
        this(new HttpClient(new MultiThreadedHttpConnectionManager()));
    }

    protected AdvancedGeoCoder(String clientId, Mac mac, String apiKey, HttpClient httpClient) {
        super(clientId, mac, apiKey);
        this.httpClient = httpClient;
    }

    public static AdvancedGeoCoder createFromClientId(String clientId, String clientKey) throws InvalidKeyException {
        return createFromClientId(clientId, clientKey,
                new HttpClient(new MultiThreadedHttpConnectionManager()));
    }

    public static AdvancedGeoCoder createFromClientId(String clientId, String clientKey, HttpClient httpClient) throws InvalidKeyException {
        return new AdvancedGeoCoder(
                checkNotNullOrEmpty(clientId, "clientId"),
                getMAC(checkNotNullOrEmpty(clientKey, "clientKey")),
                null, httpClient);
    }

    @Override
    protected GeocodeResponse request(final String urlString) throws IOException {
        final GetMethod getMethod = new GetMethod(urlString);
        try {
            httpClient.executeMethod(getMethod);
            final Reader reader = new InputStreamReader(getMethod.getResponseBodyAsStream(), getMethod.getResponseCharSet());

            return OBJECT_MAPPER.readValue(reader, GeocodeResponse.class);
        } finally {
            getMethod.releaseConnection();
        }
    }
}