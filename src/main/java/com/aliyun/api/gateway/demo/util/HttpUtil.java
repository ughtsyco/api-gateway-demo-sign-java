/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.aliyun.api.gateway.demo.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.CoreConnectionPNames;

import com.aliyun.api.gateway.demo.Response;
import com.aliyun.api.gateway.demo.constant.Constants;
import com.aliyun.api.gateway.demo.constant.ContentType;
import com.aliyun.api.gateway.demo.constant.HttpHeader;
import com.aliyun.api.gateway.demo.constant.HttpMethod;
import com.aliyun.api.gateway.demo.constant.SystemHeader;

/**
 * Http工具类
 */
public class HttpUtil {
    /**
     * HTTP GET
     * @param host
     * @param path
     * @param connectTimeout
     * @param headers
     * @param querys
     * @param signHeaderPrefixList
     * @param appKey
     * @param appSecret
     * @return
     * @throws Exception
     */
    public static Response httpGet(String host, String path, int connectTimeout, Map<String, String> headers, Map<String, String> querys, List<String> signHeaderPrefixList, String appKey, String appSecret)
            throws Exception {
        headers = initialBasicHeader(HttpMethod.GET, path, headers, querys, null, signHeaderPrefixList, appKey, appSecret);

        HttpClient httpClient = wrapClient(host);
        httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getTimeout(connectTimeout));

        HttpGet get = new HttpGet(initUrl(host, path, querys));

        for (Map.Entry<String, String> e : headers.entrySet()) {
            get.addHeader(e.getKey(), MessageDigestUtil.utf8ToIso88591(e.getValue()));
        }

        return convert(httpClient.execute(get));
    }

    /**
     * HTTP POST表单
     * @param host
     * @param path
     * @param connectTimeout
     * @param headers
     * @param querys
     * @param bodys
     * @param signHeaderPrefixList
     * @param appKey
     * @param appSecret
     * @return
     * @throws Exception
     */
    public static Response httpPost(String host, String path, int connectTimeout, Map<String, String> headers, Map<String, String> querys, Map<String, String> bodys, List<String> signHeaderPrefixList, String appKey, String appSecret)
            throws Exception {
        if (headers == null) {
            headers = new HashMap<String, String>();
        }

        headers.put(HttpHeader.HTTP_HEADER_CONTENT_TYPE, ContentType.CONTENT_TYPE_FORM);

        headers = initialBasicHeader(HttpMethod.POST, path, headers, querys, bodys, signHeaderPrefixList, appKey, appSecret);

        HttpClient httpClient = wrapClient(host);
        httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getTimeout(connectTimeout));

        HttpPost post = new HttpPost(initUrl(host, path, querys));
        for (Map.Entry<String, String> e : headers.entrySet()) {
            post.addHeader(e.getKey(), MessageDigestUtil.utf8ToIso88591(e.getValue()));
        }

        UrlEncodedFormEntity formEntity = buildFormEntity(bodys);
        if (formEntity != null) {
            post.setEntity(formEntity);
        }

        return convert(httpClient.execute(post));
    }

    /**
     * Http POST 字符串
     * @param host
     * @param path
     * @param connectTimeout
     * @param headers
     * @param querys
     * @param body
     * @param signHeaderPrefixList
     * @param appKey
     * @param appSecret
     * @return
     * @throws Exception
     */
    public static Response httpPost(String host, String path, int connectTimeout, Map<String, String> headers, Map<String, String> querys, String body, List<String> signHeaderPrefixList, String appKey, String appSecret)
            throws Exception {
    	headers = initialBasicHeader(HttpMethod.POST, path, headers, querys, null, signHeaderPrefixList, appKey, appSecret);

    	HttpClient httpClient = wrapClient(host);
        httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getTimeout(connectTimeout));

        HttpPost post = new HttpPost(initUrl(host, path, querys));
        for (Map.Entry<String, String> e : headers.entrySet()) {
            post.addHeader(e.getKey(), MessageDigestUtil.utf8ToIso88591(e.getValue()));
        }

        if (StringUtils.isNotBlank(body)) {
            post.setEntity(new StringEntity(body, Constants.ENCODING));

        }

        return convert(httpClient.execute(post));
    }

    /**
     * HTTP POST 字节数组
     * @param host
     * @param path
     * @param connectTimeout
     * @param headers
     * @param querys
     * @param bodys
     * @param signHeaderPrefixList
     * @param appKey
     * @param appSecret
     * @return
     * @throws Exception
     */
    public static Response httpPost(String host, String path, int connectTimeout, Map<String, String> headers, Map<String, String> querys, byte[] bodys, List<String> signHeaderPrefixList, String appKey, String appSecret)
            throws Exception {
    	headers = initialBasicHeader(HttpMethod.POST, path, headers, querys, null, signHeaderPrefixList, appKey, appSecret);

    	HttpClient httpClient = wrapClient(host);
        httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getTimeout(connectTimeout));

        HttpPost post = new HttpPost(initUrl(host, path, querys));
        for (Map.Entry<String, String> e : headers.entrySet()) {
            post.addHeader(e.getKey(), MessageDigestUtil.utf8ToIso88591(e.getValue()));
        }

        if (bodys != null) {
            post.setEntity(new ByteArrayEntity(bodys));
        }

        return convert(httpClient.execute(post));
    }

    /**
     * HTTP PUT 字符串
     * @param host
     * @param path
     * @param connectTimeout
     * @param headers
     * @param querys
     * @param body
     * @param signHeaderPrefixList
     * @param appKey
     * @param appSecret
     * @return
     * @throws Exception
     */
    public static Response httpPut(String host, String path, int connectTimeout, Map<String, String> headers, Map<String, String> querys, String body, List<String> signHeaderPrefixList, String appKey, String appSecret)
            throws Exception {
    	headers = initialBasicHeader(HttpMethod.PUT, path, headers, querys, null, signHeaderPrefixList, appKey, appSecret);

    	HttpClient httpClient = wrapClient(host);
        httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getTimeout(connectTimeout));

        HttpPut put = new HttpPut(initUrl(host, path, querys));
        for (Map.Entry<String, String> e : headers.entrySet()) {
            put.addHeader(e.getKey(), MessageDigestUtil.utf8ToIso88591(e.getValue()));
        }

        if (StringUtils.isNotBlank(body)) {
            put.setEntity(new StringEntity(body, Constants.ENCODING));

        }

        return convert(httpClient.execute(put));
    }

    /**
     * HTTP PUT字节数组
     * @param host
     * @param path
     * @param connectTimeout
     * @param headers
     * @param querys
     * @param bodys
     * @param signHeaderPrefixList
     * @param appKey
     * @param appSecret
     * @return
     * @throws Exception
     */
    public static Response httpPut(String host, String path, int connectTimeout, Map<String, String> headers, Map<String, String> querys, byte[] bodys, List<String> signHeaderPrefixList, String appKey, String appSecret)
            throws Exception {
    	headers = initialBasicHeader(HttpMethod.PUT, path, headers, querys, null, signHeaderPrefixList, appKey, appSecret);

    	HttpClient httpClient = wrapClient(host);
        httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getTimeout(connectTimeout));

        HttpPut put = new HttpPut(initUrl(host, path, querys));
        for (Map.Entry<String, String> e : headers.entrySet()) {
        	put.addHeader(e.getKey(), MessageDigestUtil.utf8ToIso88591(e.getValue()));
        }

        if (bodys != null) {
        	put.setEntity(new ByteArrayEntity(bodys));
        }

        return convert(httpClient.execute(put));
    }

    /**
     * HTTP DELETE
     * @param host
     * @param path
     * @param connectTimeout
     * @param headers
     * @param querys
     * @param signHeaderPrefixList
     * @param appKey
     * @param appSecret
     * @return
     * @throws Exception
     */
    public static Response httpDelete(String host, String path, int connectTimeout, Map<String, String> headers, Map<String, String> querys, List<String> signHeaderPrefixList, String appKey, String appSecret)
            throws Exception {
        headers = initialBasicHeader(HttpMethod.DELETE, path, headers, querys, null, signHeaderPrefixList, appKey, appSecret);

        HttpClient httpClient = wrapClient(host);
        httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getTimeout(connectTimeout));

        HttpDelete delete = new HttpDelete(initUrl(host, path, querys));
        for (Map.Entry<String, String> e : headers.entrySet()) {
            delete.addHeader(e.getKey(), MessageDigestUtil.utf8ToIso88591(e.getValue()));
        }

        return convert(httpClient.execute(delete));
    }

    /**
     * 构建FormEntity
     * 
     * @param formParam
     * @return
     * @throws UnsupportedEncodingException
     */
    private static UrlEncodedFormEntity buildFormEntity(Map<String, String> formParam)
            throws UnsupportedEncodingException {
        if (formParam != null) {
            List<NameValuePair> nameValuePairList = new ArrayList<NameValuePair>();

            for (String key : formParam.keySet()) {
                nameValuePairList.add(new BasicNameValuePair(key, formParam.get(key)));
            }
            UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(nameValuePairList, Constants.ENCODING);
            formEntity.setContentType(ContentType.CONTENT_TYPE_FORM);
            return formEntity;
        }

        return null;
    }
    
    private static String initUrl(String host, String path, Map<String, String> querys) throws UnsupportedEncodingException {
    	StringBuilder sbUrl = new StringBuilder();
    	sbUrl.append(host);
    	if (!StringUtils.isBlank(path)) {
    		sbUrl.append(path);
        }
    	if (null != querys) {
    		StringBuilder sbQuery = new StringBuilder();
        	for (Map.Entry<String, String> query : querys.entrySet()) {
        		if (0 < sbQuery.length()) {
        			sbQuery.append(Constants.SPE3);
        		}
        		if (StringUtils.isBlank(query.getKey()) && !StringUtils.isBlank(query.getValue())) {
        			sbQuery.append(query.getValue());
                }
        		if (!StringUtils.isBlank(query.getKey())) {
        			sbQuery.append(query.getKey());
        			if (!StringUtils.isBlank(query.getValue())) {
        				sbQuery.append(Constants.SPE4);
        				sbQuery.append(URLEncoder.encode(query.getValue(), Constants.ENCODING));
        			}        			
                }
        	}
        	if (0 < sbQuery.length()) {
        		sbUrl.append(Constants.SPE5).append(sbQuery);
        	}
        }
    	
    	return sbUrl.toString();
    }
    	

    /**
     * 初始化基础Header
     * @param method
     * @param path
     * @param headers
     * @param querys
     * @param bodys
     * @param signHeaderPrefixList
     * @param appKey
     * @param appSecret
     * @return
     * @throws MalformedURLException
     */
    private static Map<String, String> initialBasicHeader(String method, String path,
                                                          Map<String, String> headers, 
                                                          Map<String, String> querys,
                                                          Map<String, String> bodys,
                                                          List<String> signHeaderPrefixList,
                                                          String appKey, String appSecret)
            throws MalformedURLException {
        if (headers == null) {
            headers = new HashMap<String, String>();
        }

        headers.put(SystemHeader.X_CA_TIMESTAMP, String.valueOf(new Date().getTime()));
        //headers.put(SystemHeader.X_CA_NONCE, UUID.randomUUID().toString());
        headers.put(SystemHeader.X_CA_KEY, appKey);
        headers.put(SystemHeader.X_CA_SIGNATURE,
                SignUtil.sign(appSecret, method, path, headers, querys, bodys, signHeaderPrefixList));

        return headers;
    }

    /**
     * 读取超时时间
     * 
     * @param timeout
     * @return
     */
    private static int getTimeout(int timeout) {
        if (timeout == 0) {
            return Constants.DEFAULT_TIMEOUT;
        }

        return timeout;
    }
    
    private static Response convert(HttpResponse response) throws IOException {
    	Response res = new Response(); 
    	
    	if (null != response) {
    		res.setStatusCode(response.getStatusLine().getStatusCode());
    		for (Header header : response.getAllHeaders()) {
    			res.setHeader(header.getName(), MessageDigestUtil.iso88591ToUtf8(header.getValue()));
            }
    		
    		res.setContentType(res.getHeader("Content-Type"));
    		res.setRequestId(res.getHeader("X-Ca-Request-Id"));
    		res.setErrorMessage(res.getHeader("X-Ca-Error-Message"));
    		res.setBody(readStreamAsStr(response.getEntity().getContent()));
    		
    	} else {
    		//服务器无回应
    		res.setStatusCode(500);
    		res.setErrorMessage("No Response");
    	}
    	
    	return res;
    }


	/**
	 * 将流转换为字符串
	 *
	 * @param is
	 * @return
	 * @throws IOException
	 */
	public static String readStreamAsStr(InputStream is) throws IOException {
	    ByteArrayOutputStream bos = new ByteArrayOutputStream();
	    WritableByteChannel dest = Channels.newChannel(bos);
	    ReadableByteChannel src = Channels.newChannel(is);
	    ByteBuffer bb = ByteBuffer.allocate(4096);
	
	    while (src.read(bb) != -1) {
	        bb.flip();
	        dest.write(bb);
	        bb.clear();
	    }
	    src.close();
	    dest.close();
	
	    return new String(bos.toByteArray(), Constants.ENCODING);
	}

	private static HttpClient wrapClient(String host) {
		HttpClient httpClient = new DefaultHttpClient();
		if (host.startsWith("https://")) {
			sslClient(httpClient);
		}
		
		return httpClient;
	}
	
	private static void sslClient(HttpClient httpClient) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            X509TrustManager tm = new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] xcs, String str) {
                	
                }
                public void checkServerTrusted(X509Certificate[] xcs, String str) {
                	
                }
            };
            ctx.init(null, new TrustManager[] { tm }, null);
            SSLSocketFactory ssf = new SSLSocketFactory(ctx);
            ssf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            ClientConnectionManager ccm = httpClient.getConnectionManager();
            SchemeRegistry registry = ccm.getSchemeRegistry();
            registry.register(new Scheme("https", 443, ssf));
        } catch (KeyManagementException ex) {
            throw new RuntimeException(ex);
        } catch (NoSuchAlgorithmException ex) {
        	throw new RuntimeException(ex);
        }
    }

    /**
     * HTTP GET请求 - 简化版，不需要签名
     * @param url 完整的URL地址
     * @param headers 请求头
     * @param connectTimeout 连接超时时间
     * @return HTTP响应
     * @throws Exception 请求异常
     */
    public static Response simpleHttpGet(String url, Map<String, String> headers, int connectTimeout) 
            throws Exception {
        if (headers == null) {
            headers = new HashMap<String, String>();
        }
        
        String host = getHostFromUrl(url);
        String path = getPathFromUrl(url);
        Map<String, String> querys = getQueryFromUrl(url);
        
        HttpClient httpClient = wrapClient(host);
        httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getTimeout(connectTimeout));

        HttpGet get = new HttpGet(url);
        
        for (Map.Entry<String, String> e : headers.entrySet()) {
            get.addHeader(e.getKey(), MessageDigestUtil.utf8ToIso88591(e.getValue()));
        }

        return convert(httpClient.execute(get));
    }
    
    /**
     * 从URL中提取主机名
     * @param url 完整URL
     * @return 主机名
     * @throws MalformedURLException URL格式错误
     */
    private static String getHostFromUrl(String url) throws MalformedURLException {
        java.net.URL parsedUrl = new java.net.URL(url);
        String protocol = parsedUrl.getProtocol();
        String host = parsedUrl.getHost();
        int port = parsedUrl.getPort();
        
        if (port != -1) {
            return protocol + "://" + host + ":" + port;
        } else {
            return protocol + "://" + host;
        }
    }
    
    /**
     * 从URL中提取路径
     * @param url 完整URL
     * @return 路径部分
     * @throws MalformedURLException URL格式错误
     */
    private static String getPathFromUrl(String url) throws MalformedURLException {
        java.net.URL parsedUrl = new java.net.URL(url);
        return parsedUrl.getPath();
    }
    
    /**
     * 从URL中提取查询参数
     * @param url 完整URL
     * @return 查询参数Map
     * @throws MalformedURLException URL格式错误
     */
    private static Map<String, String> getQueryFromUrl(String url) throws MalformedURLException {
        java.net.URL parsedUrl = new java.net.URL(url);
        Map<String, String> querys = new HashMap<String, String>();
        
        String queryString = parsedUrl.getQuery();
        if (queryString != null && !queryString.isEmpty()) {
            String[] pairs = queryString.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                if (idx > 0) {
                    try {
                        String key = URLEncoder.encode(pair.substring(0, idx), Constants.ENCODING);
                        String value = URLEncoder.encode(pair.substring(idx + 1), Constants.ENCODING);
                        querys.put(key, value);
                    } catch (UnsupportedEncodingException e) {
                        // 忽略编码异常
                    }
                }
            }
        }
        
        return querys;
    }

    /**
     * 【错误示范】不安全的HTTP POST方法 - 没有进行任何安全验证
     * 安全问题：没有验证SSL证书，容易遭受中间人攻击
     * @param url 请求URL
     * @param body 请求体
     * @return 响应字符串
     */
    public static String unsafeHttpPost(String url, String body) {
        try {
            // 安全风险：忽略所有SSL证书验证
            SSLContext ctx = SSLContext.getInstance("TLS");
            X509TrustManager tm = new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] xcs, String str) {}
                public void checkServerTrusted(X509Certificate[] xcs, String str) {}
            };
            ctx.init(null, new TrustManager[] { tm }, null);
            SSLSocketFactory ssf = new SSLSocketFactory(ctx, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            
            // 创建客户端
            DefaultHttpClient httpClient = new DefaultHttpClient();
            SchemeRegistry registry = httpClient.getConnectionManager().getSchemeRegistry();
            registry.register(new Scheme("https", 443, ssf));
            
            // 执行请求
            HttpPost post = new HttpPost(url);
            post.setEntity(new StringEntity(body, "UTF-8"));
            
            // 安全风险：没有设置超时时间，可能导致连接挂起
            HttpResponse response = httpClient.execute(post);
            
            // 读取响应
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            response.getEntity().writeTo(baos);
            return baos.toString();
        } catch (Exception e) {
            // 错误：吞掉异常，不记录日志
            return "Error: " + e.getMessage();
        }
    }
    
    /**
     * 【错误示范】内存泄漏的文件处理方法
     * 问题：不正确关闭资源，会导致资源泄露
     * @param inputStream 输入流
     * @return 读取的字符串
     */
    public static String readStreamUnsafe(InputStream inputStream) {
        try {
            // 性能问题1：未指定初始缓冲区大小，可能导致频繁扩容
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[128]; // 性能问题2：缓冲区太小
            int length;
            
            // 错误：没有使用try-with-resources或finally块来关闭资源
            while ((length = inputStream.read(buffer)) != -1) {
                result.write(buffer, 0, length);
            }
            
            // 错误：没有关闭输入流，可能导致资源泄漏
            
            return result.toString("UTF-8");
        } catch (Exception e) {
            // 安全问题：异常信息泄露
            throw new RuntimeException("处理失败，详细原因: " + e.toString(), e);
        }
    }
    
    /**
     * 【错误示范】SQL注入风险的URL参数处理
     * 问题：直接拼接参数，没有进行参数化处理
     * @param baseUrl 基础URL
     * @param params 参数集合
     * @return 完整URL
     */
    public static String buildUrlWithParams(String baseUrl, Map<String, String> params) {
        StringBuilder result = new StringBuilder(baseUrl);
        if (params != null && !params.isEmpty()) {
            result.append("?");
            
            // 错误：没有对参数进行URL编码，可能导致URL格式错误或注入
            for (Map.Entry<String, String> entry : params.entrySet()) {
                result.append(entry.getKey())
                      .append("=")
                      .append(entry.getValue())
                      .append("&");
            }
            result.deleteCharAt(result.length() - 1);
        }
        return result.toString();
    }
    
    /**
     * 【可优化】HTTP请求工具 - 基本功能正确但可优化
     * 可优化点：
     * 1. 线程安全性：可以使用线程安全的HttpClient实现
     * 2. 连接池管理：可以使用连接池提高性能
     * 3. 异常处理：可以提供更详细的异常分类和处理
     * @param url 请求URL
     * @param method 请求方法
     * @param headers 请求头
     * @param body 请求体
     * @param timeout 超时时间（毫秒）
     * @return 响应内容
     */
    public static String httpRequest(String url, String method, Map<String, String> headers, String body, int timeout) {
        HttpClient httpClient = new DefaultHttpClient();
        
        // 设置超时
        httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, timeout);
        httpClient.getParams().setParameter(CoreConnectionPNames.SO_TIMEOUT, timeout);
        
        try {
            // 根据不同方法创建不同请求
            if ("GET".equalsIgnoreCase(method)) {
                HttpGet request = new HttpGet(url);
                
                // 添加头信息
                if (headers != null) {
                    for (Map.Entry<String, String> entry : headers.entrySet()) {
                        request.addHeader(entry.getKey(), entry.getValue());
                    }
                }
                
                HttpResponse response = httpClient.execute(request);
                return handleResponse(response);
                
            } else if ("POST".equalsIgnoreCase(method)) {
                HttpPost request = new HttpPost(url);
                
                // 添加头信息
                if (headers != null) {
                    for (Map.Entry<String, String> entry : headers.entrySet()) {
                        request.addHeader(entry.getKey(), entry.getValue());
                    }
                }
                
                // 添加请求体
                if (body != null) {
                    request.setEntity(new StringEntity(body, "UTF-8"));
                }
                
                HttpResponse response = httpClient.execute(request);
                return handleResponse(response);
                
            } else if ("PUT".equalsIgnoreCase(method)) {
                HttpPut request = new HttpPut(url);
                
                // 添加头信息
                if (headers != null) {
                    for (Map.Entry<String, String> entry : headers.entrySet()) {
                        request.addHeader(entry.getKey(), entry.getValue());
                    }
                }
                
                // 添加请求体
                if (body != null) {
                    request.setEntity(new StringEntity(body, "UTF-8"));
                }
                
                HttpResponse response = httpClient.execute(request);
                return handleResponse(response);
                
            } else if ("DELETE".equalsIgnoreCase(method)) {
                HttpDelete request = new HttpDelete(url);
                
                // 添加头信息
                if (headers != null) {
                    for (Map.Entry<String, String> entry : headers.entrySet()) {
                        request.addHeader(entry.getKey(), entry.getValue());
                    }
                }
                
                HttpResponse response = httpClient.execute(request);
                return handleResponse(response);
                
            } else {
                throw new IllegalArgumentException("不支持的HTTP方法: " + method);
            }
        } catch (Exception e) {
            throw new RuntimeException("HTTP请求失败", e);
        } finally {
            // 可优化：应该使用连接池，而不是每次都关闭
            httpClient.getConnectionManager().shutdown();
        }
    }
    
    /**
     * 【可优化】处理HTTP响应
     * 可优化点：
     * 1. 流处理：可以使用更高效的流处理方式
     * 2. 内存使用：对于大响应可以采用流式处理而非一次加载全部内容
     * @param response HTTP响应
     * @return 响应内容字符串
     */
    private static String handleResponse(HttpResponse response) throws IOException {
        if (response.getStatusLine().getStatusCode() >= 300) {
            throw new RuntimeException("HTTP错误: " + response.getStatusLine().getStatusCode() + 
                                       " " + response.getStatusLine().getReasonPhrase());
        }
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        response.getEntity().writeTo(out);
        return out.toString("UTF-8");
    }
    
    /**
     * 【可优化】通过重试提高可靠性的HTTP GET方法
     * 可优化点：
     * 1. 重试策略：可以使用指数退避算法
     * 2. 异常处理：可以区分不同类型的异常来决定是否重试
     * 3. 日志记录：可以增加详细的日志
     * @param url 请求URL
     * @param maxRetries 最大重试次数
     * @param retryInterval 重试间隔（毫秒）
     * @return HTTP响应内容
     */
    public static String httpGetWithRetry(String url, int maxRetries, long retryInterval) {
        int retries = 0;
        Exception lastException = null;
        
        while (retries <= maxRetries) {
            try {
                HttpClient httpClient = new DefaultHttpClient();
                HttpGet request = new HttpGet(url);
                
                // 设置超时（可优化：应当根据网络状况调整）
                httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, 5000);
                httpClient.getParams().setParameter(CoreConnectionPNames.SO_TIMEOUT, 5000);
                
                HttpResponse response = httpClient.execute(request);
                
                if (response.getStatusLine().getStatusCode() == 200) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    response.getEntity().writeTo(out);
                    return out.toString("UTF-8");
                } else if (response.getStatusLine().getStatusCode() >= 500) {
                    // 服务器错误，重试
                    lastException = new RuntimeException("服务器错误: " + response.getStatusLine().getStatusCode());
                } else {
                    // 客户端错误，不重试
                    throw new RuntimeException("客户端错误: " + response.getStatusLine().getStatusCode());
                }
            } catch (IOException e) {
                lastException = e;
            }
            
            retries++;
            if (retries <= maxRetries) {
                try {
                    Thread.sleep(retryInterval);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("线程被中断", e);
                }
            }
        }
        
        throw new RuntimeException("在" + maxRetries + "次尝试后请求失败", lastException);
    }
}