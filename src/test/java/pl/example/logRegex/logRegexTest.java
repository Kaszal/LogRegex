package pl.example.logRegex;

import static org.junit.Assert.*;

import org.junit.Test;

public class logRegexTest {

	private static final String DEST_IP = "198.41.208.137";
	private static final String SYSLOGTIMESTAMP1 = "May 18 09:31:44";
	private static final String PROXY_IP = "10.51.177.2";
	private static final String PRODUCT_NAME = "mwg"; // <- NIE TRZEBA : ?
	private static final String EVENT_TIME_STAMP = " [18/May/2016:09:31:44 +1000]";
	private static final String USER_NAME = " \"pgor\" ";
	private static final String SOURCE_IP = "10.52.28.227";
	private static final String CONNECT_STATUS = "200";
	private static final String CONNECT = " \"CONNECT ";
	private static final String HTTP_PROTOCOL = "https://";
	private static final String URL = "buttons.reddit.com:";
	private static final String HTTP_VERSION = "HTTP/1.1";
	private static final String HTTP_CATEGORY = " \"Forum/Bulletin Boards\" ";
	
	private static final String RISK = " \"Unverified\" ";
	private static final String CONTENT_TYPE = "\"\" ";
	private static final String BYTES_IN_OUT = " 0";
	private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36";
	private static final String SIGNATURE= " \"\" ";
	private static final String ACTION = " \"0\" ";

	private static final String RULE_NAME = " \"Global Whitelist: Sites\" ";
	private static final String HTTP_REFERRER= " \"\"";
	
			String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\"";
	
	@Test
	public void testSysLogTimeStamp1() {
		logRegex log1 = new logRegex();
		String result = log1.sysLogTimeStamp1(log);
		assertEquals("Blad regex",SYSLOGTIMESTAMP1,result);
		//System.out.println(SYSLOGTIMESTAMP1);
		//assertTrue("Wynik",result);
	}
	
	@Test
	public void testProxyIP() {
		logRegex log2 = new logRegex();
		String result = log2.proxyIP(PROXY_IP);
		assertEquals("Blad regex",PROXY_IP,result);
		System.out.println(PROXY_IP);
	}
	
	@Test							// CZY TUTAJ NIE TRZEBA mwg: <-
	public void testProduct() {
		logRegex log3 = new logRegex();
		boolean result = log3.product(PRODUCT_NAME);
		assertTrue("Wynik",result);
	}
	
	@Test							// CZY TUTAJ NIE TRZEBA mwg: <-
	public void testEventTimeStamp() {
		logRegex log4 = new logRegex();
		boolean result = log4.eventTimeStamp(EVENT_TIME_STAMP);
		assertTrue("Wynik",result);
	}
	
	@Test
	public void testUser() {
		logRegex log5 = new logRegex();
		boolean result = log5.user(USER_NAME);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testSourceIP() {
		logRegex log6 = new logRegex();
		boolean result = log6.sourceIP(SOURCE_IP);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testStatus() {
		logRegex log7 = new logRegex();
		boolean result = log7.status(CONNECT_STATUS);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testHttpMethod() {
		logRegex log8 = new logRegex();
		boolean result = log8.httpMethod(CONNECT);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testHttpProtocol() {
		logRegex log9 = new logRegex();
		boolean result = log9.httpProtocol(HTTP_PROTOCOL);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testURL() {
		logRegex log10 = new logRegex();
		boolean result = log10.url(URL);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testVersion() {
		logRegex log11 = new logRegex();
		boolean result = log11.httpVersion(HTTP_VERSION);
		assertTrue("Wynik", result);
	}
	
	
	@Test
	public void testCategory() {
		logRegex log12 = new logRegex();
		boolean result = log12.httpCategory(HTTP_CATEGORY);
		assertTrue("Wynik", result);
	}
	
	
	@Test
	public void testRisk() {
		logRegex log13 = new logRegex();
		boolean result = log13.risk(RISK);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testContentType() {
		logRegex log14 = new logRegex();
		boolean result = log14.httpContentType(CONTENT_TYPE);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testBytesIN() {
		logRegex log15 = new logRegex();
		boolean result = log15.bytesIN(BYTES_IN_OUT);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testBytesOUT() {
		logRegex log16 = new logRegex();
		boolean result = log16.bytesOUT(BYTES_IN_OUT);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testUserAgent() {
		logRegex log17 = new logRegex();
		boolean result = log17.httpUserAgent(USER_AGENT);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testSignature() {
		logRegex log18 = new logRegex();
		boolean result = log18.signature(SIGNATURE);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testAction() {
		logRegex log19 = new logRegex();
		boolean result = log19.action(ACTION);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testBlockResult() {
		logRegex log20 = new logRegex();
		boolean result = log20.blockResult(SIGNATURE);  // BLOCK_RESULT!!!!!!!!!
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testCustomRuleName() {
		logRegex log21 = new logRegex();
		boolean result = log21.customRuleName(RULE_NAME);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testDestIP() {
		logRegex log22 = new logRegex();
		boolean result = log22.destIP(DEST_IP);
		assertTrue("Wynik", result);
	}
	
	@Test
	public void testHttpReferrer() {
		logRegex log23 = new logRegex();
		boolean result = log23.httpReferrer(HTTP_REFERRER); 
		assertTrue("Wynik", result);
	}

}
