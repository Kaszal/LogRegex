package pl.example.logRegex;

public interface LogInterface {
	
	String sysLogTimeStamp1(String log);
	String proxyIP(String log);
	String product(String log);
	String eventTimeStamp(String log);
	String user(String log);
	String sourceIP(String log);
	String status(String log);
	String httpMethod(String log);
	String httpProtocol(String log);
	String url(String log);
	String httpVersion(String log);
	String httpCategory(String log);
	String risk(String log);
	String httpContentType(String log);
	String bytesIN(String log);
	String bytesOUT(String log);
	String httpUserAgent(String log);
	String signature(String log);
	String action(String log);
	String blockResult(String log);
	String customRuleName(String log);
	String destIP(String log);
	String httpReferrer(String log);

}
