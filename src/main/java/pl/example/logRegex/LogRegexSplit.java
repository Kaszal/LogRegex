package pl.example.logRegex;

public class LogRegexSplit {
	
	public static void main(String[] args) {
		
		String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\"";
			//divide log by white characters
		String[] tmp = log.split("\\s+");
		
		LogGettersSetters log1 = new LogGettersSetters();
		
		for(int i=0; i < tmp.length; i++) {
			if(!tmp[i].equals("\"\""))					// usuwamy tylko zbedne ""
			tmp[i] = tmp[i].replaceAll("\"", "");
			System.out.println(tmp[i]);
		}
		
		log1.setSysLogTimeStamp1(tmp[0]+" "+tmp[1]+" "+tmp[2]);
		log1.setProxyIP(tmp[3]);
		log1.setProduct(tmp[4]);
		log1.setEventTimeStamp(tmp[5]+" "+tmp[6]);
		log1.setUser(tmp[7]);
		log1.setSourceIP(tmp[8]);
		log1.setStatus(tmp[9]);
		log1.setHttpMethod(tmp[10]);
		log1.setHttpProtocol(tmp[11]);
		log1.setUrl(tmp[12]);
		log1.setHttpVersion(tmp[13]);
		log1.setHttpCategory(tmp[14]);
		log1.setRisk(tmp[15]);	
		log1.setHttpContentType(tmp[16]);
		log1.setBytesIN(tmp[17]);
		log1.setBytesOUT(tmp[18]);
		log1.setHttpUserAgent(tmp[19]+" "+tmp[20]+" "+tmp[21]+" "+tmp[22]+" "+tmp[23]+" "+tmp[24]+" "+tmp[25]+" "+tmp[26]+" "+tmp[27]+" "+tmp[28]+" "+tmp[29]);
		log1.setSignature(tmp[30]);
		log1.setAction(tmp[31]);
		log1.setBlockResult(tmp[32]);
		log1.setCustomRuleName(tmp[33]+" "+tmp[34]+" "+tmp[35]);
		log1.setDestIP(tmp[36]);
		log1.setHttpReferrer(tmp[37]);
		
		System.out.println("");
		System.out.println(log1.getSysLogTimeStamp1());
		System.out.println(log1.getProxyIP());
		System.out.println(log1.getProduct());
		System.out.println(log1.getEventTimeStamp());
		System.out.println(log1.getUser());
		System.out.println(log1.getSourceIP());
		System.out.println(log1.getStatus());
		System.out.println(log1.getHttpMethod());			// erase "...
		System.out.println(log1.getHttpProtocol());
		System.out.println(log1.getUrl());					// erase "...
		System.out.println(log1.getHttpVersion());
		System.out.println(log1.getHttpCategory());
		System.out.println(log1.getRisk());
		System.out.println(log1.getHttpContentType());			
		System.out.println(log1.getBytesIN());
		System.out.println(log1.getBytesOUT());
		System.out.println(log1.getHttpUserAgent());			// ZMIENNA WARTOSC!
		System.out.println(log1.getSignature());
		System.out.println(log1.getAction());
		System.out.println(log1.getBlockResult());
		System.out.println(log1.getCustomRuleName());
		System.out.println(log1.getDestIP());
		System.out.println(log1.getHttpReferrer());
	
	}
	
	
} 

