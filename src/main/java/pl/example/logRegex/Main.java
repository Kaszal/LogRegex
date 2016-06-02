package pl.example.logRegex;

import java.util.Random;
import java.util.regex.Pattern;

import com.sun.org.apache.xerces.internal.impl.xs.identity.Selector.Matcher;

public class Main {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		 String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\"";
         //divide log by white characters
    
     LogRegexSplit logSplit = new LogRegexSplit(log);
    
     logSplit.setValues();
    
     System.out.println(logSplit.getSysLogTimeStamp1());
     System.out.println(logSplit.getProxyIP());
     System.out.println(logSplit.getProduct());
     System.out.println(logSplit.getEventTimeStamp());
     System.out.println(logSplit.getUser());
     System.out.println(logSplit.getSourceIP());
     System.out.println(logSplit.getStatus());
     System.out.println(logSplit.getHttpMethod());          
     System.out.println(logSplit.getHttpProtocol());
     System.out.println(logSplit.getUrl());                 
     System.out.println(logSplit.getHttpVersion());
     System.out.println(logSplit.getHttpCategory());
     System.out.println(logSplit.getRisk());
     System.out.println(logSplit.getHttpContentType());         
     System.out.println(logSplit.getBytesIN());
     System.out.println(logSplit.getBytesOUT());
     System.out.println(logSplit.getHttpUserAgent());            // DYNAMIC VALUE! (TODO)
     System.out.println(logSplit.getSignature());
     System.out.println(logSplit.getAction());
     System.out.println(logSplit.getBlockResult());
     System.out.println(logSplit.getCustomRuleName());
     System.out.println(logSplit.getDestIP());
     System.out.println(logSplit.getHttpReferrer());
     
     
     
     //------------------MAIN TEST LOGREGEX------------------
    
     logRegexObj logRegex = new logRegexObj(log);
     
     System.out.println("----------------------------");
     System.out.println();
     System.out.println();
     System.out.println();
     System.out.println("----------------------------");
     
     System.out.println(logRegex.sysLogTimeStamp1(log));
     System.out.println(logRegex.proxyIP(log));
     System.out.println(logRegex.product(log));
       System.out.println(logRegex.eventTimeStamp(log));
     System.out.println(logRegex.user(log));
     System.out.println(logRegex.sourceIP(log));
     System.out.println(logRegex.status(log));
     System.out.println(logRegex.httpMethod(log));          
           						/// System.out.println(logRegex.httpProtocol(log));		<- Don't exist in log
      System.out.println(logRegex.url(log));                 
     System.out.println(logRegex.httpVersion(log));
     System.out.println(logRegex.httpCategory(log));
     System.out.println(logRegex.risk(log));
     System.out.println(logRegex.httpContentType(log));         
     System.out.println(logRegex.bytesIN(log));
       System.out.println(logRegex.bytesOUT(log));
       System.out.println(logRegex.httpUserAgent(log));            // DYNAMIC VALUE! (TODO)
     System.out.println(logRegex.signature(log));
     System.out.println(logRegex.action(log));
     System.out.println(logRegex.blockResult(log));
     System.out.println(logRegex.customRuleName(log));
     System.out.println(logRegex.destIP(log));
     System.out.println(logRegex.httpReferrer(log));
		
		
		
	}
}

