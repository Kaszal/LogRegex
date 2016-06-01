package pl.example.logRegex;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class logRegex {
	
	private static String log = "May 18 09:31:44 10.51.177.2 mwg: [18/May/2016:09:31:44 +1000] \"pgor\" 10.52.28.227 200 \"CONNECT buttons.reddit.com:443 HTTP/1.1\" \"Forum/Bulletin Boards\" \"Unverified\" \"\" 0 0 \"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.75 Safari/537.36\" \"\" \"0\" \"\" \"Global Whitelist: Sites\" \"198.41.208.137\" \"\""; 
	
	 public String sysLogTimeStamp1(String log) {
	        
	       String result;
	       Pattern sysLogPattern = Pattern.compile("^(\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)");
	       
		      Matcher matcher = sysLogPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;         
	          
	    }
	
	//-----------------------------------------------
	
	public String proxyIP(String log) {
		String result;
		Pattern proxyIPPattern = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;   
	}
	
	//-----------------------------------------------
	
	public String product(String log) {
		
		String result;
		
		Pattern productPattern = Pattern.compile("\\w+");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}
	
	//-----------------------------------------------
	
	public String eventTimeStamp(String log) {
		 
		
		String result;
		
		Pattern productPattern = Pattern.compile("\\s\\[([^\\]]+)\\]");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}
	
	public String user(String log) {
		 
		
		String result;
		
		Pattern userPattern = Pattern.compile("\\s\\x22([^\\x22]*)\\x22\\s");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}
	
	public String sourceIP(String log) {
		 
		
		String result;
		
		Pattern IPPattern = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}

	public String status(String log) {
		 
		
		String result;
		
		Pattern IPPattern = Pattern.compile("\\d{1,3}");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}
	
	public String httpMethod(String log) {
		 
		
		String result;
		
		Pattern methodPattern = Pattern.compile("\\s\\x22(\\w+)\\s");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}
	
	public String httpProtocol(String log) {
		 
		
		String result;
		
		Pattern protocolPattern = Pattern.compile("(http://|https://)?");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}
	
	public String url(String log) {
		 
		
		String result;
		
		Pattern urlPattern = Pattern.compile("\\S+:");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	}
	
	public String httpVersion(String log) {
		 
		
		String result;
		
		Pattern versionPattern = Pattern.compile("\\w+/\\d+\\.\\d+");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	
	public String httpCategory(String log) {
		 
		
		String result;
		
																		//log.replaceAll("/", "znak");
		
		Pattern versionPattern = Pattern.compile("\\w*\\w*");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
	
	public String risk(String log) {
		 
		
		String result;
												//\\s\\x22([^\\x22]*)\\x22\\s
		Pattern riskPattern = Pattern.compile("\\s\\x22\\w*\\x22\\s");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String httpContentType(String log) {
		 
		
		String result;
		
		Pattern contentTypePattern = Pattern.compile("\\x22\\x22\\s");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String bytesIN(String log) {
		 
		
		String result;
		
		Pattern bytesINPattern = Pattern.compile("\\s\\d+");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String bytesOUT(String log) {
		 
		
		String result;
		
		Pattern bytesOUTPattern = Pattern.compile("\\s\\d+");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String httpUserAgent(String log) {
		 
		
		String result;
		
		Pattern userAgentPattern = Pattern.compile("(^\\x22)\\w");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String signature(String log) {
		 
		
		String result;
		
		Pattern signaturePattern = Pattern.compile("\\s\\x22\\x22\\s");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String action(String log) {
		 
		
		String result;
		
		Pattern actionPattern = Pattern.compile("\\s\\x22\\d+\\x22\\s");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String blockResult(String log) {
		 
		
		String result;
		
		Pattern ruleNamePattern = Pattern.compile("\\s\\x22\\x22\\s");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String customRuleName(String log) {
		 
		
		String result;
		
		Pattern ruleNamePattern = Pattern.compile("\\s\\x22[\\w\\s]*\\x22\\s");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String destIP(String log) {
		 
		
		String result;
		
		Pattern destIPPattern = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public String httpReferrer(String log) {
		 
		
		String result;
		
		Pattern referrerPattern = Pattern.compile("\\s\\x22(\\x22)$");
		
	      Matcher matcher = proxyIPPattern.matcher(log);
		   
	        if(matcher.find())
	            result = matcher.group(1);
	        else
	        	result = "NOT FOUND";
	      
	        return result;  
		}
	
	public static void main(String[] args) {
		
		logRegex log1 = new logRegex();
		
		System.out.println(log1.sysLogTimeStamp1(log));
	}
	
	
	}
