package pl.example.logRegex;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class logRegexObj implements LogInterface {
	
	private static final String BYTES_OUT_REGEX = "(\\s\\d+\\s\\x22)";
	private static final String URL_REGEX = "(\\x22\\s\\S+\\s+\\S+\\s\\x22)";
	private static final String STATUS_REGEX = "(\\s\\d{3}\\s)";
	private static final String EVENT_TIME_STAMP_REGEX = "(\\s\\[([^\\]]+)\\])";
	//------UPPER ADDED IN THE END
	private static final String HTTP_REFERRER_REGEX = "\\s\\x22(\\x22)$";
	private static final String DEST_IP_REGEX = "(\\x22\\d+\\.\\d+\\.\\d+\\.\\d+\\x22)";
	private static final String CUSTOM_RULE_NAME_REGEX = "(\\s\\x22[\\w\\s]*\\x22\\s)";
	private static final String ACTION_REGEX = "(\\s\\x22\\d+\\x22\\s)";
	private static final String SIGNATURE_REGEX = "(\\s\\x22\\x22\\s)";
	private static final String BYTES_IN_REGEX = "(\\x22\\s\\d+\\s)";
	private static final String HTTP_CONTENT_TYPE_REGEX = "(\\x22\\x22\\s)";
	private static final String RISK_REGEX = "(\\x22[A-Z]\\S\\w*\\x22)";
	private static final String HTTP_CATEGORY_REGEX = "(\\x22[A-Z;a-z]+\\S+\\s+\\S*\\x22)";
	private static final String HTTP_VERSION_REGEX = "(HTTP/[0-9]*\\.[0-9]*)";
	//private static final String HTTP_PROTOCOL_REGEX = "(http://|https://)?"; DON'T EXIST IN LOG
	private static final String HTTP_METHOD_REGEX = "([A-Z]{3,7}\\s)";
	private static final String SOURCE_IP_REGEX = "(\\x22\\s\\d+\\.\\d+\\.\\d+\\.\\d+\\s)";
	private static final String USER_REGEX = "(\\]\\s\\x22([^\\x22]*)\\x22\\s)";
	private static final String PRODUCT_REGEX = "(\\s\\w+:\\s\\[{1})";
	private static final String PROXY_IP_REGEX = "(\\d+\\.\\d+\\.\\d+\\.\\d+)";
	private static final String SYS_LOG_REGEX = "^(\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+)";
	
	String log;
	
	public logRegexObj(String log) {
		this.log = log;
	} 
	
	//-----------USEFUL METHODS---------
	private String FindAndClean(Matcher matcher, String result, int groupNumber) {
		try {
		        if(matcher.find())
		            result = matcher.group(groupNumber);
		        if(!result.equals("\"\""))					// remove unnecessary tags ""
					result = result.replaceAll("\"", "");      
		  }catch(IllegalStateException isEx) {
			  System.out.println("NOT FOUND MATCH! "+isEx);  
		  }
		return result;
	}
	
	//-----------MAIN METHODS---------
	
	 public String sysLogTimeStamp1(String log) {
		 
	       Pattern sysLogPattern = Pattern.compile(SYS_LOG_REGEX);
	       Matcher matcher = sysLogPattern.matcher(log);
	       String result = null;
	       
		      result = FindAndClean(matcher, result, 1);
	      
	       return result;    
	    }
	
	//-----------------------------------------------
	
	public String proxyIP(String log) {
		
		Pattern proxyIPPattern = Pattern.compile(PROXY_IP_REGEX);
	    Matcher matcher = proxyIPPattern.matcher(log);
	    String result = null;
	       
		      result = FindAndClean(matcher, result, 1);
	      
	    return result; 
		
	}
	
	//-----------------------------------------------
	
	public String product(String log) {
		 
		Pattern productPattern = Pattern.compile(PRODUCT_REGEX);
		
		Matcher matcher = productPattern.matcher(log);
		
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
    
	    return result; 
	}
	
	//-----------------------------------------------
	
	public String eventTimeStamp(String log) {
		 
		Pattern eventTimeStampPattern = Pattern.compile(EVENT_TIME_STAMP_REGEX);
	    Matcher matcher = eventTimeStampPattern.matcher(log);   
	    String result = null;
		       
		result = FindAndClean(matcher, result, 1);
	    
		return result;  
	}
	
	public String user(String log) {
		
		Pattern userPattern = Pattern.compile(USER_REGEX);
	    Matcher matcher = userPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
  
	    return result;  
	}
	
	public String sourceIP(String log) {
		 
		Pattern sourceIPPattern = Pattern.compile(SOURCE_IP_REGEX);
		Matcher matcher = sourceIPPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
  
	    return result; 
	}

	public String status(String log) {

		Pattern statusPattern = Pattern.compile(STATUS_REGEX);
		
	    Matcher matcher = statusPattern.matcher(log);   
	    String result = null;
		       
		result = FindAndClean(matcher, result, 1);
	    
		return result;  
	}
	
	public String httpMethod(String log) {
		 
		Pattern methodPattern = Pattern.compile(HTTP_METHOD_REGEX);
		Matcher matcher = methodPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
  
	    return result; 
	}
	
/*	public String httpProtocol(String log) {								<- Don't exist in log
		 
		Pattern protocolPattern = Pattern.compile(HTTP_PROTOCOL_REGEX);
		Matcher matcher = protocolPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
  
	    return result; 
	}*/
	
	public String url(String log) {						

		Pattern urlPattern = Pattern.compile(URL_REGEX);
		Matcher matcher = urlPattern.matcher(log);
		
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
  
	    return result; 
	}
	
	public String httpVersion(String log) {
		 
		Pattern versionPattern = Pattern.compile(HTTP_VERSION_REGEX);
		Matcher matcher = versionPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
  
	    return result; 
		}
	
	
	public String httpCategory(String log) {					//ZADZIALA TYLKO Z findFirstText
		 															//log.replaceAll("/", "znak");
		Pattern httpCategoryPattern = Pattern.compile(HTTP_CATEGORY_REGEX);
		Matcher matcher = httpCategoryPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
  
	    return result; 
		}
	
	public String risk(String log) {
		 									
		Pattern riskPattern = Pattern.compile(RISK_REGEX);
		Matcher matcher = riskPattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
  
	    return result; 
		}
	
	public String httpContentType(String log) {								
		 
		Pattern contentTypePattern = Pattern.compile(HTTP_CONTENT_TYPE_REGEX);
		Matcher matcher = contentTypePattern.matcher(log);
			
	    String result = null;
	       
	      result = FindAndClean(matcher, result, 1);
  
	    return result;  
		}
	
	public String bytesIN(String log) {											
		 
		Pattern bytesINPattern = Pattern.compile(BYTES_IN_REGEX);
		Matcher matcher = bytesINPattern.matcher(log);
			
		String result = null;
		       
		      result = FindAndClean(matcher, result, 1);
	    
		return result;  
		}
	
	public String bytesOUT(String log) {											
		 
		Pattern bytesOUTPattern = Pattern.compile(BYTES_OUT_REGEX);
		Matcher matcher = bytesOUTPattern.matcher(log);
			
			String result = null;
			       
			      result = FindAndClean(matcher, result, 2);			// GROUP 2 MUSI BYC
	    return result; 
		}
	
	public String httpUserAgent(String log) {
		 
		Pattern userAgentPattern = Pattern.compile("(\\w+)");			// REGEX TODO
		Matcher matcher = userAgentPattern.matcher(log);
		
		String result = null;
		       
		      result = FindAndClean(matcher, result, 1);
	    
		return result;  
		}
	
	public String signature(String log) {
		 
		Pattern signaturePattern = Pattern.compile(SIGNATURE_REGEX);
		Matcher matcher = signaturePattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result, 1);
	    
		    return result; 
		}
	
	public String action(String log) {
		 
		Pattern actionPattern = Pattern.compile(ACTION_REGEX);
		Matcher matcher = actionPattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result, 1);
	    
		    return result; 
		}
	
	public String blockResult(String log) {
		 
		Pattern ruleNamePattern = Pattern.compile(SIGNATURE_REGEX);
		Matcher matcher = ruleNamePattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result, 1);
	    
		    return result;   
		}
	
	public String customRuleName(String log) {										//REGEX TODO
		 
		Pattern ruleNamePattern = Pattern.compile(CUSTOM_RULE_NAME_REGEX);
		Matcher matcher = ruleNamePattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result, 1);
	    
		    return result; 
		}
	
	public String destIP(String log) {
		 
		Pattern destIPPattern = Pattern.compile(DEST_IP_REGEX);
		Matcher matcher = destIPPattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result, 1);
	    
		    return result;  
		}
	
	public String httpReferrer(String log) {
		 
		Pattern referrerPattern = Pattern.compile(HTTP_REFERRER_REGEX);
		Matcher matcher = referrerPattern.matcher(log);
			
		    String result = null;
		       
		      result = FindAndClean(matcher, result, 1);
	    
		    return result;  
		}

	public String httpProtocol(String log) {
		// TODO Auto-generated method stub
		return null;
	}
	
	
	}
