package pl.example.logRegex;

public class LogRegexSplit extends LogGettersSetters {
	   
    private String log;
   
    //----KONSTRUKTOR----
    LogRegexSplit(String log) {
    this.log = log;
    }
   
    void setValues() {
        String[] tmp = log.split("\\s+");
       
        for(int i=0; i < tmp.length; i++) {
            if(!tmp[i].equals("\"\""))                  // remove unnecessary tags ""
            tmp[i] = tmp[i].replaceAll("\"", "");
            //System.out.println(tmp[i]);           // <- line to see log without groups
        }
       
        //          GROUPS LOG
        setSysLogTimeStamp1(tmp[0]+" "+tmp[1]+" "+tmp[2]);
        setProxyIP(tmp[3]);
        setProduct(tmp[4]);
        setEventTimeStamp(tmp[5]+" "+tmp[6]);
        setUser(tmp[7]);
        setSourceIP(tmp[8]);
        setStatus(tmp[9]);
        setHttpMethod(tmp[10]);
        setHttpProtocol(tmp[11]);
        setUrl(tmp[12]);
        setHttpVersion(tmp[13]);
        setHttpCategory(tmp[14]);
        setRisk(tmp[15]);  
        setHttpContentType(tmp[16]);
        setBytesIN(tmp[17]);
        setBytesOUT(tmp[18]);
        setHttpUserAgent(tmp[19]+" "+tmp[20]+" "+tmp[21]+" "+tmp[22]+" "+tmp[23]+" "+tmp[24]+" "+tmp[25]+" "+tmp[26]+" "+tmp[27]+" "+tmp[28]+" "+tmp[29]);
        setSignature(tmp[30]);
        setAction(tmp[31]);
        setBlockResult(tmp[32]);
        setCustomRuleName(tmp[33]+" "+tmp[34]+" "+tmp[35]);
        setDestIP(tmp[36]);
        setHttpReferrer(tmp[37]);
   
    }
   
}

