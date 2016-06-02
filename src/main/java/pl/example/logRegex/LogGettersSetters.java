package pl.example.logRegex;

public class LogGettersSetters {
	 
    private String sysLogTimeStamp1;
    private String proxyIP;
    private String product;
    private String eventTimeStamp;
    private String user;
    private String sourceIP;
    private String status;
    private String httpMethod;
    private String httpProtocol;
    private String url;
    private String httpVersion;
    private String httpCategory;
    private String risk;
    private String httpContentType;
    private String bytesIN;
    private String bytesOUT;
    private String httpUserAgent;
    private String signature;
    private String action;
    private String blockResult;
    private String customRuleName;
    private String destIP;
    private String httpReferrer;
   
 
    public String getSysLogTimeStamp1() {
        return sysLogTimeStamp1;
    }
    public void setSysLogTimeStamp1(String sysLogTimeStamp1) {
        this.sysLogTimeStamp1 = sysLogTimeStamp1;
    }
    public String getProxyIP() {
        return proxyIP;
    }
    public void setProxyIP(String proxyIP) {
        this.proxyIP = proxyIP;
    }
    public String getProduct() {
        return product;
    }
    public void setProduct(String product) {
        this.product = product;
    }
    public String getEventTimeStamp() {
        return eventTimeStamp;
    }
    public void setEventTimeStamp(String eventTimeStamp) {
        this.eventTimeStamp = eventTimeStamp;
    }
    public String getUser() {
        return user;
    }
    public void setUser(String user) {
        this.user = user;
    }
    public String getSourceIP() {
        return sourceIP;
    }
    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }
    public String getStatus() {
        return status;
    }
    public void setStatus(String status) {
        this.status = status;
    }
    public String getHttpMethod() {
        return httpMethod;
    }
    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }
    public String getHttpProtocol() {
        return httpProtocol;
    }
    public void setHttpProtocol(String httpProtocol) {
        this.httpProtocol = httpProtocol;
    }
    public String getUrl() {
        return url;
    }
    public void setUrl(String url) {
        this.url = url;
    }
    public String getHttpVersion() {
        return httpVersion;
    }
    public void setHttpVersion(String httpVersion) {
        this.httpVersion = httpVersion;
    }
    public String getHttpCategory() {
        return httpCategory;
    }
    public void setHttpCategory(String httpCategory) {
        this.httpCategory = httpCategory;
    }
    public String getRisk() {
        return risk;
    }
    public void setRisk(String risk) {
        this.risk = risk;
    }
    public String getHttpContentType() {
        return httpContentType;
    }
    public void setHttpContentType(String httpContentType) {
        this.httpContentType = httpContentType;
    }
    public String getBytesIN() {
        return bytesIN;
    }
    public void setBytesIN(String bytesIN) {
        this.bytesIN = bytesIN;
    }
    public String getBytesOUT() {
        return bytesOUT;
    }
    public void setBytesOUT(String bytesOUT) {
        this.bytesOUT = bytesOUT;
    }
    public String getHttpUserAgent() {
        return httpUserAgent;
    }
    public void setHttpUserAgent(String httpUserAgent) {
        this.httpUserAgent = httpUserAgent;
    }
    public String getSignature() {
        return signature;
    }
    public void setSignature(String signature) {
        this.signature = signature;
    }
    public String getAction() {
        return action;
    }
    public void setAction(String action) {
        this.action = action;
    }
    public String getBlockResult() {
        return blockResult;
    }
    public void setBlockResult(String blockResult) {
        this.blockResult = blockResult;
    }
    public String getCustomRuleName() {
        return customRuleName;
    }
    public void setCustomRuleName(String customRuleName) {
        this.customRuleName = customRuleName;
    }
    public String getDestIP() {
        return destIP;
    }
    public void setDestIP(String destIP) {
        this.destIP = destIP;
    }
    public String getHttpReferrer() {
        return httpReferrer;
    }
    public void setHttpReferrer(String httpReferrer) {
        this.httpReferrer = httpReferrer;
    }
   
   
    //------------ hashCode() AND equals() --------------------
   
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((action == null) ? 0 : action.hashCode());
        result = prime * result + ((blockResult == null) ? 0 : blockResult.hashCode());
        result = prime * result + ((bytesIN == null) ? 0 : bytesIN.hashCode());
        result = prime * result + ((bytesOUT == null) ? 0 : bytesOUT.hashCode());
        result = prime * result + ((customRuleName == null) ? 0 : customRuleName.hashCode());
        result = prime * result + ((destIP == null) ? 0 : destIP.hashCode());
        result = prime * result + ((eventTimeStamp == null) ? 0 : eventTimeStamp.hashCode());
        result = prime * result + ((httpCategory == null) ? 0 : httpCategory.hashCode());
        result = prime * result + ((httpContentType == null) ? 0 : httpContentType.hashCode());
        result = prime * result + ((httpMethod == null) ? 0 : httpMethod.hashCode());
        result = prime * result + ((httpProtocol == null) ? 0 : httpProtocol.hashCode());
        result = prime * result + ((httpReferrer == null) ? 0 : httpReferrer.hashCode());
        result = prime * result + ((httpUserAgent == null) ? 0 : httpUserAgent.hashCode());
        result = prime * result + ((httpVersion == null) ? 0 : httpVersion.hashCode());
        result = prime * result + ((product == null) ? 0 : product.hashCode());
        result = prime * result + ((proxyIP == null) ? 0 : proxyIP.hashCode());
        result = prime * result + ((risk == null) ? 0 : risk.hashCode());
        result = prime * result + ((signature == null) ? 0 : signature.hashCode());
        result = prime * result + ((sourceIP == null) ? 0 : sourceIP.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((sysLogTimeStamp1 == null) ? 0 : sysLogTimeStamp1.hashCode());
        result = prime * result + ((url == null) ? 0 : url.hashCode());
        result = prime * result + ((user == null) ? 0 : user.hashCode());
        return result;
    }
   
   
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        LogGettersSetters other = (LogGettersSetters) obj;
        if (action == null) {
            if (other.action != null)
                return false;
        } else if (!action.equals(other.action))
            return false;
        if (blockResult == null) {
            if (other.blockResult != null)
                return false;
        } else if (!blockResult.equals(other.blockResult))
            return false;
        if (bytesIN == null) {
            if (other.bytesIN != null)
                return false;
        } else if (!bytesIN.equals(other.bytesIN))
            return false;
        if (bytesOUT == null) {
            if (other.bytesOUT != null)
                return false;
        } else if (!bytesOUT.equals(other.bytesOUT))
            return false;
        if (customRuleName == null) {
            if (other.customRuleName != null)
                return false;
        } else if (!customRuleName.equals(other.customRuleName))
            return false;
        if (destIP == null) {
            if (other.destIP != null)
                return false;
        } else if (!destIP.equals(other.destIP))
            return false;
        if (eventTimeStamp == null) {
            if (other.eventTimeStamp != null)
                return false;
        } else if (!eventTimeStamp.equals(other.eventTimeStamp))
            return false;
        if (httpCategory == null) {
            if (other.httpCategory != null)
                return false;
        } else if (!httpCategory.equals(other.httpCategory))
            return false;
        if (httpContentType == null) {
            if (other.httpContentType != null)
                return false;
        } else if (!httpContentType.equals(other.httpContentType))
            return false;
        if (httpMethod == null) {
            if (other.httpMethod != null)
                return false;
        } else if (!httpMethod.equals(other.httpMethod))
            return false;
        if (httpProtocol == null) {
            if (other.httpProtocol != null)
                return false;
        } else if (!httpProtocol.equals(other.httpProtocol))
            return false;
        if (httpReferrer == null) {
            if (other.httpReferrer != null)
                return false;
        } else if (!httpReferrer.equals(other.httpReferrer))
            return false;
        if (httpUserAgent == null) {
            if (other.httpUserAgent != null)
                return false;
        } else if (!httpUserAgent.equals(other.httpUserAgent))
            return false;
        if (httpVersion == null) {
            if (other.httpVersion != null)
                return false;
        } else if (!httpVersion.equals(other.httpVersion))
            return false;
        if (product == null) {
            if (other.product != null)
                return false;
        } else if (!product.equals(other.product))
            return false;
        if (proxyIP == null) {
            if (other.proxyIP != null)
                return false;
        } else if (!proxyIP.equals(other.proxyIP))
            return false;
        if (risk == null) {
            if (other.risk != null)
                return false;
        } else if (!risk.equals(other.risk))
            return false;
        if (signature == null) {
            if (other.signature != null)
                return false;
        } else if (!signature.equals(other.signature))
            return false;
        if (sourceIP == null) {
            if (other.sourceIP != null)
                return false;
        } else if (!sourceIP.equals(other.sourceIP))
            return false;
        if (status == null) {
            if (other.status != null)
                return false;
        } else if (!status.equals(other.status))
            return false;
        if (sysLogTimeStamp1 == null) {
            if (other.sysLogTimeStamp1 != null)
                return false;
        } else if (!sysLogTimeStamp1.equals(other.sysLogTimeStamp1))
            return false;
        if (url == null) {
            if (other.url != null)
                return false;
        } else if (!url.equals(other.url))
            return false;
        if (user == null) {
            if (other.user != null)
                return false;
        } else if (!user.equals(other.user))
            return false;
        return true;
    }
 
}