/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.example;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 *
 * @author DevAdmin
 */

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "root")

public class PropertyConfig {
    @Value("${root.facebook.client.clientId}")
    private String facebookclientId;
    public String getFacebookClientId()
    {
        return facebookclientId;
    }
    
    @Value("${root.facebook.client.clientSecret}")
    private String facebookclientSecret;
    public String getFacebookClientSecret()
    {
        return facebookclientSecret;
    }
    
    @Value("${root.facebook.client.accessTokenUri}")
    private String facebookaccessTokenUri;
    public String getFacebookAccessTokenUri()
    {
        return facebookaccessTokenUri;
    }
    
    @Value("${root.facebook.client.userAuthorizationUri}")
    private String facebookuserAuthorizationUri;
    public String getFacebookUserAuthorizationUri()
    {
        return facebookuserAuthorizationUri;
    }
    
    @Value("${root.facebook.client.tokenName}")
    private String facebooktokenName;
    public String getFacebookTokenName()
    {
        return facebooktokenName;
    }
    
    @Value("${root.facebook.client.authenticationScheme}")
    private String facebookauthenticationScheme;
    public String getFacebookAuthenticationScheme()
    {
        return facebookauthenticationScheme;
    }
    
    @Value("${root.facebook.client.clientAuthenticationScheme}")
    private String facebookclientAuthenticationScheme;
    public String getFacebookClientAuthenticationScheme()
    {
        return facebookclientAuthenticationScheme;
    }
    
    @Value("${root.facebook.resource.userInfoUri}")
    private String facebookuserInfoUri;
    public String getFacebookUserInfoUri()
    {
        return facebookuserInfoUri;
    }
    
    @Value("#{'${root.facebook.client.scope}'.split(',')}")
    private List<String> fbscope;
    public List<String> getFacebookScopes()
    {
        return fbscope;
    }
    
    
    //salesforce configs
    
    @Value("${root.salesforce.client.clientId}")
    private String salesforceclientId;
    public String getSalesforceClientId()
    {
        return salesforceclientId;
    }
    
    @Value("${root.salesforce.client.clientSecret}")
    private String salesforceclientSecret;
    public String getSalesforceClientSecret()
    {
        return salesforceclientSecret;
    }
    
    @Value("${root.salesforce.client.accessTokenUri}")
    private String salesforceaccessTokenUri;
    public String getSalesforceAccessTokenUri()
    {
        return salesforceaccessTokenUri;
    }
    
    @Value("${root.salesforce.client.userAuthorizationUri}")
    private String salesforceuserAuthorizationUri;
    public String getSalesforceUserAuthorizationUri()
    {
        return salesforceuserAuthorizationUri;
    }
    
    @Value("${root.salesforce.client.tokenName}")
    private String salesforcetokenName;
    public String getSalesforceTokenName()
    {
        return salesforcetokenName;
    }
    
    @Value("${root.salesforce.client.authenticationScheme}")
    private String salesforceauthenticationScheme;
    public String getSalesforceAuthenticationScheme()
    {
        return salesforceauthenticationScheme;
    }
    
    @Value("${root.salesforce.client.clientAuthenticationScheme}")
    private String salesforceclientAuthenticationScheme;
    public String getSalesforceClientAuthenticationScheme()
    {
        return salesforceclientAuthenticationScheme;
    }
    
    @Value("${root.salesforce.client.useCurrentUri}")
    private boolean salesforceuseCurrentUri;
    public boolean isSalesforceUseCurrentUri()
    {
        return salesforceuseCurrentUri;
    }
    
    @Value("${root.salesforce.client.preEstablishedRedirectUri}")
    private String salesforcepreEstablishedRedirectUri;
    public String getSalesforcePreEstablishedRedirectUri()
    {
        return salesforcepreEstablishedRedirectUri;
    }
    
    @Value("${root.salesforce.resource.userInfoUri}")
    private String salesforceuserInfoUri;
    public String getSalesforceUserInfoUri()
    {
        return salesforceuserInfoUri;
    }
    
    
    
    
     
    @Value("#{'${root.salesforce.client.scope}'.split(',')}")
    private List<String> sfscope;
    public List<String> getSalesforceScopes()
    {
        return sfscope;
    }
    
   
}
