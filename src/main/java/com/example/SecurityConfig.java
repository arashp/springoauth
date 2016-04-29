/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example;


import java.io.IOException;
import java.security.Principal;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

/**
 *
 * @author arash.pourmoghaddam
 */
@Configuration
@EnableWebSecurity(debug = true)
@ComponentScan({"com.example"})
@EnableOAuth2Client
@RestController
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    
    
    
    
    @Autowired
        PropertyConfig properties;
        
	@Autowired
	OAuth2ClientContext oauth2ClientContext;
        
       
        public OAuth2RestTemplate facebookTemplate;
        
        
        public  OAuth2RestTemplate salesforceTemplate;
        
        
        @RequestMapping("/user")
	public Principal user(Principal principal) {
                
		return principal;
	}
        
          @RequestMapping(value="/SaveProviderToSession",method=RequestMethod.POST)
        public void SaveProviderToSession(@RequestBody String provider, HttpSession httpSession) {
                  httpSession.setAttribute("Provider", provider);
        }
        
        
        @RequestMapping(value="/GetProviderFromSession",method=RequestMethod.GET)
        public String GetProviderFromSession(HttpSession httpSession) {
                if(httpSession.getAttribute("Provider") == null)
                {
                    return "";
                }else{
                    return httpSession.getAttribute("Provider").toString();    
                }
                
        }
        
       
        
        
        @RequestMapping("/salesforce/userinfo")
	public String salesforceuser() {
		return facebookTemplate.getForObject(salesforceResource().getUserInfoUri(), String.class);
                
	}
        
        @RequestMapping("/facebook/userinfo")
	public String facebookuser() {
		return facebookTemplate.getForObject(facebookResource().getUserInfoUri(), String.class);
                
	}
        
        @RequestMapping("/salesforce/feeds")
	public String salesforceFeeds() {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
	        
                    return salesforceTemplate.getForObject("https://arash-dev-ed.my.salesforce.com/services/data/v36.0/chatter/feeds/news/" + auth.getPrincipal().toString() + "/feed-elements" , String.class);
              
        }
        
        @RequestMapping("/facebook/likes")
	public String facebookLikes() {
                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
	        
                    return facebookTemplate.getForObject("https://graph.facebook.com/v2.6/" + auth.getPrincipal().toString() + "/likes" , String.class);
              
        }
            
    private Filter csrfHeaderFilter() {
		return new OncePerRequestFilter() {
			@Override
			protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
					FilterChain filterChain) throws ServletException, IOException {
				CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                                 
				if (csrf != null) {
					Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
					String token = csrf.getToken();
					if (cookie == null || token != null && !token.equals(cookie.getValue())) {
						cookie = new Cookie("XSRF-TOKEN", token);
						cookie.setPath("/");
						response.addCookie(cookie);
					}
				}
				filterChain.doFilter(request, response);
			}
		};
	}

	private CsrfTokenRepository csrfTokenRepository() {
		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.setHeaderName("X-XSRF-TOKEN");
		return repository;
	}
        
        
        @Bean
        public Filter ssoSalesforceFilter() {
		OAuth2ClientAuthenticationProcessingFilter salesforceFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/salesforce");
	        
                salesforceTemplate = new OAuth2RestTemplate(salesforce(), oauth2ClientContext);
		
                
                salesforceFilter.setRestTemplate(salesforceTemplate);
		
                salesforceFilter.setTokenServices(new UserInfoTokenServices(salesforceResource().getUserInfoUri(), salesforce().getClientId()));
                
                return salesforceFilter;
	}
        
        @Bean
	public Filter ssoFacebookFilter() {
		OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
	        
                facebookTemplate = new OAuth2RestTemplate(facebook(), oauth2ClientContext);
		
                
                facebookFilter.setRestTemplate(facebookTemplate);
		
                facebookFilter.setTokenServices(new UserInfoTokenServices(facebookResource().getUserInfoUri(), facebook().getClientId()));
                
                return facebookFilter;
	}
        
	@Bean
        OAuth2ProtectedResourceDetails salesforce() {
		AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
                details.setAccessTokenUri(properties.getSalesforceAccessTokenUri());
                details.setUserAuthorizationUri(properties.getSalesforceUserAuthorizationUri());
                details.setAuthenticationScheme(AuthenticationScheme.valueOf(properties.getSalesforceAuthenticationScheme()));
                details.setClientAuthenticationScheme(AuthenticationScheme.valueOf(properties.getSalesforceClientAuthenticationScheme()));
                details.setClientId(properties.getSalesforceClientId());
                details.setClientSecret(properties.getSalesforceClientSecret());
                details.setTokenName(properties.getSalesforceTokenName());
                details.setUseCurrentUri(properties.isSalesforceUseCurrentUri());
                details.setPreEstablishedRedirectUri(properties.getSalesforcePreEstablishedRedirectUri());
                details.setScope(properties.getSalesforceScopes());
                return details;
	}
        
           
        @Bean
        OAuth2ProtectedResourceDetails facebook() {
		AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
                details.setAccessTokenUri(properties.getFacebookAccessTokenUri());
                details.setUserAuthorizationUri(properties.getFacebookUserAuthorizationUri());
                details.setAuthenticationScheme(AuthenticationScheme.valueOf(properties.getFacebookAuthenticationScheme()));
                details.setClientAuthenticationScheme(AuthenticationScheme.valueOf(properties.getFacebookClientAuthenticationScheme()));
                details.setClientId(properties.getFacebookClientId());
                details.setClientSecret(properties.getFacebookClientSecret());
                details.setTokenName(properties.getFacebookTokenName());
                details.setScope(properties.getFacebookScopes());
                return details;
	}

	@Bean
	ResourceServerProperties salesforceResource() {
		ResourceServerProperties resource = new ResourceServerProperties();
                resource.setUserInfoUri(properties.getSalesforceUserInfoUri());
                return resource;
	}
        
        @Bean
	ResourceServerProperties facebookResource() {
		ResourceServerProperties resource = new ResourceServerProperties();
                resource.setUserInfoUri(properties.getFacebookUserInfoUri());
                return resource;
	}
        
       
   
        
       @Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off	
               
		http.antMatcher("/**")
			.authorizeRequests()
				.antMatchers("/SaveProviderToSession","/GetProviderFromSession","/", "/login**","/webjars/**","/hello**").permitAll()
				.anyRequest().authenticated()
			.and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
			.and().logout().logoutSuccessUrl("/").permitAll()
			.and().csrf().csrfTokenRepository(csrfTokenRepository())
			.and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
			.addFilterBefore(ssoSalesforceFilter(), BasicAuthenticationFilter.class)
                        .addFilterBefore(ssoFacebookFilter(), BasicAuthenticationFilter.class);
                      
		// @formatter:on
	}
}
