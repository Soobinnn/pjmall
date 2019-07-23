package com.example.pjmall.frontend.config.app;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import javax.servlet.ServletException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.pjmall.frontend.security.CustomUrlAuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class AppSecurityConfig {

	@Autowired
	private UserDetailsService userDetailsService;
	
	
	@Bean(name="springSecurityFilterChain")
	public FilterChainProxy getFilterChainProxy() throws ServletException, Exception {
		List<SecurityFilterChain> securityFilterChains = new ArrayList<SecurityFilterChain>();
		
		
		securityFilterChains.add(new DefaultSecurityFilterChain( new AntPathRequestMatcher("/assets/**") ));
		securityFilterChains.add(new DefaultSecurityFilterChain( new AntPathRequestMatcher("/favicon.ico") ));
		
		
		securityFilterChains.add(new DefaultSecurityFilterChain( new AntPathRequestMatcher("/**"),
			// 1.
			securityContextPersistenceFilter(),
			// 2.
			logoutFilter(),
			// 3.
			usernamePasswordAuthenticationFilter( authenticationSuccessHandler() ),
			// 4.
			// anonymousProcessingFilter(),
			// 5.
			exceptionTranslationFilter(),
			// 6.
			filterSecurityInterceptor()
		));
		
		return new FilterChainProxy( securityFilterChains );
	}
	
	
	/* 1. securityContextPersistenceFilter  securityContext를 관리하는 필터 (필수) */
	@Bean
	public SecurityContextPersistenceFilter securityContextPersistenceFilter() {
		return new SecurityContextPersistenceFilter( new HttpSessionSecurityContextRepository() );
	}

	/* 2. LogoutFilter: logout으로 오는 것을 감시한다. customLogoutSuccessHandler - 로그아웃성공하면 메인이지만, API의 경우 로그아웃성공하면 JSON으로 응답 */
	@Bean
	public LogoutFilter logoutFilter() throws ServletException {
		
		CookieClearingLogoutHandler cookieClearingLogoutHandler = new CookieClearingLogoutHandler("JSESSIONID");

		SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
		securityContextLogoutHandler.setInvalidateHttpSession(true);
		securityContextLogoutHandler.setClearAuthentication(true);
		
		LogoutFilter logoutFilter = new LogoutFilter( "/", cookieClearingLogoutHandler,  securityContextLogoutHandler);
		logoutFilter.setFilterProcessesUrl("/user/logout");
		logoutFilter.afterPropertiesSet();
		
		return logoutFilter;
	}	

	
	/* 3. */
	@Bean
	public AbstractAuthenticationProcessingFilter usernamePasswordAuthenticationFilter(AuthenticationSuccessHandler authenticationSuccessHandler) throws Exception {
		
		UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter = new UsernamePasswordAuthenticationFilter();
		
		usernamePasswordAuthenticationFilter.setAuthenticationManager( authenticationManager() );
		// super(new AntPathRequestMatcher("/login", "POST"));->
		usernamePasswordAuthenticationFilter.setUsernameParameter("email");
		usernamePasswordAuthenticationFilter.setPasswordParameter("password");
		usernamePasswordAuthenticationFilter.setFilterProcessesUrl("/user/auth");
		usernamePasswordAuthenticationFilter.setAllowSessionCreation( true );
		usernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
		usernamePasswordAuthenticationFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/user/login?result=fail"));

		usernamePasswordAuthenticationFilter.afterPropertiesSet();

		return usernamePasswordAuthenticationFilter;

	}	
	
	@Bean
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
	    return new CustomUrlAuthenticationSuccessHandler();
	}	
	
	/* 4. anonymousProcessingFilter 로그인 하지 않은 사용자들을 감시. isAuthenticated 처리를 위해서 반드시 해야 한다. */
	@Bean
	public AnonymousAuthenticationFilter anonymousProcessingFilter(){
		return new AnonymousAuthenticationFilter( "ABC937s60d629s74" );
	}
	
	/* 5. exceptionTranslationFilter 인증 또는 권한 이 없는 접근은  Exception을 발생시킨다. */	
	@Bean
	public ExceptionTranslationFilter exceptionTranslationFilter() {
		ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter( new LoginUrlAuthenticationEntryPoint("/user/login"));
		
		AccessDeniedHandlerImpl accessDeniedHandlerImpl = new AccessDeniedHandlerImpl();
		accessDeniedHandlerImpl.setErrorPage("/error/403");
		exceptionTranslationFilter.setAccessDeniedHandler( accessDeniedHandlerImpl );
		exceptionTranslationFilter.afterPropertiesSet();
		
		return exceptionTranslationFilter;
	}
	
	
	/* 6. 인터셉터 URL에 접근 제어 (Basic ACL) */
	@Bean
	public FilterSecurityInterceptor filterSecurityInterceptor() throws Exception {
		FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
		
		filterSecurityInterceptor.setAuthenticationManager( authenticationManager() );
		filterSecurityInterceptor.setAccessDecisionManager( accessDecisionManager() );
		// filterSecurityInterceptor.setRunAsManager( runAsManager() );
		
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();

		requestMap.put(new AntPathRequestMatcher("/user/update"), SecurityConfig.createList("isAuthenticated()"));
		requestMap.put(new AntPathRequestMatcher("/user/logout"), SecurityConfig.createList("isAuthenticated()"));
		requestMap.put(new AntPathRequestMatcher("/admin**"), SecurityConfig.createList("hasRole('ADMIN')"));

		FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource = 
				new ExpressionBasedFilterInvocationSecurityMetadataSource( requestMap, new DefaultWebSecurityExpressionHandler());
		
		filterSecurityInterceptor.setSecurityMetadataSource( filterInvocationSecurityMetadataSource );
		filterSecurityInterceptor.afterPropertiesSet();

		return filterSecurityInterceptor;
	}
	
	@Bean
	public AuthenticationManager authenticationManager() {
		AuthenticationManager authenticationManager = new ProviderManager( Arrays.asList(authenticationProvider() ));
		return authenticationManager;
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	}
	
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
	    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
	    authProvider.setUserDetailsService(userDetailsService);
	    authProvider.setPasswordEncoder(passwordEncoder());
	    
	    return authProvider;
	}
	
	public AffirmativeBased accessDecisionManager() throws Exception {
		RoleVoter roleVoter = new RoleVoter();
		roleVoter.setRolePrefix("ROLE_");

		AffirmativeBased affirmativeBased = new AffirmativeBased( Arrays.asList(roleVoter, new WebExpressionVoter(), new AuthenticatedVoter() ));
		affirmativeBased.setAllowIfAllAbstainDecisions( false );
		affirmativeBased.afterPropertiesSet();

		return affirmativeBased;
	}	
	
}
