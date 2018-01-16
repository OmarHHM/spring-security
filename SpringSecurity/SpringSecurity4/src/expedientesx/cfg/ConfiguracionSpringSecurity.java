package expedientesx.cfg;
import java.util.Arrays;
import java.util.Properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import expedientesx.util.HorarioVoter;

@Configuration
@EnableWebSecurity
public class ConfiguracionSpringSecurity extends WebSecurityConfigurerAdapter {
	
	@Bean
	public PasswordEncoder passwordEncoder(){
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
	}
	
	@Autowired
	public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService());	
	}
	
	@Bean
	public UnanimousBased accessDecisionManager() throws Exception {
		UnanimousBased unanimousBased = new UnanimousBased(
				Arrays.asList(new AuthenticatedVoter(), 
						  new WebExpressionVoter(), 
						  new RoleVoter(),
						  new HorarioVoter() ) );
		unanimousBased.setAllowIfAllAbstainDecisions(false);
		unanimousBased.afterPropertiesSet();

		return unanimousBased;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		
		http
		.formLogin()
			.loginPage("/paginas/login.jsp")
			.failureUrl("/paginas/login.jsp?login_error");

		http
		.logout()
			.logoutSuccessUrl("/paginas/desconectado.jsp")
			.deleteCookies("JSESSIONID");
		
		http
			.csrf().disable();
		
		http
		.authorizeRequests()
			.antMatchers("/paginas/*").permitAll()
			.antMatchers("/css/*").permitAll()
			.antMatchers("/imagenes/*").permitAll()
			.antMatchers("/**").access("hasRole('AGENTE_ESPECIAL')");
		
		http
			.sessionManagement()
			.invalidSessionUrl("/paginas/sesion-expirada.jsp")
			.maximumSessions(1)
			.maxSessionsPreventsLogin(true);
		http
		.exceptionHandling()
		.accessDeniedPage("/paginas/acceso-denegado.jsp");
		
		http
		.authorizeRequests()
			.accessDecisionManager(accessDecisionManager())
			.antMatchers("/paginas/*").permitAll()
			.antMatchers("/css/*").permitAll()
			.antMatchers("/imagenes/*").permitAll()
			.antMatchers("/**").access("isAuthenticated()");

	}
	
	
	public UserDetailsService userDetailsService(){
		  Properties usuarios = new Properties();
			usuarios.put("Fernando","$2a$10$SMPYtil7Hs2.cV7nrMjrM.dRAkuoLdYM8NdVrF.GeHfs/MrzcQ/zi,ROLE_AGENTE,enabled");
			usuarios.put("Mulder"  ,"$2a$10$M2JRRHUHTfv4uMR4NWmCLebk1r9DyWSwCMZmuq4LKbImOkfhGFAIa,ROLE_AGENTE_ESPECIAL,enabled");
			usuarios.put("Scully"  ,"$2a$10$cbF5xp0grCOGcI6jZvPhA.asgmILATW1hNbM2MEqGJEFnRhhQd3ba,ROLE_AGENTE_ESPECIAL,enabled");
			usuarios.put("Skinner" ,"$2a$10$ZFtPIULMcxPe3r/5VunbVujMD7Lw8hkqAmJlxmK5Y1TK3L1bf8ULG,ROLE_DIRECTOR,enabled");
	        
			return new InMemoryUserDetailsManager(usuarios);
	}
}