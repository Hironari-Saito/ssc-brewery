package guru.sfg.brewery.config;

import guru.sfg.brewery.security.SfgPasswordEncoderFactories;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    public RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager authenticationManager){
//        RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/api/**"));
//        filter.setAuthenticationManager(authenticationManager);
//        return filter;
//    }
//
//    public RestUrlAuthFilter restUrlAuthFilter(AuthenticationManager authenticationManager) {
//        RestUrlAuthFilter filter = new RestUrlAuthFilter(new AntPathRequestMatcher("/api/**"));
//        filter.setAuthenticationManager(authenticationManager);
//        return filter;
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilterBefore(restHeaderAuthFilter(authenticationManager()),
//                UsernamePasswordAuthenticationFilter.class)
//
//
//        http.addFilterBefore(restUrlAuthFilter(authenticationManager()),
//                UsernamePasswordAuthenticationFilter.class);
        http

            .authorizeRequests(authorize -> {
                authorize
                        .antMatchers("/h2-console/**").permitAll() // do not use in production
                        .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()                 ;
            } )
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin().and()
            .httpBasic()
            .and().csrf().disable();

        //h2 console config
        http.headers().frameOptions().sameOrigin();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//        return new LdapShaPasswordEncoder();
//        return new StandardPasswordEncoder();
//        return new BCryptPasswordEncoder();
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return SfgPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


//    @Autowired
//    JpaUserDetailsService jpaUserDetailsService;

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(this.jpaUserDetailsService).passwordEncoder(passwordEncoder());
//        auth.inMemoryAuthentication()
//                .withUser("spring")
//                .password("{bcrypt}$2a$10$/lcw3MKkzSLGOfh8Fi8uIu9la/S7EIdbcobkCJIvtRAx8wIrl6Qli")
//                .roles("ADMIN")
//                .and()
//                .withUser("user")
//                .password("{sha256}70d25251eef56beb3da0c54d9dbd0415cf9057226120710767c5290121e0b19fc192a47bae3a3942")
//                .roles("USER");
//
//        auth.inMemoryAuthentication()
//                .withUser("scott")
//                .password("{bcrypt10}$2a$10$iPiSEw1VUH8cFjgJ2bw85.LatKYJXTl3PzML7i.1y6NTaIly8LnlC")
//                .roles("CUSTOMER");
//    }

    //    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("spring")
//                .password("guru")
//                .roles("ADMIN")
//                .build();
//
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(admin,user);
//    }
}
