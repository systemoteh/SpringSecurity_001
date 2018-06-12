*************************************************************************************************************
*   Overview
*                              
*   In this tutorial, we show you how to create authorization check users Web Application using tehnilogies:
*   Spring (MVC, Security, JPA), Hibernate, MySQL, Maven, HTML/CSS/JS (Bootstrap), Tomcat 7, IntelliJ IDEA CE
*************************************************************************************************************
=============================================================================================================
    Database and Tables
=============================================================================================================

--- Create Schema and Tables from script:
-------------------------------------------------------------------------------------------------------------
-- Schema spring_security_001
CREATE SCHEMA `spring_security_001` ;

-- Table: users
CREATE TABLE spring_security_001.users (
  id       INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL
)
  ENGINE = InnoDB;

-- Table: roles
CREATE TABLE spring_security_001.roles (
  id   INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL
)
  ENGINE = InnoDB;

-- Table for mapping user and roles: user_roles
CREATE TABLE spring_security_001.user_roles (
  user_id INT NOT NULL,
  role_id INT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users (id),
  FOREIGN KEY (role_id) REFERENCES roles (id),
  UNIQUE (user_id, role_id)
)
  ENGINE = InnoDB;

-- Insert data
-- login: admin     password: admin
-- login: user      password: user  
INSERT INTO spring_security_001.users VALUES (1, 'admin', '$2a$04$cMJ4Hhur5MQuyn41MbNRLOuYyhtq5VUucAf8uw0g.CXbjb.jtWWR2');
INSERT INTO spring_security_001.users VALUES (2, 'user', '$2a$04$TA3vJwtPAcBzSXBVUFIRou9qymYuKd.qF97Ia8dc1tzRpTss9roTG');
INSERT INTO spring_security_001.roles VALUES (1, 'ROLE_ADMIN');
INSERT INTO spring_security_001.roles VALUES (2, 'ROLE_USER');
INSERT INTO spring_security_001.user_roles VALUES (1, 1);
INSERT INTO spring_security_001.user_roles VALUES (2, 2);
-------------------------------------------------------------------------------------------------------------

=============================================================================================================
    Maven Project
=============================================================================================================

--- Create new Maven project from archetype - maven-archetype-webapp :
-------------------------------------------------------------------------------------------------------------
    groupId - ru.systemoteh
    artifactId - SpringSecurity_001
    version - 1.0
-------------------------------------------------------------------------------------------------------------

--- In IDEA Toolbar -> Edit Configarations (near Build Project) -> Add new configuration -> Maven :
-------------------------------------------------------------------------------------------------------------
    Name - Tomcat 7
    Command line - tomcat7:run

Before launch -> Add new -> Run Maven Goal:

    Commanf line - clean
-------------------------------------------------------------------------------------------------------------

--- Create new Directory java in srs/main .  Mark Directory as Sources Root

--- Create package ru.systemoteh.springsecurity_001 in src/main/java

--- Create a temp file temporary.txt to correctly create nested packages in src/main/java/ru.systemoteh.springsecurity_001 

--- Create new Directory resources in srs/main .  Mark Directory as Resources Root 

=============================================================================================================
    Maven Dependencies
=============================================================================================================

--- Edit pom.xml :
-------------------------------------------------------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>

<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>ru.systemoteh</groupId>
    <artifactId>SpringSecurity_001</artifactId>
    <version>1.0</version>
    <packaging>war</packaging>

    <name>SpringSecurity_001</name>
    <url>http://www.systemoteh.ru</url>

    <properties>
        <spring.version>4.2.0.RELEASE</spring.version>
        <spring-security.version>4.0.2.RELEASE</spring-security.version>
        <spring-data-jpa.version>1.8.2.RELEASE</spring-data-jpa.version>
        <hibernate.version>4.3.11.Final</hibernate.version>
        <hibernate-validator.version>5.2.1.Final</hibernate-validator.version>
        <mysql-connector.version>5.1.36</mysql-connector.version>
        <commons-dbcp.version>1.4</commons-dbcp.version>
        <jstl.version>1.2</jstl.version>
        <junit.version>3.8.1</junit.version>
        <logback.version>1.1.3</logback.version>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>

    <dependencies>

        <!-- Spring -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-web</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-web</artifactId>
            <version>${spring-security.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-config</artifactId>
            <version>${spring-security.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.data</groupId>
            <artifactId>spring-data-jpa</artifactId>
            <version>${spring-data-jpa.version}</version>
        </dependency>

        <!-- Hibernate -->
        <dependency>
            <groupId>org.hibernate</groupId>
            <artifactId>hibernate-validator</artifactId>
            <version>${hibernate-validator.version}</version>
        </dependency>
        <dependency>
            <groupId>org.hibernate</groupId>
            <artifactId>hibernate-entitymanager</artifactId>
            <version>${hibernate.version}</version>
        </dependency>

        <!-- MySQL -->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>${mysql-connector.version}</version>
        </dependency>

        <!-- DataSource -->
        <dependency>
            <groupId>commons-dbcp</groupId>
            <artifactId>commons-dbcp</artifactId>
            <version>${commons-dbcp.version}</version>
        </dependency>

        <!-- Servlets -->
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>jstl</artifactId>
            <version>${jstl.version}</version>
        </dependency>

        <!-- Test -->
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>${junit.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>ch.qos.logback</groupId>
            <artifactId>logback-classic</artifactId>
            <version>${logback.version}</version>
        </dependency>

    </dependencies>

    <build>
        <finalName>SpringSecurity_001</finalName>
        <pluginManagement>
            <plugins>

                <!-- Tomcat 7 -->
                <plugin>
                    <groupId>org.apache.tomcat.maven</groupId>
                    <artifactId>tomcat7-maven-plugin</artifactId>
                    <version>2.2</version>
                    <configuration>
                        <port>8888</port>
                        <path>/</path>
                    </configuration>
                </plugin>

                <!-- Maven -->
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-compiler-plugin</artifactId>
                    <version>3.1</version>
                    <configuration>
                        <source>1.8</source>
                        <target>1.8</target>
                        <encoding>UTF-8</encoding>
                    </configuration>
                </plugin>

            </plugins>
        </pluginManagement>
    </build>
</project>
-------------------------------------------------------------------------------------------------------------

--- Edit web.xml in src/main/webapp/WEB-INF/ :
-------------------------------------------------------------------------------------------------------------
<!DOCTYPE web-app PUBLIC
        "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
        "http://java.sun.com/dtd/web-app_2_3.dtd" >

<web-app>
    <display-name>SpringSecurity_001</display-name>

    <context-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>/WEB-INF/appconfig-root.xml</param-value>
    </context-param>

    <filter>
        <filter-name>springSecurityFilterChain</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    </filter>

    <filter-mapping>
        <filter-name>springSecurityFilterChain</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

    <listener>
        <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
    </listener>

    <servlet>
        <servlet-name>dispatcher</servlet-name>
        <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
        <init-param>
            <param-name>contextConfigLocation</param-name>
            <param-value></param-value>
        </init-param>
        <load-on-startup>1</load-on-startup>
    </servlet>

    <servlet-mapping>
        <servlet-name>dispatcher</servlet-name>
        <url-pattern>/</url-pattern>
    </servlet-mapping>

</web-app>
-------------------------------------------------------------------------------------------------------------

=============================================================================================================
    Configure WebApp 
=============================================================================================================

--- Add and edit appconfig-root.xml in src/main/webapp/WEB-INF/ :
-------------------------------------------------------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:context="http://www.springframework.org/schema/context"
       xmlns="http://www.springframework.org/schema/beans"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd

		http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd">

    <import resource="appconfig-mvc.xml"/>

    <import resource="appconfig-data.xml"/>

    <import resource="appconfig-security.xml"/>

    <context:component-scan base-package="ru.systemoteh.springsecurity_001.*"/>

    <context:property-placeholder location="classpath:database.properties"/>

</beans>
-------------------------------------------------------------------------------------------------------------

--- Add and edit appconfig-mvc.xml in src/main/webapp/WEB-INF/ :
-------------------------------------------------------------------------------------------------------------
<beans xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:mvc="http://www.springframework.org/schema/mvc"
       xmlns="http://www.springframework.org/schema/beans"
       xsi:schemaLocation="http://www.springframework.org/schema/mvc http://www.springframework.org/schema/mvc/spring-mvc.xsd http://www.springframework.org/schema/beans
 http://www.springframework.org/schema/beans/spring-beans.xsd">

    <mvc:annotation-driven/>

    <mvc:resources mapping="/resources/**" location="/resources/"/>

    <bean id="messageSource" class="org.springframework.context.support.ReloadableResourceBundleMessageSource">
        <property name="basenames">
            <list>
                <value>classpath:validation</value>
            </list>
        </property>
    </bean>

    <bean class="org.springframework.web.servlet.view.InternalResourceViewResolver">
        <property name="prefix">
            <value>/WEB-INF/views/</value>
        </property>
        <property name="suffix">
            <value>.jsp</value>
        </property>
    </bean>

</beans>
-------------------------------------------------------------------------------------------------------------

--- Add and edit appconfig-data.xml in src/main/webapp/WEB-INF/ :
-------------------------------------------------------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:jpa="http://www.springframework.org/schema/data/jpa"
       xmlns:tx="http://www.springframework.org/schema/tx"
       xmlns="http://www.springframework.org/schema/beans"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
    http://www.springframework.org/schema/beans/spring-beans.xsd
    http://www.springframework.org/schema/data/jpa
    http://www.springframework.org/schema/data/jpa/spring-jpa.xsd
    http://www.springframework.org/schema/tx
    http://www.springframework.org/schema/tx/spring-tx.xsd">

    <bean id="dataSource" class="org.apache.commons.dbcp.BasicDataSource" destroy-method="close">
        <property name="driverClassName" value="${jdbc.driverClassName}"/>
        <property name="url" value="${jdbc.url}"/>
        <property name="username" value="${jdbc.username}"/>
        <property name="password" value="${jdbc.password}"/>
    </bean>

    <bean id="entityManagerFactory" class="org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean">
        <property name="dataSource" ref="dataSource"/>
        <property name="packagesToScan" value="ru.systemoteh.springsecurity_001.model"/>
        <property name="jpaVendorAdapter">
            <bean class="org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter"/>
        </property>
        <property name="jpaProperties">
            <props>
                <prop key="hibernate.dialect">org.hibernate.dialect.MySQL5Dialect</prop>
                <prop key="hibernate.show_sql">true</prop>
            </props>
        </property>
    </bean>

    <bean id="transactionManager"
          class="org.springframework.orm.jpa.JpaTransactionManager">
        <property name="entityManagerFactory" ref="entityManagerFactory"/>
    </bean>

    <tx:annotation-driven/>

    <jpa:repositories base-package="ru.systemoteh.springsecurity_001.dao"/>
</beans>
-------------------------------------------------------------------------------------------------------------

--- Add and edit appconfig-security.xml in src/main/webapp/WEB-INF/ :
-------------------------------------------------------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<beans:beans xmlns="http://www.springframework.org/schema/security"
             xmlns:beans="http://www.springframework.org/schema/beans"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://www.springframework.org/schema/beans
		http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
		http://www.springframework.org/schema/security
		http://www.springframework.org/schema/security/spring-security.xsd">

    <http auto-config="true">
        <intercept-url pattern="/" access="hasAnyRole('ROLE_USER', 'ROLE_ADMIN')"/>
        <intercept-url pattern="/welcome" access="hasAnyRole('ROLE_USER', 'ROLE_ADMIN')"/>
        <intercept-url pattern="/admin" access="hasRole('ROLE_ADMIN')"/>

        <form-login login-page="/login" default-target-url="/welcome" authentication-failure-url="/login?error"
                    username-parameter="username" password-parameter="password"/>

        <logout logout-success-url="/login?logout"/>
    </http>

    <authentication-manager alias="authenticationManager">
        <authentication-provider user-service-ref="userDetailsServiceImpl">
            <password-encoder ref="encoder"></password-encoder>
        </authentication-provider>
    </authentication-manager>

    <beans:bean id="userDetailsServiceImpl"
                class="ru.systemoteh.springsecurity_001.service.UserDetailsServiceImpl"></beans:bean>

    <beans:bean id="encoder"
                class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder">
        <beans:constructor-arg name="strength" value="11"/>
    </beans:bean>
</beans:beans>
-------------------------------------------------------------------------------------------------------------

--- Create and edit database.properties in srs/main/resources :
-------------------------------------------------------------------------------------------------------------
jdbc.driverClassName=com.mysql.jdbc.Driver
jdbc.url=jdbc:mysql://localhost:3306/spring_security_001
jdbc.username=root
jdbc.password=password
-------------------------------------------------------------------------------------------------------------

--- Create and edit validation.properties in srs/main/resources :
-------------------------------------------------------------------------------------------------------------
Required=This field is required.
Size.userForm.username=Username must be between 8 and 32 characters.
Duplicate.userForm.username=Such username already exists.
Size.userForm.password=Password must be over 8 characters.
Different.userForm.password=Password don't match.
-------------------------------------------------------------------------------------------------------------

--- Create and edit logback.xml in srs/main/resources :
-------------------------------------------------------------------------------------------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE logback>
<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%date{HH:mm:ss.SSS} [%thread] %-5level %logger{15}#%line %msg\n</pattern>
        </encoder>
    </appender>

    <logger name="ru.systemoteh.springsecurity_001">
        <level value="debug"/>
    </logger>

    <logger name="org.springframework">
        <level value="info"/>
    </logger>

    <root>
        <level value="error"/>
        <appender-ref ref="STDOUT"/>
    </root>
</configuration>
-------------------------------------------------------------------------------------------------------------

=============================================================================================================
    Creating Model Layer
=============================================================================================================

--- Create package model in ru.systemoteh.springsecurity_001

--- Create User class in model package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.model;

import javax.persistence.*;
import java.util.Set;

/**
 * Simple JavaBean domain object that represents a User.
 */

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Transient
    private String confirmPassword;

    @ManyToMany
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles;


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
-------------------------------------------------------------------------------------------------------------

--- Create Role class in model package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.model;

import javax.persistence.*;
import java.util.Set;

/**
 * Simple JavaBean object that represents role of {@link User}.
 */

@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(name = "name")
    private String name;

    @ManyToMany(mappedBy = "roles")
    private Set<User> users;

    public Role() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    @Override
    public String toString() {
        return "Role{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", users=" + users +
                '}';
    }
}
-------------------------------------------------------------------------------------------------------------

=============================================================================================================
    Creating DAO Layer
=============================================================================================================

--- Create package dao in ru.systemoteh.springsecurity_001

--- Create UserDao interface in dao package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.systemoteh.springsecurity_001.model.User;

public interface UserDao extends JpaRepository<User, Long> {

    User findByUsername(String username);

}
-------------------------------------------------------------------------------------------------------------

--- Create RoleDao interface in dao package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.systemoteh.springsecurity_001.model.Role;

public interface RoleDao extends JpaRepository<Role, Long> {
    
}
-------------------------------------------------------------------------------------------------------------

=============================================================================================================
    Creating Service Layer
=============================================================================================================

--- Create package service in ru.systemoteh.springsecurity_001

--- Create UserService interface in service package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.service;

import ru.systemoteh.springsecurity_001.model.User;

/**
 * Service class for {@link ru.systemoteh.springsecurity_001.model.User}
 */

public interface UserService {

    void save(User user);

    User findByUsername(String username);

}
-------------------------------------------------------------------------------------------------------------

--- Create UserServiceImpl class in service package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import ru.systemoteh.springsecurity_001.dao.RoleDao;
import ru.systemoteh.springsecurity_001.dao.UserDao;
import ru.systemoteh.springsecurity_001.model.Role;
import ru.systemoteh.springsecurity_001.model.User;

import java.util.HashSet;
import java.util.Set;

/**
 * Implementation of {@link UserService} interface.
 */

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private RoleDao roleDao;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public void save(User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        Set<Role> roles = new HashSet<>();
        roles.add(roleDao.getOne(2L));
        user.setRoles(roles);
        userDao.save(user);
    }

    @Override
    public User findByUsername(String username) {
        return userDao.findByUsername(username);
    }
}
-------------------------------------------------------------------------------------------------------------

--- Create UserDetailsServiceImpl class in service package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.annotation.Transactional;
import ru.systemoteh.springsecurity_001.dao.UserDao;
import ru.systemoteh.springsecurity_001.model.Role;
import ru.systemoteh.springsecurity_001.model.User;

import java.util.HashSet;
import java.util.Set;

/**
 * Implementation of {@link org.springframework.security.core.userdetails.UserDetailsService} interface.
 */

public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserDao userDao;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userDao.findByUsername(username);

        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();

        for (Role role : user.getRoles()) {
            grantedAuthorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), grantedAuthorities);
    }
}
-------------------------------------------------------------------------------------------------------------

--- Create SecurityService interface in service package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.service;

/**
 * Service for Security.
 */

public interface SecurityService {

    String findLoggedInUsername();

    void autoLogin(String username, String password);
}
-------------------------------------------------------------------------------------------------------------

--- Create SecurityServiceImpl class in service package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

/**
 * Implementation of {@link SecurityService} interface.
 */

@Service
public class SecurityServiceImpl implements SecurityService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityServiceImpl.class);

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public String findLoggedInUsername() {
        Object userDetails = SecurityContextHolder.getContext().getAuthentication().getDetails();
        if (userDetails instanceof UserDetails) {
            return ((UserDetails) userDetails).getUsername();
        }

        return null;
    }

    @Override
    public void autoLogin(String username, String password) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());

        authenticationManager.authenticate(authenticationToken);

        if (authenticationToken.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            LOGGER.debug(String.format("Successfully %s auto logged in", username));
        }
    }
}
-------------------------------------------------------------------------------------------------------------

--- Create package validator in ru.systemoteh.springsecurity_001

--- Create UserValidator class in validator package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.validator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;
import ru.systemoteh.springsecurity_001.model.User;
import ru.systemoteh.springsecurity_001.service.UserService;

/**
 * Validator for {@link ru.systemoteh.springsecurity_001.model.User} class,
 * implements {@link Validator} interface.
 */

@Component
public class UserValidator implements Validator {

    @Autowired
    private UserService userService;

    @Override
    public boolean supports(Class<?> aClass) {
        return User.class.equals(aClass);
    }

    @Override
    public void validate(Object o, Errors errors) {
        User user = (User) o;

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "username", "Required");
        if (user.getUsername().length() < 8 || user.getUsername().length() > 32) {
            errors.rejectValue("username", "Size.userForm.username");
        }

        if (userService.findByUsername(user.getUsername()) != null) {
            errors.rejectValue("username", "Duplicate.userForm.username");
        }

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "password", "Required");
        if (user.getPassword().length() < 8 || user.getPassword().length() > 32) {
            errors.rejectValue("password", "Size.userForm.password");
        }

        if (!user.getConfirmPassword().equals(user.getPassword())) {
            errors.rejectValue("confirmPassword", "Different.userForm.password");
        }
    }
}
-------------------------------------------------------------------------------------------------------------

=============================================================================================================
    Creating Controller Layer 
=============================================================================================================

--- Create package controller in ru.systemoteh.springsecurity_001

--- Create UserController class in controller package:
-------------------------------------------------------------------------------------------------------------
package ru.systemoteh.springsecurity_001.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import ru.systemoteh.springsecurity_001.model.User;
import ru.systemoteh.springsecurity_001.service.SecurityService;
import ru.systemoteh.springsecurity_001.service.UserService;
import ru.systemoteh.springsecurity_001.validator.UserValidator;

/**
 * Controller for {@link ru.systemoteh.springsecurity_001.model.User}'s pages.
 */

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private SecurityService securityService;

    @Autowired
    private UserValidator userValidator;

    @RequestMapping(value = "/registration", method = RequestMethod.GET)
    public String registration(Model model) {
        model.addAttribute("userForm", new User());

        return "registration";
    }

    @RequestMapping(value = "/registration", method = RequestMethod.POST)
    public String registration(@ModelAttribute("userForm") User userForm, BindingResult bindingResult, Model model) {
        userValidator.validate(userForm, bindingResult);

        if (bindingResult.hasErrors()) {
            return "registration";
        }

        userService.save(userForm);

        securityService.autoLogin(userForm.getUsername(), userForm.getConfirmPassword());

        return "redirect:/welcome";
    }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(Model model, String error, String logout) {
        if (error != null) {
            model.addAttribute("error", "Username or password is incorrect.");
        }

        if (logout != null) {
            model.addAttribute("message", "Logged out successfully.");
        }

        return "login";
    }

    @RequestMapping(value = {"/", "/welcome"}, method = RequestMethod.GET)
    public String welcome(Model model) {
        return "welcome";
    }

    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public String admin(Model model) {
        return "admin";
    }
}
-------------------------------------------------------------------------------------------------------------

=============================================================================================================
    Creating JSP Views
=============================================================================================================

--- Download Bootstrap

--- Create Directory resources in /src/main/webapp

--- Create Directoryes css and js in /src/main/webapp/resources

--- Put downloaded Bootstrap file bootstrap.min.css in /src/main/webapp/resources/css

--- Create common.css in /src/main/webapp/resources/css :
-------------------------------------------------------------------------------------------------------------
body {
    padding-top: 40px;
    padding-bottom: 40px;
    background-color: #eee;
}

.form-signin {
    max-width: 330px;
    padding: 15px;
    margin: 0 auto;
}

.form-signin .form-signin-heading,
.form-signin .checkbox {
    margin-bottom: 10px;
}

.form-signin .checkbox {
    font-weight: normal;
}

.form-signin .form-control {
    position: relative;
    height: auto;
    -webkit-box-sizing: border-box;
    -moz-box-sizing: border-box;
    box-sizing: border-box;
    padding: 10px;
    font-size: 16px;
}

.form-signin .form-control:focus {
    z-index: 2;
}

.form-signin input {
    margin-top: 10px;
    border-bottom-right-radius: 0;
    border-bottom-left-radius: 0;
}

.form-signin button {
    margin-top: 10px;
}

.has-error {
    color: red
}
-------------------------------------------------------------------------------------------------------------

--- Put downloaded Bootstrap file bootstrap.min.js in /src/main/webapp/resources/js

--- Create Directory views in /src/main/webapp/WEB-INF

--- Create admin.jsp in /src/main/webapp/WEB-INF/views
-------------------------------------------------------------------------------------------------------------
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page isELIgnored ="false" %>

<c:set var="contextPath" value="${pageContext.request.contextPath}"/>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Admin</title>

    <link href="${contextPath}/resources/css/bootstrap.min.css" rel="stylesheet">
</head>

<body>
<div class="container">
    <c:if test="${pageContext.request.userPrincipal.name != null}">
        <form id="logoutForm" method="post" action="${contextPath}/logout">
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
        </form>
        <h2>Admin Page ${pageContext.request.userPrincipal.name} | <a onclick="document.forms['logoutForm'].submit()">Logout</a>
        </h2>
    </c:if>
</div>

<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
<script src="${contextPath}/resources/js/bootstrap.min.js"></script>

</body>
</html>
-------------------------------------------------------------------------------------------------------------

--- Create login.jsp in /src/main/webapp/WEB-INF/views
-------------------------------------------------------------------------------------------------------------
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ page isELIgnored ="false" %>

<c:set var="contextPath" value="${pageContext.request.contextPath}"/>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Log in with your account</title>

    <link href="${contextPath}/resources/css/bootstrap.min.css" rel="stylesheet">
    <link href="${contextPath}/resources/css/common.css" rel="stylesheet">

    <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
    <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>

</head>

<body>

<div class="container">

    <form method="POST" action="${contextPath}/login" class="form-signin">
        <h2 class="form-heading">Log in</h2>

        <div class="form-group ${error != null ? 'has-error' : ''}">
            <span>${message}</span>
            <input name="username" type="text" class="form-control" placeholder="Username"
                   autofocus="true"/>
            <input name="password" type="password" class="form-control" placeholder="Password"/>
            <span>${error}</span>
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>

            <button class="btn btn-lg btn-primary btn-block" type="submit">Log In</button>
            <h4 class="text-center"><a href="${contextPath}/registration">Create an account</a></h4>
        </div>

    </form>

</div>
<!-- /container -->
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
<script src="${contextPath}/resources/js/bootstrap.min.js"></script>
</body>
</html>
-------------------------------------------------------------------------------------------------------------

--- Create registration.jsp in /src/main/webapp/WEB-INF/views
-------------------------------------------------------------------------------------------------------------
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ page isELIgnored ="false" %>

<c:set var="contextPath" value="${pageContext.request.contextPath}"/>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Create an account</title>

    <link href="${contextPath}/resources/css/bootstrap.min.css" rel="stylesheet">
    <link href="${contextPath}/resources/css/common.css" rel="stylesheet">


    <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
    <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>

</head>

<body>

<div class="container">

    <form:form method="POST" modelAttribute="userForm" class="form-signin">
        <h2 class="form-signin-heading">Create your account</h2>
        <spring:bind path="username">
            <div class="form-group ${status.error ? 'has-error' : ''}">
                <form:input type="text" path="username" class="form-control" placeholder="Username"
                            autofocus="true"></form:input>
                <form:errors path="username"></form:errors>
            </div>
        </spring:bind>

        <spring:bind path="password">
            <div class="form-group ${status.error ? 'has-error' : ''}">
                <form:input type="password" path="password" class="form-control" placeholder="Password"></form:input>
                <form:errors path="password"></form:errors>
            </div>
        </spring:bind>

        <spring:bind path="confirmPassword">
            <div class="form-group ${status.error ? 'has-error' : ''}">
                <form:input type="password" path="confirmPassword" class="form-control"
                            placeholder="Confirm your password"></form:input>
                <form:errors path="confirmPassword"></form:errors>
            </div>
        </spring:bind>

        <button class="btn btn-lg btn-primary btn-block" type="submit">Submit</button>
    </form:form>

</div>
<!-- /container -->
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
<script src="${contextPath}/resources/js/bootstrap.min.js"></script>
</body>
</html>
-------------------------------------------------------------------------------------------------------------

--- Create welcome.jsp in /src/main/webapp/WEB-INF/views
-------------------------------------------------------------------------------------------------------------
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page isELIgnored ="false" %>

<c:set var="contextPath" value="${pageContext.request.contextPath}"/>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Welcome</title>

    <link href="${contextPath}/resources/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>

<div class="container">

    <c:if test="${pageContext.request.userPrincipal.name != null}">
        <form id="logoutForm" method="POST" action="${contextPath}/logout">
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
        </form>

        <h2>Welcome ${pageContext.request.userPrincipal.name} | <a onclick="document.forms['logoutForm'].submit()">Logout</a>
        </h2>

    </c:if>

</div>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
<script src="${contextPath}/resources/js/bootstrap.min.js"></script>
</body>
</html>
-------------------------------------------------------------------------------------------------------------

--- Edit index.jsp in /src/main/webapp :
-------------------------------------------------------------------------------------------------------------
<%@ page pageEncoding="UTF-8" contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<c:redirect url="/login"/>
-------------------------------------------------------------------------------------------------------------

--- Delete temporary.txt in src/main/java/ru.systemoteh.springsecurity_001

--- Start Web Application

--- Enter in browser http://localhost:8888/

*************************************************************************************************************

    So if we enter login: admin and password: admin, and click Log In, we will be on the Welcome page. Change the address in the browser address bar to http://localhost:8888/admin , we are now on the Admin page. Press Logout. Now enter login: user and password: user, and click Log in. Change the address in the browser address bar to http://localhost:8888/admin . Access to a user with the user role is denied.
    If you create a new user on the page http://localhost:8888/registration , then this user will also be denied access to the Admin page

*************************************************************************************************************

    Итак если мы вводим логин: admin и пароль: админ, и нажимаем Log In, то окажемся на странице Welcome. Изменим адрес в адресной строке браузера на http://localhost:8888/admin , теперь мы на странице Admin. Нажимаем Logout. Теперь вводим логин: user и пароль: user, и нажимаем Log In. Изменим адрес в адресной строке браузера на http://localhost:8888/admin . Доступ пользователю с ролью user запрещен.
Если создать нового пользователя на странице http://localhost:8888/registration , то этому пользователю тоже будет запрещен доступ к странице Admin




 
