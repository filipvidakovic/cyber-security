package org.cybersecurity.config.database;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.apache.commons.dbcp2.BasicDataSource;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;

import javax.sql.DataSource;

@Configuration
@EnableJpaRepositories(basePackages = "org.cybersecurity.repositories")
public class DatabaseConfig {
    @Value("${db.url}")
    private String dbUrl;

    @Value("${db.username}")
    private String dbUsername;

    @Value("${db.password}")
    private String dbPassword;

    @Value("${db.driver-class-name}")
    private String dbDriver;

    @Value("${jpa.dialect}")
    private String hibernateDialect;

    @Value("${jpa.show-sql}")
    private boolean showSql;

    @Value("${jpa.ddl-auto}")
    private String ddlAuto;

    @Bean
    public DataSource dataSource() {
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setUrl(dbUrl);
        dataSource.setUsername(dbUsername);
        dataSource.setPassword(dbPassword);
        dataSource.setDriverClassName(dbDriver);
        return dataSource;
    }

    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory(DataSource dataSource) {
        LocalContainerEntityManagerFactoryBean factoryBean = new LocalContainerEntityManagerFactoryBean();
        factoryBean.setDataSource(dataSource);
        factoryBean.setPackagesToScan("org.cybersecurity.model");
        factoryBean.setJpaVendorAdapter(new HibernateJpaVendorAdapter());

        // Hibernate properties
        factoryBean.getJpaPropertyMap().put("hibernate.dialect", hibernateDialect);
        factoryBean.getJpaPropertyMap().put("hibernate.show_sql", showSql);
        factoryBean.getJpaPropertyMap().put("hibernate.hbm2ddl.auto", ddlAuto);

        return factoryBean;
    }

    // Transaction Manager Bean
    @Bean
    public JpaTransactionManager transactionManager(LocalContainerEntityManagerFactoryBean entityManagerFactory) {
        return new JpaTransactionManager(entityManagerFactory.getObject());
    }
}

