package org.cloudfoundry.identity.uaa.audit.predix.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * Created by 212408019 on 1/25/17.
 */
public class LogEachBean /*implements BeanPostProcessor */{

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("<><><><><><><><><><><><><BeforeInitialization<><><><><><><><><><><>< : " + beanName);
        return bean;  // you can return any other object as well
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        System.out.println("<><><><><><><><><><><><AfterInitialization<><><><><><><><><>><><><><> : " + beanName);
        return bean;  // you can return any other object as well
    }
}
