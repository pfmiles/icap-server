package com.github.pfmiles.icapserver;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotates a class which is going to be loaded as a ICAP server module.
 * For more about icap server modules, please refer to wiki page: <a href="https://github.com/pfmiles/icap-server/wiki/ICAP-server-modules-explained">ICAP server modules explained</a>
 *
 * @author pf-miles
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Module {
    /**
     * Endpoint value
     *
     * @return the endpoint of the defining module, must be specified.
     */
    String value() default "";
}
