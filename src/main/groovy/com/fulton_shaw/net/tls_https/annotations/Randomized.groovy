package com.fulton_shaw.net.tls_https.annotations

import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy

/**
 * indicate a key is generated ran
 */
@Retention(RetentionPolicy.RUNTIME)
@interface Randomized {
    /**
     * lower bound, inclusive
     * @return
     */
    long lower() default Long.MIN_VALUE;
    /**
     * upper bound,exclusive
     * @return
     */
    long upper() default Long.MAX_VALUE;
}