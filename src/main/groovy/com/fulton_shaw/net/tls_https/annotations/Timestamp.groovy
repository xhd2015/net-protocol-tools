package com.fulton_shaw.net.tls_https.annotations

import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy

/**
 * indicate the field is a timestamp
 */
@Retention(RetentionPolicy.RUNTIME)
@interface Timestamp {
    public static final int SECONDS = 0
    public static final int MILLISECONDS = 1
    /**
     * 0 = seconds
     * 1 = milliseconds
     * @return
     */
    int type() default 0;
}