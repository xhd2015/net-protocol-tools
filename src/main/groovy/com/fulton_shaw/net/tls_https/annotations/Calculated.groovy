package com.fulton_shaw.net.tls_https.annotations

import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy

@Retention(RetentionPolicy.RUNTIME)
@interface Calculated {
    public static final int REMAINING = -1
    public static final int NEXT = 1
    /**
     * -1 = REMAINING value after this
     * N (N>0) =  1 value after this
     *
     * @return
     */
    int value() default NEXT;
}