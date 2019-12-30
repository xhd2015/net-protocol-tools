package com.fulton_shaw.net.tls_https.annotations

import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy


@Retention(RetentionPolicy.RUNTIME)
@interface Length {
    int value() default -1;
}
