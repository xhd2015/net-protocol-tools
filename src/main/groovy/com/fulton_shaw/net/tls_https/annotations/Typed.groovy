package com.fulton_shaw.net.tls_https.annotations

import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy


@Retention(RetentionPolicy.RUNTIME)
@interface Typed {
    /**
     * delegate construction to another field
     * the target field class contains mappedType method
     * @return
     */
    String value()
}
