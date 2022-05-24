package org.apache.hadoop.fs.s3a.auth.delegation;

public class DelegationConstants {
    /**
     * Property containing classname for token binding: {@value}.
     */
    public static final String DELEGATION_TOKEN_BINDING =
            "fs.s3a.delegation.token.binding";
    /**
     * Default token binding {@value}.
     */
    public static final String DEFAULT_DELEGATION_TOKEN_BINDING = "";
}
