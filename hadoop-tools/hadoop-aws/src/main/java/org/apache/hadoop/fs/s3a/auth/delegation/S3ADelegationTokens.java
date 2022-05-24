package org.apache.hadoop.fs.s3a.auth.delegation;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;

import static org.apache.hadoop.fs.s3a.auth.delegation.DelegationConstants.DEFAULT_DELEGATION_TOKEN_BINDING;
import static org.apache.hadoop.fs.s3a.auth.delegation.DelegationConstants.DELEGATION_TOKEN_BINDING;

public class S3ADelegationTokens {
    /**
     * Predicate: does this configuration enable delegation tokens?
     * That is: is there any text in the option
     * {@link DelegationConstants#DELEGATION_TOKEN_BINDING} ?
     * @param conf configuration to examine
     * @return true iff the trimmed configuration option is not empty.
     */
    public static boolean hasDelegationTokenBinding(Configuration conf) {
        return StringUtils.isNotEmpty(
                conf.getTrimmed(DELEGATION_TOKEN_BINDING,
                        DEFAULT_DELEGATION_TOKEN_BINDING));
    }
}
