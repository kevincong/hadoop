/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.fs.s3a.auth.delegation;

import java.io.IOException;
import java.net.URI;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.AWSCredentialProviderList;
import org.apache.hadoop.fs.s3a.auth.RoleModel;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.service.ServiceOperations;

import static org.apache.hadoop.fs.s3a.auth.delegation.DelegationConstants.DEFAULT_DELEGATION_TOKEN_BINDING;
import static org.apache.hadoop.fs.s3a.auth.delegation.DelegationConstants.DELEGATION_TOKEN_BINDING;

/**
 * Support for creating a DT from a filesystem.
 *
 * Isolated from S3A for control and testability.
 *
 * The S3A Delegation Tokens are special in that the tokens are not directly
 * used to authenticate with the AWS services.
 * Instead they can session/role  credentials requested off AWS on demand.
 *
 * The design is extensible in that different back-end bindings can be used
 * to switch to different session creation mechanisms, or indeed, to any
 * other authentication mechanism supported by an S3 service, provided it
 * ultimately accepts some form of AWS credentials for authentication through
 * the AWS SDK. That is, if someone wants to wire this up to Kerberos, or
 * OAuth2, this design should support them.
 *
 * URIs processed must be the canonical URIs for the service.
 */
@InterfaceAudience.Private
public class S3ADelegationTokens {

    private static final Logger LOG = LoggerFactory.getLogger(
            S3ADelegationTokens.class);

    /**
     * Text value of this token service.
     */
    private Text service;


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
