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

package org.apache.hadoop.fs.s3a.impl;

import com.amazonaws.services.s3.model.ObjectMetadata;

import static org.apache.hadoop.fs.s3a.commit.CommitConstants.X_HEADER_MAGIC_MARKER;

/**
 * Part of the S3A FS where object headers are
 * processed.
 * Implements all the various XAttr read operations.
 * Those APIs all expect byte arrays back.
 * Metadata cloning is also implemented here, so as
 * to stay in sync with custom header logic.
 *
 * The standard header names are extracted from the AWS SDK.
 * The S3A connector does not (currently) support setting them,
 * though it would be possible to do so through the createFile()
 * builder API.
 */
public class HeaderProcessing {

    /**
     * Directory content type : {@value}.
     * Matches use/expectations of AWS S3 console.
     */
    public static final String CONTENT_TYPE_X_DIRECTORY =
            "application/x-directory";


    /**
     * Creates a copy of the passed {@link ObjectMetadata}.
     * Does so without using the {@link ObjectMetadata#clone()} method,
     * to avoid copying unnecessary headers.
     * This operation does not copy the {@code X_HEADER_MAGIC_MARKER}
     * header to avoid confusion. If a marker file is renamed,
     * it loses information about any remapped file.
     * If new fields are added to ObjectMetadata which are not
     * present in the user metadata headers, they will not be picked
     * up or cloned unless this operation is updated.
     * @param source the {@link ObjectMetadata} to copy
     * @param dest the metadata to update; this is the return value.
     */
    public static void cloneObjectMetadata(ObjectMetadata source,
                                           ObjectMetadata dest) {

        // Possibly null attributes
        // Allowing nulls to pass breaks it during later use
        if (source.getCacheControl() != null) {
            dest.setCacheControl(source.getCacheControl());
        }
        if (source.getContentDisposition() != null) {
            dest.setContentDisposition(source.getContentDisposition());
        }
        if (source.getContentEncoding() != null) {
            dest.setContentEncoding(source.getContentEncoding());
        }
        if (source.getContentMD5() != null) {
            dest.setContentMD5(source.getContentMD5());
        }
        if (source.getContentType() != null) {
            dest.setContentType(source.getContentType());
        }
        if (source.getExpirationTime() != null) {
            dest.setExpirationTime(source.getExpirationTime());
        }
        if (source.getExpirationTimeRuleId() != null) {
            dest.setExpirationTimeRuleId(source.getExpirationTimeRuleId());
        }
        if (source.getHttpExpiresDate() != null) {
            dest.setHttpExpiresDate(source.getHttpExpiresDate());
        }
        if (source.getLastModified() != null) {
            dest.setLastModified(source.getLastModified());
        }
        if (source.getOngoingRestore() != null) {
            dest.setOngoingRestore(source.getOngoingRestore());
        }
        if (source.getRestoreExpirationTime() != null) {
            dest.setRestoreExpirationTime(source.getRestoreExpirationTime());
        }
        if (source.getSSEAlgorithm() != null) {
            dest.setSSEAlgorithm(source.getSSEAlgorithm());
        }
        if (source.getSSECustomerAlgorithm() != null) {
            dest.setSSECustomerAlgorithm(source.getSSECustomerAlgorithm());
        }
        if (source.getSSECustomerKeyMd5() != null) {
            dest.setSSECustomerKeyMd5(source.getSSECustomerKeyMd5());
        }

        // copy user metadata except the magic marker header.
        source.getUserMetadata().entrySet().stream()
                .filter(e -> !e.getKey().equals(X_HEADER_MAGIC_MARKER))
                .forEach(e -> dest.addUserMetadata(e.getKey(), e.getValue()));
    }

}
