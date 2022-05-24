package org.apache.hadoop.fs.s3a.impl;

public final class NetworkBinding {
    /**
     * Given an S3 bucket region as returned by a bucket location query,
     * fix it into a form which can be used by other AWS commands.
     * <p>
     * <a href="https://forums.aws.amazon.com/thread.jspa?messageID=796829">
     * https://forums.aws.amazon.com/thread.jspa?messageID=796829</a>
     * </p>
     * See also {@code com.amazonaws.services.s3.model.Region.fromValue()}
     * for its conversion logic.
     * @param region region from S3 call.
     * @return the region to use in DDB etc.
     */
    public static String fixBucketRegion(final String region) {
        return region == null || region.equals("US")
                ? "us-east-1"
                : region;
    }
}
