"""
lambda
======

Module to hold Lambda handlers
"""
from __future__ import print_function
import boto3
import dateutil.parser
import email
import json
import logging
import tempfile


class SESRecord(object):
    @classmethod
    def from_dict(cls, d):
        rec = cls()
        rec._raw = d

        return rec

    @property
    def region(self):
        return self._raw['awsRegion']

    @property
    def event_name(self):
        return self._raw['eventName']

    @property
    def event_src(self):
        return self._raw['eventSource']

    @property
    def event_stamp(self):
        return dateutil.parser.parse(self._raw['eventTime'])

    @property
    def event_version(self):
        return self._raw['eventVersion']

    @property
    def event_params(self):
        return self._raw['requestParameters']

    @property
    def event_response(self):
        return self._raw['responseElements']

    @property
    def s3(self):
        return self._raw['s3']

    @property
    def s3_bucket(self):
        return self.s3['bucket']

    @property
    def s3_bucket_arn(self):
        return self.s3_bucket['arn']

    @property
    def s3_bucket_name(self):
        return self.s3_bucket['name']

    @property
    def s3_bucket_owner_ident(self):
        return self.s3_bucket['ownerIdentity']

    @property
    def s3_config_id(self):
        return self.s3['configurationId']

    @property
    def s3_obj(self):
        return self.s3['object']

    @property
    def s3_obj_etag(self):
        return self.s3_obj['eTag']

    @property
    def s3_obj_key(self):
        return self.s3_obj['key']

    @property
    def s3_obj_size(self):
        return self.s3_obj['size']

    @property
    def user_id(self):
        return self._raw['userIdentity']


class S3EventRecordSet(object):
    @classmethod
    def from_dict(cls, in_dict):
        assert 'Records' in in_dict, \
            "Missing 'Records' key in parsing input"

        eset = cls()
        eset.records = [SESRecord.from_dict(r) for r in in_dict['Records']]

        return eset


def fetch_s3_content(s3_resource, s3_bucket, s3_key):
    return s3_resource.Object(s3_bucket, s3_key).get()['Body'].read().decode('utf-8')


def fetch_s3_email(*args, **kwargs):
    return email.message_from_string(fetch_s3_content(*args, **kwargs))


def process_s3_key(*args, **kwargs):
    logging.warning("Downloading S3 key: s3://{b}/{k}".format(
        b=kwargs.get('s3_bucket', 'BROKEN'),
        k=kwargs.get('s3_key', 'BROKEN'),
    ))

    email_obj = fetch_s3_email(*args, **kwargs)

    # TODO Do something with this email
    # See this link for references:
    # https://docs.python.org/2/library/email-examples.html


def lambda_handler(event, context):
    try:
        logging.warning("Parsing S3EventRecordSet")
        rs = S3EventRecordSet.from_dict(event)
    except Exception as e:
        logging.critical("Failed to parse recordset", exc_info=True)
        return False


    logging.warning("Found {c} record{s}".format(
        c=len(rs.records),
        s="s" if len(rs.records) != 1 else ""))

    s3_resource = boto3.resource('s3')

    for record in rs.records:
        logging.info("S3 record:\n" + json.dumps(record.s3, indent=4))

        # Avoid unnecessary keys
        if record.s3_obj_key == 'AMAZON_SES_SETUP_NOTIFICATION':
            logging.critical("Found S3 Setup File")
            continue

        process_s3_key(
            s3_resource=s3_resource,
            s3_bucket=record.s3_bucket_name,
            s3_key=record.s3_obj_key)
