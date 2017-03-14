#!/usr/bin/env python
import boto3
from ansible.plugins.lookup import LookupBase
from ansible import errors


class LookupModule(LookupBase):
    def __init__(self, basedir=None, **kwargs):
        self.basedir = basedir

    def run(self, terms, inject=None, **kwargs):
        try:
            return [boto3.client('sts').get_caller_identity()['Account']]
        except Exception as e:
            raise errors.AnsibleLookupError(str(e))
