#!/usr/bin/python
# (c) 2016, Pierre Jodouin <pjodouin@virtualcomputing.solutions>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

import re
# import json
# from hashlib import md5

try:
    import boto3
    import boto              # seems to be needed for ansible.module_utils
    from botocore.exceptions import ClientError, ParamValidationError, MissingParametersError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


DOCUMENTATION = '''
---
module: s3_event
short_description: Creates, updates or deletes AWS S3 event notifications.
description:
    - This module allows the management of AWS S3 event notifications.
      It is idempotent and supports "Check" mode.
version_added: "2.1"
author: Pierre Jodouin (@pjodouin)
options:
  state:
    description:
      - Describes the desired state and defaults to "present".
    required: true
    default: "present"
    choices: ["present", "absent"]

  bucket:
    description:
      - Name of source bucket.
    required: true
    default: none
    aliases: ['bucket_name']

  prefix:
    description:
      - Bucket prefix (e.g. images/)
    required: false
    default: none

  suffix:
    description:
      - Bucket suffix (e.g. log)
    required: false
    default: none

  id:
    description:
      - Unique ID for this source event.
    required: true
    default: none
    aliases: [ 'config_id' ]

  topic_arn:
    description:
      - The name or ARN of the lambda function, including the alias/version suffix.
        Mutually exclusive with C(queue_arn) and C(lambda_function_arn).
    required: false
    default: none
    aliases: ['topic']

  queue_arn:
    description:
      - The name or ARN of the lambda function, including the alias/version suffix.
        Mutually exclusive with C(topic_arn) and C(lambda_function_arn).
    required: false
    default: none
    aliases: ['queue']

  lambda_function_arn:
    description:
      - The name or ARN of the lambda function, including the alias/version suffix.
        Mutually exclusive with C(queue_arn) and C(topic_arn).
    required: false
    default: none
    aliases: ['function_name', 'function_arn']

  events:
    description:
      - List of events (e.g. ['s3:ObjectCreated:Put'])
    required: true
    default: none

notes:
    - Make sure the appropriate permissions are granted prior to creating an event notification. For example,
      use the lambda_policy module to grant permissions to the S3 bucket if you want the specified event to trigger
      a call to the lambda function.
requirements:
    - boto3
extends_documentation_fragment:
    - aws

'''

EXAMPLES = '''
---
# Example that creates lambda event notifications for an S3 bucket
- hosts: localhost
  gather_facts: no
  vars:
    state: present
    bucket: myBucket
  tasks:
  - name: S3 event notification
    s3_event:
      state: "{{ state | default('present') }}"
      bucket: "{{ bucket }}"
      id: lambda-s3-myBucket-data-log
      lambda_function_arn: ingestData
      prefix: twitter
      suffix: log
      events:
      - s3:ObjectCreated:Put

  - name: S3 event notification for SNS
    s3_event:
      state: "{{ state | default('present') }}"
      bucket: "{{ bucket }}"
      id: lambda-s3-myBucket-delete-sns-log
      topic_arn: arn:aws:sns:xx-east-1:123456789012:NotifyMe
      prefix: twitter
      suffix: log
      events:
      - s3:ObjectRemoved:Delete

  - name: S3 event notification for SQS
    s3_event:
      state: "{{ state | default('present') }}"
      bucket: "{{ bucket }}"
      id: lambda-s3-myBucket-copy-sqs-log
      queue_arn: myQueue
      prefix: twitter
      suffix: log
      events:
      - s3:ObjectCreated:Copy

  - name: show source event config
    debug: var=s3_event

'''

RETURN = '''
---
s3_event:
    description: Dictionary of event notification configurations.
    returned: success
    type: dict

'''

# ---------------------------------------------------------------------------------------------------
#
#   Helper Functions & classes
#
# ---------------------------------------------------------------------------------------------------


class AWSConnection:
    """
    Create the connection object and client objects as required.
    """

    def __init__(self, ansible_obj, resources, boto3=True):

        try:
            self.region, self.endpoint, aws_connect_kwargs = get_aws_connection_info(ansible_obj, boto3=boto3)

            self.resource_client = dict()
            if not resources:
                resources = ['s3']

            resources.append('iam')

            for resource in resources:
                aws_connect_kwargs.update(dict(region=self.region,
                                               endpoint=self.endpoint,
                                               conn_type='client',
                                               resource=resource
                                               ))
                self.resource_client[resource] = boto3_conn(ansible_obj, **aws_connect_kwargs)

            # if region is not provided, then get default profile/session region
            if not self.region:
                self.region = self.resource_client['s3'].meta.region_name

        except (ClientError, ParamValidationError, MissingParametersError) as e:
            ansible_obj.fail_json(msg="Unable to connect, authorize or access resource: {0}".format(e))

        # set account ID
        try:
            self.account_id = self.resource_client['iam'].get_user()['User']['Arn'].split(':')[4]
        except (ClientError, ValueError, KeyError, IndexError):
            self.account_id = ''

    def client(self, resource='s3'):
        return self.resource_client[resource]


def pc(key):
    """
    Changes python key into Pascale case equivalent. For example, 'this_function_name' becomes 'ThisFunctionName'.

    :param key:
    :return:
    """

    return "".join([token.capitalize() for token in key.split('_')])


def ordered_obj(obj):
    """
    Order object for comparison purposes

    :param obj:
    :return:
    """

    if isinstance(obj, dict):
        return sorted((k, ordered_obj(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered_obj(x) for x in obj)
    else:
        return obj


def set_api_sub_params(params):
    """
    Sets module sub-parameters to those expected by the boto3 API.

    :param module_params:
    :return:
    """

    api_params = dict()

    for param in params.keys():
        param_value = params.get(param, None)
        if param_value:
            api_params[pc(param)] = param_value

    return api_params


def validate_params(module, aws):
    """
    Performs basic parameter validation.

    :param module:
    :param aws:
    :return:
    """

    function_name = module.params.get('lambda_function_arn')
    if function_name:
        # validate function name
        if not re.search('^[\w\-:]+$', function_name):
            module.fail_json(
                    msg='Function name {0} is invalid. Names must contain only alphanumeric characters, colons and hyphens.'.format(function_name)
            )
        if len(function_name) > 64:
            module.fail_json(msg='Function name "{0}" exceeds 64 character limit'.format(function_name))

        # check if 'function_name' needs to be expanded in full ARN format
        if not function_name.startswith('arn:aws:lambda:'):
            module.params['lambda_function_arn'] = 'arn:aws:lambda:{0}:{1}:function:{2}'.format(aws.region, aws.account_id, function_name)

    topic_arn = module.params.get('topic_arn')
    if topic_arn:
        # check if 'topic_arn' needs to be expanded in full ARN format
        if not topic_arn.startswith('arn:aws:sns:'):
            module.params['topic_arn'] = 'arn:aws:sns:{0}:{1}:{2}'.format(aws.region, aws.account_id, topic_arn)

    queue_arn = module.params.get('queue_arn')
    if queue_arn:
        # check if 'queue_arn' needs to be expanded in full ARN format
        if not queue_arn.startswith('arn:aws:sqs:'):
            module.params['queue_arn'] = 'arn:aws:sqs:{0}:{1}:{2}'.format(aws.region, aws.account_id, queue_arn)

    return


def get_arn(module):
    """

    :param module:
    :return:
    """

    service_configs = {
        'topic': 'TopicConfigurations',
        'queue': 'QueueConfigurations',
        'lambda': 'LambdaFunctionConfigurations'
        }

    service_arn = None
    service = None
    service_param = None

    for item in ('topic_arn', 'queue_arn', 'lambda_function_arn'):
        if module.params[item]:
            service_arn = module.params[item]
            service_param = pc(item)
            service = item.split('_', 1)[0]
            break

    if not service_arn:
        module.fail_json(msg='Error: exactly one target service ARN is required.')

    return service_configs[service], service_param, service_arn


# ---------------------------------------------------------------------------------------------------
#
#   S3 Event Handlers
#
# ---------------------------------------------------------------------------------------------------

def state_management(module, aws):
    """
    Adds, updates or deletes s3 event notifications.

    :param module: Ansible module reference
    :param aws:
    :return dict:
    """

    client = aws.client('s3')
    changed = False
    current_state = 'absent'
    state = module.params['state']
    config_id = module.params['id']
    bucket = module.params['bucket']

    api_params = dict(Bucket=module.params['bucket'])

    # check if event notifications exist
    try:
        facts = client.get_bucket_notification_configuration(**api_params)
        facts.pop('ResponseMetadata')
    except (ClientError, ParamValidationError, MissingParametersError) as e:
        facts = None
        module.fail_json(msg='Error retrieving s3 event notification configuration: {0}'.format(e))

    configurations, service_param, service_arn = get_arn(module)

    current_configs = list()
    matching_id_config = dict()

    if configurations in facts:
        current_configs = facts[configurations]
        # current_configs = facts.pop(configurations)

        for config in current_configs:
            if config['Id'] == config_id:
                matching_id_config = config
                current_configs.remove(config)
                current_state = 'present'
                break

    if state == 'present':
        # build configurations
        new_configuration = dict(Id=config_id)
        new_configuration[service_param] = service_arn

        filter_rules = []
        if module.params.get('prefix'):
            filter_rules.append(dict(Name='Prefix', Value=str(module.params['prefix'])))
        if module.params.get('suffix'):
            filter_rules.append(dict(Name='Suffix', Value=str(module.params['suffix'])))
        if filter_rules:
            new_configuration.update(Filter=dict(Key=dict(FilterRules=filter_rules)))

        new_configuration.update(Events=module.params['events'])

        if current_state == 'present':

            # check if source event configuration has changed
            if ordered_obj(matching_id_config) == ordered_obj(new_configuration):
                current_configs.append(matching_id_config)
            else:
                # update s3 event notification
                current_configs.append(new_configuration)
                facts[configurations] = current_configs
                api_params = dict(NotificationConfiguration=facts, Bucket=bucket)

                try:
                    if not module.check_mode:
                        client.put_bucket_notification_configuration(**api_params)
                    changed = True
                except (ClientError, ParamValidationError, MissingParametersError) as e:
                    module.fail_json(msg='Error updating s3 event notification for {0}: {1}'.format(service_arn, e))

        else:
            # create s3 event notification
            current_configs.append(new_configuration)
            facts[configurations] = current_configs
            api_params = dict(NotificationConfiguration=facts, Bucket=bucket)

            try:
                if not module.check_mode:
                    client.put_bucket_notification_configuration(**api_params)
                changed = True
            except (ClientError, ParamValidationError, MissingParametersError) as e:
                module.fail_json(msg='Error creating s3 event notification for {0}: {1}'.format(service_arn, e))

    else:
        # state = 'absent'
        if current_state == 'present':

            # delete the s3 event notifications
            if current_configs:
                facts[configurations] = current_configs

            api_params.update(NotificationConfiguration=facts)

            try:
                if not module.check_mode:
                    client.put_bucket_notification_configuration(**api_params)
                changed = True
            except (ClientError, ParamValidationError, MissingParametersError) as e:
                module.fail_json(msg='Error removing s3 source event notification for {0}: {1}'.format(service_arn, e))

    return dict(changed=changed, ansible_facts=dict(s3_event=facts))


# ---------------------------------------------------------------------------------------------------
#
#   MAIN
#
# ---------------------------------------------------------------------------------------------------

def main():
    """
    Main entry point.

    :return dict: ansible facts
    """

    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        state=dict(required=False, default='present', choices=['present', 'absent']),
        bucket=dict(required=True, default=None, aliases=['bucket_name', ]),
        id=dict(required=True, default=None, aliases=['config_id', ]),
        prefix=dict(required=False, default=None),
        suffix=dict(required=False, default=None),
        topic_arn=dict(required=False, default=None, aliases=['topic', ]),
        queue_arn=dict(required=False, default=None, aliases=['queue', ]),
        lambda_function_arn=dict(required=False, default=None, aliases=['function_arn', 'lambda_arn']),
        events=dict(type='list', required=True, default=None)
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[],
        mutually_exclusive=[['topic_arn', 'queue_arn', 'lambda_function_arn']]
    )

    # validate dependencies
    if not HAS_BOTO3:
        module.fail_json(msg='Both boto3 & boto are required for this module.')

    aws = AWSConnection(module, ['s3'])

    validate_params(module, aws)

    results = state_management(module, aws)

    module.exit_json(**results)


# ansible import module(s) kept at ~eof as recommended
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
