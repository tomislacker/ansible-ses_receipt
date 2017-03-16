#!/usr/bin/python

DOCUMENTATION = """
module: lambda_permission
short_description: Manages Lambda policies
description:
    - The M(lambda_permission) module allows you to create and delete Lambda permissions (policies)
version_added: 2.3
author:
  - "Ben Tomasik (@tomislacker)"
options:
  name:
    description:
      - The name of the Lambda function
    required: True
  id:
    description:
      - Statement Id of the policy (required for state=absent)
    required: False
  policy:
    description:
      - Hash of the various parameters for the policy _See [Lambda.Client.add_permission](http://boto3.readthedocs.io/en/latest/reference/services/lambda.html#Lambda.Client.add_permission) for details_
  state:
    description:
      - Whether to create or destroy the receipt rule set
    required: False
    default: present
    choices: ["absent", "present"]
extends_documentation_fragment: aws
requirements: [ "boto3","botocore" ]
"""

EXAMPLES = """

- name: Create default rule set
  ses_rule_set:
    name: default-rule-set
- name: Allow S3 events to trigger Lambda
  lambda_permission:
    name: my-lambda-name
    id: s3-invoke-policy
    policy:
      Action: 'lambda:InvokeFunction'
      Principal: 's3.amazonaws.com'
      SourceArn: 'arn:aws:s3:::my-bucket-name'
      SourceAccount: '012345678901'

"""

RETURN = ""

import json

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    import botocore
    HAS_BOTOCORE = True
except ImportError:
    HAS_BOTOCORE = False


def statement_id_exists(lambda_client, name, sid, qualifier):
    """
    Checks for a statement id existing within Lambda policy
    """
    get_policy_args = {
        'FunctionName': name,
    }

    if qualifier:
        get_policy_args.update({
            'Qualifier': qualifier,
        })

    try:
        resp = lambda_client.get_policy(**get_policy_args)
        policy_obj = json.loads(resp['Policy'])
        return len([s for s in policy_obj['Statement'] if s['Sid'] == sid]) > 0

    except botocore.exceptions.ClientError:
        # If ResourceNotFound, no policy exists
        return False


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        id=dict(type='str', required=False),
        policy=dict(type='dict', required=False),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    name = module.params.get('name')
    id = module.params.get('id')
    policy = module.params.get('policy')
    state = module.params.get('state').lower()

    check_mode = module.check_mode
    changed = False

    if not HAS_BOTO3:
        module.fail_json(msg='Python module "boto3" is missing, please install it')

    if not HAS_BOTOCORE:
        module.fail_json(msg='Python module "botocore" is missing, please install it')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    if not region:
        module.fail_json(msg='region must be specified')

    try:
        client = boto3_conn(module, conn_type='client', resource='lambda',
                            region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except (botocore.exceptions.ClientError, botocore.exceptions.ValidationError) as e:
        module.fail_json(msg=str(e))

    ###
    # Compose the arguments for removing the policy (if required)
    ###
    remove_policy_args = {
        'FunctionName': name,
        'StatementId': id or '_-_-_unused_-_-_',
    }
    if 'Qualifier' in policy:
        remove_policy_args.update({
            'Qualifier': policy['Qualifier'],
        })

    ###
    # Determine the intended state of the policy/statement & attempt to
    # change it if required
    ###
    if state == 'absent':
        # Remove the policy statement if exists
        raise NotImplementedError

    elif state == 'present':
        ###
        # Compose the arguments for creating the policy
        ###
        create_policy_args = {
            'FunctionName': name,
        }

        # If a statement id is present, add it in
        if id:
            create_policy_args.update({
                'StatementId': id,
            })

        # Add in the other policy arguments
        create_policy_args.update(policy)

        if id and statement_id_exists(client, name, id, policy.get('Qualifier', None)):
            # Statement already exists
            # Delete & re-create it
            # TODO: Attempt to see if the statement is identical and don't
            # remove+re-add it if so
            changed = True

            if not check_mode:
                # First delete the permission
                try:
                    client.remove_permission(**remove_policy_args)
                except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
                    module.fail_json(msg="Failed to remove permission before re-adding: {}".format(str(e)))

                # Then re-create it
                try:
                    client.add_permission(**create_policy_args)
                except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
                    module.fail_json(msg="Failed to re-add permission: {}".format(str(e)))

        else:
            # Statement does not exist yet, create it
            changed = True

            if not check_mode:
                try:
                    client.add_permission(**create_policy_args)
                except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
                    module.fail_json(msg="Failed to re-add permission: {}".format(str(e)))

    module.exit_json(changed=changed)


from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()

