#!/usr/bin/python

DOCUMENTATION = """
module: ses_rule_set
short_description: Manages SES inbound receipt rule sets
description:
    - The M(ses_rule_set) module allows you to create, delete, and manage SES receipt rule sets
version_added: 2.3
author:
  - "Ben Tomasik (@tomislacker)"
options:
  name:
    description:
      - The name of the receipt rule set
    required: True
  state:
    description:
      - Whether to create or destroy the receipt rule set
    required: False
    default: present
    choices: ["absent", "present"]
  activate:
    description:
      - Whether or not to set this rule set as the active one
    required: False
    default: False
extends_documentation_fragment: aws
requirements: [ "boto3","botocore" ]
"""

EXAMPLES = """

- name: Create default rule set
  ses_rule_set:
    name: default-rule-set

"""

RETURN = ""

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


def rule_set_exists(ses_client, name):
    rule_sets = ses_client.list_receipt_rule_sets()['RuleSets']
    return len([s for s in rule_sets if s['Name'].lower() == name.lower()]) > 0


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        activate=dict(type='bool', default=False),
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    name = module.params.get('name').lower()
    state = module.params.get('state').lower()
    activate = module.params.get('activate')
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
        client = boto3_conn(module, conn_type='client', resource='ses',
                            region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except (botocore.exceptions.ClientError, botocore.exceptions.ValidationError) as e:
        module.fail_json(msg=str(e))

    if state == 'absent':
        # Remove the rule set if present
        if rule_set_exists(client, name):
            changed = True

            if not check_mode:
                try:
                    client.delete_receipt_rule_set(
                        RuleSetName=name)
                except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
                    module.fail_json(msg=str(e))

    elif state == 'present':
        # Add rule set if missing
        if not rule_set_exists(client, name):
            changed = True

            if not check_mode:
                try:
                    client.create_receipt_rule_set(
                        RuleSetName=name)
                except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
                    module.fail_json(msg=str(e))

        # Set active if requested
        if activate:
            # First determine if it's the active rule set
            active_name = client.describe_active_receipt_rule_set()['Metadata']['Name'].lower()

            if name != active_name:
                changed = True

                if not check_mode:
                    try:
                        client.set_active_receipt_rule_set(
                            RuleSetName=name)
                    except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
                        module.fail_json(msg=str(e))

    module.exit_json(changed=changed)


from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()

