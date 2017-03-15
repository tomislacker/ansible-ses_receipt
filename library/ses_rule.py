#!/usr/bin/python

DOCUMENTATION = """
module: ses_rule
short_description: Manages SES inbound receipt rules
description:
    - The M(ses_rule_set) module allows you to create, delete, and manage SES receipt rules
version_added: 2.3
author:
  - "Ben Tomasik (@tomislacker)"
options:
  name:
    description:
      - The name of the receipt rule
    required: True
  ruleset:
    description:
      - The name of the receipt rule set
    required: True
  state:
    description:
      - Whether to create or destroy the receipt rule
    required: False
    default: present
    choices: ["absent", "present"]
  after:
    description:
      - Insert new rule before another (This only applies during creation)
    required: False
  enabled:
    description:
      - Whether the rule should be enabled or not
    required: False
    default: True
  tls_required:
    description:
      - Whether inbound emails should require TLS
    required: False
    default: False
  recipients:
    description:
      - Recipient specification(s)
    required: True
  actions:
    description:
      - Rule actions
    required: True
  scan_enabled:
    description:
      - Whether inbound emails should get virus scanned
    required: False
    default: False
extends_documentation_fragment: aws
requirements: [ "boto3","botocore" ]
"""

EXAMPLES = """

# Pushes emails to S3 that are received for any address @mydomain.com as well
# as any address @<any subdomain>.mydomain.com
- name: Create catch-all rule
  ses_rule:
    name: main-rule
    ruleset: default-rule-set
    recipients:
      - '.mydomain.com'
      - 'mydomain.com'
    actions:
      - S3Action:
          BucketName: my-bucket

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


def rule_exists(ses_client, ruleset, name):
    rules = ses_client.describe_receipt_rule_set(RuleSetName=ruleset)['Rules']
    return len([r for r in rules if r['Name'].lower() == name.lower()]) > 0


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        ruleset=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        after=dict(type='str', required=False),
        enabled=dict(type='bool', default=True),
        tls_required=dict(type='bool', default=False),
        recipients=dict(type='list', required=True),
        actions=dict(type='list', required=True),
        scan_enabled=dict(type='bool', default=True),
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    name = module.params.get('name').lower()
    ruleset = module.params.get('ruleset').lower()
    state = module.params.get('state').lower()
    after = module.params.get('after')
    enabled = module.params.get('enabled')
    tls_required = module.params.get('tls_required')
    recipients = module.params.get('recipients')
    actions = module.params.get('actions')
    scan_enabled = module.params.get('scan_enabled')

    check_mode = module.check_mode
    changed = False

    if not HAS_BOTO3:
        module.fail_json(msg='Python module "boto3" is missing, please install it')

    if not HAS_BOTOCORE:
        module.fail_json(msg='Python module "botocore" is missing, please install it')

    if len(recipients) == 0 and state == 'present':
        module.fail_json(msg='No recipients provided')

    if len(actions) == 0 and state == 'present':
        module.fail_json(msg='No actions provided')

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    if not region:
        module.fail_json(msg='region must be specified')

    try:
        client = boto3_conn(module, conn_type='client', resource='ses',
                            region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except (botocore.exceptions.ClientError, botocore.exceptions.ValidationError) as e:
        module.fail_json(msg=str(e))

    if not rule_set_exists(client, ruleset):
        module.fail_json(msg='Rule set {} does not exist'.format(ruleset))

    if state == 'absent':
        # Remove the rule if present
        if rule_exists(client, ruleset, name):
            changed = True

            if not check_mode:
                try:
                    client.delete_receipt_rule(
                        RuleSetName=ruleset,
                        RuleName=name)
                except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
                    module.fail_json(msg=str(e))

    elif state == 'present':
        create_args = {
            'RuleSetName': ruleset,
            'Rule': {
                'Name': name,
                'Enabled': enabled,
                'TlsPolicy': "Require" if tls_required else "Optional",
                'Recipients': recipients,
                'Actions': actions,
                'ScanEnabled': scan_enabled,
            },
        }

        if not rule_exists(client, ruleset, name):
            # Rule doesn't exist, add it
            changed = True


            if after:
                create_args.update({
                    'After': after.lower(),
                })

            if not check_mode:
                try:
                    client.create_receipt_rule(**create_args)
                except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
                    module.fail_json(msg=str(e))

        else:
            # Rule exists, update it
            # TODO Check if there'll actually be a difference before marking
            # the module task as changed
            changed = True

            if not check_mode:
                try:
                    client.update_receipt_rule(**create_args)
                except (botocore.exceptions.ParamValidationError, botocore.exceptions.ClientError) as e:
                    module.fail_json(msg=str(e))

    module.exit_json(changed=changed)


from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()

