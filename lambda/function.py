from __future__ import print_function
from urllib.error import HTTPError
import os, boto3, json, base64
import urllib.request, urllib.parse
import logging
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Decrypt encrypted URL with KMS
def decrypt(encrypted_url):
    region = os.environ['AWS_REGION']
    try:
        kms = boto3.client('kms', region_name=region)
        plaintext = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_url))['Plaintext']
        return plaintext.decode()
    except Exception:
        logger.exception("Failed to decrypt URL with KMS")

def ec2_get_instance_name(iid):
    region = os.environ['AWS_REGION']
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(iid)
    instancename = iid
    for tags in instance.tags:
        if tags["Key"] == 'Name':
            instancename = tags["Value"]
    return instancename

def cloudwatch_notification(message, region):
    states = {'OK': 'good', 'INSUFFICIENT_DATA': 'warning', 'ALARM': 'danger'}
    return {
        "color": states[message['NewStateValue']],
        "fallback": "Alarm {} triggered".format(message['AlarmName']),
        "fields": [
            { "title": "Alarm Name", "value": message['AlarmName'], "short": True },
            { "title": "Alarm Description", "value": message['AlarmDescription'], "short": False},
            { "title": "Alarm reason", "value": message['NewStateReason'], "short": False},
            { "title": "Old State", "value": message['OldStateValue'], "short": True },
            { "title": "Current State", "value": message['NewStateValue'], "short": True },
            {
                "title": "Link to Alarm",
                "value": "https://console.aws.amazon.com/cloudwatch/home?region=" + region + "#alarm:alarmFilter=ANY;name=" + urllib.parse.quote(message['AlarmName']),
                "short": False
            }
        ]
    }

def ebs_snapshot_notification(message, region):
    states = {'succeeded': 'good', 'failed': 'danger'}
    volume_id = re.search("arn:aws:ec2::\S+:volume/vol-(\w+)", message['detail']['source'])[1]
    snap_id = re.search("arn:aws:ec2::\S+:snapshot/snap-(\w+)", message['detail']['snapshot_id'])[1]
    return {
        "color": states[message['detail']['result']],
        "fallback": "EBS Snapshot Notification for {}".format(message['detail']['source']),
        "fields": [
            { "title": "Event", "value": message['detail']['event'], "short": False },
            {
                "title": "EBS Volume",
                "value": "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Volumes:volumeId=" + urllib.parse.quote(volume_id),
                "short": False

            },
            { "title": "Start Time", "value": message['detail']['startTime'], "short": True },
            { "title": "End Time", "value": message['detail']['endTime'], "short": True },
            {
                "title": "Snapshot",
                "value": "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Snapshots:visibility=owned-by-me;snapshotId=" + urllib.parse.quote(snap_id),
                "short": False
            }
        ]
    }

def ec2_state_change_notification(message, region):
    states = {'running': 'good', 'pending': 'warning', 'stopping': 'danger', 'stopped': 'danger'}
    instance = ec2_get_instance_name(message['detail']['instance-id'])
    return {
        "color": states[message['detail']['state']],
        "fallback": "EC2 Instance {} is {}".format(instance, message['detail']['state']),
        "fields": [
            { "title": "Instance", "value": instance, "short": True },
            { "title": "State", "value": message['detail']['state'], "short": True },
            {
                "title": "Link to Instance",
                "value": "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Instances:instanceId=" + urllib.parse.quote(message['detail']['instance-id']),
                "short": False
            }
        ]
    }

def dlm_notification(message, region):
    states = {'OK': 'good', 'notification': 'warning', 'ERROR': 'danger'}
    if "state" in message['detail']:
        state = message['detail']['state']
        policy = re.search("arn:aws:dlm:\S*:\S+:policy/policy-(\w+)", message['detail']['policy_id'])[1]
        fields = [
            { "title": "State", "value": state, "short": True },
            { "title": "Cause", "value": message['detail']['cause'], "short": False},
            {
                "title": "Link to Policy",
                "value": "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Lifecycle:PolicyId=" + urllib.parse.quote(policy),
                "short": False
            }

        ]
    else:
        state = "notification"
        policy = re.search("policy-(\w+)", message['detail']['requestParameters']['policyId'])[1]
        fields = [
            { "title": "Event", "value": message['detail']['eventName'], "short": True},
            {
                "title": "Link to Policy",
                "value": "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Lifecycle:PolicyId=" + urllib.parse.quote(policy),
                "short": False
            }
        ]

    return {
        "color": states[state],
        "fallback": "DLM Policy {} State Change".format(policy),
        "fields": fields
    }


def default_notification(subject, message, color="default"):
    return {
        "fallback": "A new message",
        "color": color,
        "fields": [{"title": subject if subject else "Message", "value": json.dumps(message) if type(message) is dict else message, "short": False}]
    }


# Send a message to a slack channel
def notify_slack(subject, message, region):
    slack_url = os.environ['SLACK_WEBHOOK_URL']
    if not slack_url.startswith("http"):
        slack_url = decrypt(slack_url)

    slack_channel = os.environ['SLACK_CHANNEL']
    slack_username = os.environ['SLACK_USERNAME']
    slack_emoji = os.environ['SLACK_EMOJI']

    payload = {
        "channel": slack_channel,
        "username": slack_username,
        "icon_emoji": slack_emoji,
        "attachments": []
    }
    if type(message) is str:
        try:
            message = json.loads(message)
        except json.JSONDecodeError as err:
            logger.exception(f'JSON decode error: {err}')

    if subject is None:
        subject = message["detail-type"]

    if "AlarmName" in message:
        notification = cloudwatch_notification(message, region)
        subject = "AWS CloudWatch notification - " + message["AlarmName"]
    elif message['detail-type'] == "EBS Snapshot Notification":
        notification = ebs_snapshot_notification(message, region)
    elif message['detail-type'] == "EC2 Instance State-change Notification":
        notification = ec2_state_change_notification(message, region)
    elif message['source'] == "aws.dlm":
        notification = dlm_notification(message, region)
        subject = "DLM Policy State Change"
    else:
        color = "default"
        if "alert" in subject:
            color = "danger"
        notification = default_notification(subject, message, color)
        subject = "AWS notification"

    payload['text'] = subject
    payload['attachments'].append(notification)
    
    data = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    req = urllib.request.Request(slack_url)

    try:
        result = urllib.request.urlopen(req, data)
        return json.dumps({"code": result.getcode(), "info": result.info().as_string()})

    except HTTPError as e:
        logger.error("{}: result".format(e))
        return json.dumps({"code": e.getcode(), "info": e.info().as_string()})


def lambda_handler(event, context):
    if 'LOG_EVENTS' in os.environ and os.environ['LOG_EVENTS'] == 'True':
        logger.warning('Event logger enabled: `{}`'.format(json.dumps(event)))
    subject = event['Records'][0]['Sns']['Subject']
    message = event['Records'][0]['Sns']['Message']
    region = event['Records'][0]['Sns']['TopicArn'].split(":")[3]
    response = notify_slack(subject, message, region)

    if json.loads(response)["code"] != 200:
        logger.error("Error: received status `{}` using event `{}` and context `{}`".format(json.loads(response)["info"], event, context))

    return response
