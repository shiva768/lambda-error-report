import json
import re
import boto3
import os
import datetime as dt
from logging import getLogger, StreamHandler, DEBUG, Formatter
from urllib.error import HTTPError
from urllib.request import Request, urlopen

""" require authority """
# cloudwatchlogs full_access
# cloudwatch readonly


""" settings """
# ログ取得
FILTER_PATTERNS = ['ERROR', 'FATAL']
GROUP_NAME = os.getenv('GROUP_NAME')
# cloudwatch履歴取得
ALARM_NAME = os.getenv('ALARM_NAME')
HISTORY_ITEM_TYPE = 'StateUpdate'
MAX_RECORD = 1
# redmine
REDMINE_URL = os.getenv('REDMINE_URL', '')
REDMINE_ACCESS_KEY = os.getenv('REDMINE_ACCESS_KEY')
REDMINE_PROJECT_ID = os.getenv('REDMINE_PROJECT_ID')
REDMINE_TRACKER_ID = os.getenv('REDMINE_TRACKER_ID')
REDMINE_TICKET_TITLE_TEMPLATE = "あらーと to {0} ({1})"
REDMINE_TICKET_TITLE_PREFIX = os.getenv('REDMINE_TICKET_TITLE_PREFIX', '')
""" /settings"""

logger = getLogger(__name__)
logger.setLevel(DEBUG)
handler = StreamHandler()
handler.setFormatter(Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

STATUS_OK = 'OK'
STATUS_ALARM = 'ALARM'
DATETIME_FORMAT = '%Y/%m/%d %H:%M:%S'
DATETIME_FORMAT_WITH_OFFSET = '%Y-%m-%dT%H:%M:%S.%f%z'
JST = dt.timezone(dt.timedelta(hours=+9), 'JST')
client_param = {}
logger.info('groupname' + GROUP_NAME)


def lambda_handler(event, context):
    logger.info(str(event))
    log_message = event['Records'][0]['Sns']['Message']
    logger.info('message:{0}'.format(log_message))
    log_json = json.loads(log_message)
    state = log_json['NewStateValue']
    from_time = get_from_time(state, log_json)
    from_timestamp = create_timestamp(from_time)
    to_timestamp = create_timestamp(dt.datetime.now())
    result = extracts(from_timestamp, to_timestamp)
    logger.info('result:' + str(result))
    post_redmine(state, result)


def extracts(from_timestamp, current_timestamp):
    client = boto3.client('logs', **client_param)
    result = {}
    for pattern in FILTER_PATTERNS:
        logs = get_logs(pattern, from_timestamp, current_timestamp, None, client)
        if len(logs) > 0:
            result[pattern] = logs
    return result


def get_logs(pattern, reason_timestamp, current_timestamp, next_token, _client):
    client = _client
    """ :type : pyboto3.cloudwatchlogs """
    dict_param = {
        'logGroupName': GROUP_NAME,
        'filterPattern': pattern,
        'startTime': reason_timestamp,
        'endTime': current_timestamp
    }
    if next_token is not None:
        dict_param['nextToken'] = next_token
    response = client.filter_log_events(**dict_param)

    logs = list(map(lambda event: event['message'], response['events']))
    if 'nextToken' in response:
        next_logs = get_logs(pattern, reason_timestamp, current_timestamp, response['nextToken'], client)
        logs.extend(next_logs)
    return logs


def get_from_time(state, log_json: dict):
    if state == STATUS_ALARM:
        return get_reason_time(log_json['NewStateReason'])
    elif state == STATUS_OK:
        return get_current_before_state_change()
    raise ValueError('unknown state. {0}'.format(state))


def get_reason_time(reason):
    reason_time_match = re.search('\((\d{2}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2})\)', reason)
    if not reason_time_match:
        raise ValueError('reason_time regexp not match. {0}'.format(reason_time_match))
    return dt.datetime.strptime(reason_time_match.group(1), '%d/%m/%y %H:%M:%S')


def get_current_before_state_change():
    client = boto3.client('cloudwatch', **client_param)
    """ :type : pyboto3.cloudwatch """
    response = client.describe_alarm_history(
        AlarmName=ALARM_NAME,
        HistoryItemType=HISTORY_ITEM_TYPE,
        MaxRecords=MAX_RECORD
    )
    logger.debug(str(response))
    history_data = response['AlarmHistoryItems'][0]['HistoryData']
    parsed_history_data = json.loads(history_data)
    before_state_change_datetime_str = parsed_history_data['oldState']['stateReasonData']['queryDate']
    logger.info('before_state_change_datetime. {0}'.format(before_state_change_datetime_str))
    return dt.datetime.strptime(before_state_change_datetime_str, DATETIME_FORMAT_WITH_OFFSET)


def create_timestamp(time: dt.datetime):
    timestamp = int(time.timestamp() * 1000)
    logger.info('time:{0}, timestamp:{1}'.format(str(time), str(timestamp)))
    return timestamp


def post_redmine(state: str, result: dict):
    data = {'issue': {
        'project_id': REDMINE_PROJECT_ID,
        'tracker_id': REDMINE_TRACKER_ID,
        'subject': REDMINE_TICKET_TITLE_PREFIX + REDMINE_TICKET_TITLE_TEMPLATE.format(state,
                                                                                      dt.datetime.now(JST).strftime(
                                                                                          DATETIME_FORMAT)),
        'description': format_log(result)
    }}
    headers = {'Accept': 'application/json', 'Content-type': 'application/json',
               'X-Redmine-API-Key': REDMINE_ACCESS_KEY}
    logger.info('data:' + str(data))
    _request = Request(REDMINE_URL, data=json.dumps(data).encode(), method='POST', headers=headers)
    response = None
    try:
        response = urlopen(_request)
        logger.info("redmine_response:{0}".format(response.read()))
    except HTTPError as e:
        logger.info("error code:{0} reason:{1}".format(e.code, e.reason))
    finally:
        response.close() if response is not None else None


def format_log(logs: dict):
    result = str()
    for pattern in FILTER_PATTERNS:
        if pattern not in logs:
            continue
        result += pattern
        result += '\n'
        result += '\n'.join(logs[pattern])
        result += '\n'
    return result


if __name__ == '__main__':
    client_param = {
        'aws_access_key_id': '',
        'aws_secret_access_key': '',
        'region_name': 'ap-northeast-1'
    }
    event = {
        "Records": [
            {
                "EventSource": "aws:sns",
                "EventVersion": "1.0",
                "EventSubscriptionArn": "",
                "Sns": {
                    "Type": "Notification",
                    "MessageId": "",
                    "TopicArn": "",
                    "Subject": "",
                    "Message": "",
                    "Timestamp": "2017-12-01T10:28:56.936Z",
                    "SignatureVersion": "1",
                    "Signature": "",
                    "SigningCertUrl": "",
                    "UnsubscribeUrl": "",
                    "MessageAttributes": {}
                }
            }
        ]
    }
    lambda_handler(event, None)
