'''
This function is will download logs from one pass and push it into LogAnalytics Table in Sentinel.

'''
import os
import datetime
import logging
import requests
import json
import datetime
import azure.functions as func
import base64
import hmac
import hashlib
import re

connection_string = os.environ['AzureWebJobsStorage']
customer_id = os.environ['WorkspaceID']
shared_key = os.environ['WorkspaceKey']
logAnalyticsUri = 'https://' + customer_id + '.ods.opinsights.azure.com'
log_type = 'Test_DataIngestion'
logAnalyticsUri = os.environ.get('logAnalyticsUri')
if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):
    logAnalyticsUri = 'https://' + customer_id + '.ods.opinsights.azure.com'

pattern = r"https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$"
match = re.match(pattern,str(logAnalyticsUri))
if(not match):
    raise Exception("Invalid Log Analytics Uri.")


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization


def post_data(body):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = logAnalyticsUri + resource + "?api-version=2016-04-01"
    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        return response.status_code
    else:
        logging.warn("Events are not processed into Azure. Response code: {}".format(response.status_code))
        return None




def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    body = json.dumps({
            "uuid": "asdfasdfasdf",
            "timestamp": "2023-02-10T12:55:49.903Z",
            "used_version": 16,
            "vault_uuid": "asdfasdfasdf",
            "item_uuid": "asdfasdfasdfa",
            "user": {
                "uuid": "asdfasdfasdfasdfasd",
                "name": "asfa asdfasdf",
                "email": "asdf.asdfs@test.com"
            },
            "client": {
                "app_name": "1Password Browser Extension",
                "app_version": "20236",
                "platform_name": "Chrome",
                "platform_version": "109.0.0.0",
                "os_name": "MacOSX",
                "os_version": "10.15.7",
                "ip_address": "11.11.11.11"
            },
            "location": {
                "country": "Cattegat",
                "region": "Uppsala",
                "city": "Jormsburg",
                "latitude": 11.3591,
                "longitude": 11.9948
            },
            "action": "fill"
        })
    post_data(body)
    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )
