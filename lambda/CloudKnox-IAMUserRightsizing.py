
import json
import sys
import datetime
import boto3
import botocore
import datetime
import time
from botocore.exceptions import ClientError

try:
    import liblogging
except ImportError:
    pass

import http.client
import mimetypes
import ssl

## AWS Secrets Manager - retrieve secretstring
def get_secret_value(key='CloudKnoxSecretString'):
          secretsmanager = boto3.client('secretsmanager')
          secret_list = secretsmanager.list_secrets()['SecretList']
          output = {}
          for s in secret_list:
              if key in s.values():
                  output = secretsmanager.get_secret_value(SecretId=key)['SecretString']
          return(output)


##  Role Policy CloudKnox API - Retrieve IAM Policy:
def getCloudKnoxRemediationPolicy(apiId, accessToken, serviceId, timestamp, url, accountId, userarn, port):
    conn = http.client.HTTPSConnection(url, port)
    content_type = "application/json"
    print('apiId: '+ apiId )
    print('accessToken: '+ accessToken )
    print('serviceId: '+ serviceId )
    print('timestamp: '+ timestamp )
    print('url: ' + url)
    print('accountId: ' + accountId)
    print('userarn: ' + userarn)
    
    headers = {
      'X-CloudKnox-Access-Token': accessToken,
      'X-CloudKnox-API-Id': apiId,
      'X-CloudKnox-Service-Account-Id': serviceId,
      'X-CloudKnox-Timestamp-Millis': timestamp,
      'Content-Type': content_type
    }
    
    endTime = int(round(time.time() * 1000))
    startTime = endTime - (90*86400*1000)
    
    cloudknoxDict = {}
    cloudknoxDict['authSystemInfo'] = {'id': accountId,
                                        'type': 'AWS'}
    cloudknoxDict['identityType'] = 'USER'
    cloudknoxDict['identityIds'] = [userarn]
    cloudknoxDict['aggregation'] = {'type': 'SUMMARY'}
    cloudknoxDict['requestParams'] = {"scope": None,
                                "resource": None,
                                "resources": None,
                                "condition": None
                            }
    cloudknoxDict['filter'] = {'historyDays': 90,
                                'preserveReads': True,
                                 "historyDuration": {
                                	"startTime": startTime,
                                	"endTime": endTime
                                }
                             }
    payload = json.dumps(cloudknoxDict)

    print('payload: ' + payload)
    
    conn.request("POST", "/api/v2/role-policy/new", payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_raw = data.decode()
    print('data_raw: ' + data_raw)
    dataResponse = json.loads(data.decode("utf-8"))
    print('dataResponse_policy: ' + dataResponse['data'][0]['policyName'])
    return dataResponse['data']

## Authenticate CloudKnox API - Retrieve accessToken:
def getAccessToken(serviceId,timestamp,accessKey,secretKey,url,port):
    conn = http.client.HTTPSConnection(url, port)
    content_type = "application/json"
    print('serviceId-accessToken: '+ serviceId )
    print('timestamp-accessToken: '+ timestamp )
    print('accessKey-accessToken: '+ accessKey )
    print('secretKey-accessToken: '+ secretKey )
    print('url-accessToken: ' + url)

    headers = {
      'X-CloudKnox-Service-Account-Id': serviceId,
      'X-CloudKnox-Timestamp-Millis': timestamp,
      'Content-Type': content_type
    }

    cloudknoxDict = {}
    cloudknoxDict['serviceAccountId'] = serviceId
    cloudknoxDict['accessKey'] = accessKey
    cloudknoxDict['secretKey'] = secretKey

    payload = json.dumps(cloudknoxDict)
    print('payload-accessToken: ' + payload)
    
    conn.request("POST", "/api/v2/service-account/authenticate", payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_raw = data.decode()
    print('data_raw: ' + data_raw)
    dataResponse = json.loads(data.decode("utf-8"))
    print('accessToken: ' + dataResponse['accessToken'])
    return dataResponse['accessToken']

def lambda_handler(event, context):
    
    ## CloudKnox Details in Secrets Manager
    secretList = json.loads(get_secret_value('CloudKnoxSecretString'))
    serviceId=""
    apiId=""
    accessKey=""
    secretKey=""
    accessToken=""
    accountId=""
    url=""
    
    serviceId_key='serviceId'
    apiId_key='apiId'
    accessKey_key='accessKey'
    secretKey_key='secretKey'
    accountId_key= 'accountId'
    url_key='url'
    
    userarn = event['userarn']
      
    if serviceId_key in secretList:
        serviceId = secretList[serviceId_key]
    if apiId_key in secretList:
        apiId = secretList[apiId_key]
    if accessKey_key in secretList:
        accessKey = secretList[accessKey_key]
    if secretKey_key in secretList:
        secretKey = secretList[secretKey_key]
    if accountId_key in secretList:
        accountId = secretList[accountId_key]
    if url_key in secretList:
        url = secretList[url_key]

    millis = int(round(time.time() * 1000))
    timestamp = str(millis)
    
    accessToken = getAccessToken(serviceId,timestamp,accessKey,secretKey,url,443)
    print('accessToken is: ' + accessToken)
    iampolicy = getCloudKnoxRemediationPolicy(apiId, accessToken, serviceId, timestamp, url, accountId, userarn, 443)
    
    return 