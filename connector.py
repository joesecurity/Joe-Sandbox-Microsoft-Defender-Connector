#!/usr/bin/python3
# Copyright by Joe Security LLC

import argparse
import json
import sys
import jbxapi
import requests
from datetime import datetime, timedelta

# Microsoft Credentials
msTenantId = '___'
msClientId = '___' 
msAppSecret = '___' 
msCloud = 'https://api.securitycenter.microsoft.com'

# Joe Sandbox Credentials
jbxAPIKey = "___"

# For Cloud Basic: https://www.joesandbox.com/api"
jbxCloud = "https://jbxcloud.joesecurity.org/api"


# Time span (hours) to search for past alerts
timeSpan = 2

def msOath2Login():

    url = "https://login.microsoftonline.com/%s/oauth2/token" % (msTenantId)

    body = {
        'resource' : msCloud,
        'client_id' : msClientId,
        'client_secret' : msAppSecret,
        'grant_type' : 'client_credentials'
    }

    response = requests.post(url=url, data=body)

    if response.status_code != 200:
        print("Unable to login to Microsoft Azure: " + response.content.decode("utf-8"))
        return ''

    data = json.loads(response.content)
    return data["access_token"]
    
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-alerts?view=o365-worldwide
def msDefenderGetAlerts(access_token):

    filterTime = datetime.utcnow() - timedelta(hours = timeSpan)          
    filterTime = filterTime.strftime("%Y-%m-%dT%H:%M:%SZ")

    request_url = msCloud + "/api/alerts?$filter=alertCreationTime+ge+{}".format(filterTime) + "&$expand=evidence"

    headers = {
        'Content-Type' : 'application/json',
        'Accept' : 'application/json',
        'Authorization' : "Bearer " + access_token
    }

    response = requests.get(url=request_url, headers=headers)

    if response.status_code != 200:
        print("Unable to query security alerts: " + response.content.decode("utf-8"))
        return ''
        
    return json.loads(response.content)
    
# https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/update-alert
def msDefenderEnrichAlert(access_token, evidence, alert_id, score, detection, threatname, analysisid):

    comment = "Joe Sandbox Analysis:\n\n"
    comment += "Evidence: " + evidence + "\n"
    comment += "Detection: %s\n" % detection.upper()
    comment += "Score: %s\n" % score
    comment += "Threat Name: %s\n" % threatname
    comment += "Analysis Url: " + jbxCloud[0:-3] + "/analysis/%s\n\n" % analysisid

    print(comment)

    request_data = {"comment": comment}

    request_url = msCloud + "/api/alerts/%s" % alert_id
    
    headers = {
        'Authorization' : "Bearer " + access_token,
        'Content-Type' : 'application/json'
    }

    response = requests.patch(request_url, data=json.dumps(request_data), headers=headers)

    if response.status_code != 200:
        print("Failed to update alert: " + alert_id + " " + response.content.decode("utf-8"))
    else:
        print("Successfully encriched alert: %s with Joe Sandbox analysis %s" % (alert_id, analysisid))
        

def searchJBX(q):
    body = {
        'apikey' : jbxAPIKey,
        'q' : q,
    }
    
    response = requests.post(url=jbxCloud + "/v2/analysis/search", data=body)
    
    if response.status_code != 200:
        print("Unable to query Joe Sandbox: " + response.content.decode("utf-8"))
        return ''
    
    return json.loads(response.content)
    
    
def main():

    print("Synchronizing Defender alerts with %s" % jbxCloud[0:-3])

    access_token = msOath2Login()
    
    if len(access_token) == 0:
        return

    alerts = msDefenderGetAlerts(access_token)

    evidences = {}

    for alert in alerts["value"]:
    
        alert_id = alert["id"]
        isEnriched = False
    
        for comment in alert["comments"]:
            if comment["comment"].find("Joe Sandbox Analysis") != -1:
                isEnriched = True
                
        if isEnriched:
            print("Skipping alert %s, already enriched" % alert_id)
            continue
    
        for evidence in alert["evidence"]:
            if evidence["entityType"] == "File" or evidence["entityType"] == "URL":
                sha256 = evidence["sha256"]
                 
                if sha256 in evidences:
                    evidences[sha256].append(alert_id)
                else:
                    evidences[sha256] = [alert_id]
   
    for evidence in evidences:
        for alert_id in evidences[evidence]:
            score = 0
            tags = []
            threatname = ""
            detection = ""
            analysisid = ""
            results = searchJBX(evidence)
            # Search the analysis with the highest score
            for analysis in results["data"]:
                if score < analysis["score"]:
                    score = analysis["score"]
                    detection = analysis["detection"]
                    threatname = analysis["threatname"]
                    analysisid = analysis["analysisid"]
                
            msDefenderEnrichAlert(access_token, evidence, alert_id, score, detection, threatname, analysisid)


if __name__ == "__main__":
    main()
    