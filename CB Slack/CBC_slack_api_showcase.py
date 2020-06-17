import json
import sys
from cbapi.psc.defense import *
import time
import requests
import os
import slack

###### Creds #######

# Input your cbapi profile here - make sure the connector type is 'SIEM'
cb = CbDefenseAPI(profile="<SIEM PROFILE>")

# Input in your Slack Token, which ideally is stored as an environmental variable
slack_token = os.environ['SLACK_TOKEN']

# Generates Slack Webclient, based on above token, for inital block-chain posting of alert
sc = slack.WebClient(slack_token)


###### Variables ######

# Specify the channel you would like alerts to be sent to (create channel for cb_alerts if not)
channel = "cb_alerts"

# This is the webhook associated with your Slack Bot, to post the actions in response to the alert content
webhook = '<SLACK BOT WEBHOOK URL>'

# This is the CBC base url for reformatting for the 'Investigate' button. Please change 'prod05' to whatever url your org is on (prod05 is the most common)
url_base = 'https://defense-prod05.conferdeploy.net/alerts?s[dataGrouping]=NO_GROUP_RESULTS&s[highlight]=true&s[searchWindow]=ALL&s[maxRows]=20&s[fromRow]=1&s[sortDefinition][fieldName]=FIRST_ACTIVITY&s[sortDefinition][sortOrder]=DESC&s[c][THREAT_SCORE][0]=1&s[c][TARGET_PRIORITY][0]=LOW&s[c][TARGET_PRIORITY][1]=MEDIUM&s[c][TARGET_PRIORITY][2]=HIGH&s[c][TARGET_PRIORITY][3]=MISSION_CRITICAL&s[c][SEVERITY][0]=WARNING&s[c][SEVERITY][1]=NOTICE&s[c]'

###### Primary Function ######

def main():


    #Get alerts from the PSC via cbapi notification listener
    while True:

        for notification in cb.notification_listener():

            #write alert output
            with open('alert.json', 'w+') as a1:
                notify = (json.dumps(notification, indent=4, sort_keys=True))
                a1.write('')
                a1.write(notify)
                print (notify)
                print ('dump completed')
                a1.close()



            #parse alert output for slack app
            with open('alert.json') as a:
                data = json.load(a)

                #determine if it is a CbD Alert if 'threatInfo' in alert
                if 'threatInfo' in data:

                    #compile url for investigate
                    incidId = data['threatInfo']['incidentId']
                    url_incident = '[INCIDENT_ID][0]={}&s[c][DISMISSED][0]=true&s[c][DISMISSED][1]=false'.format(incidId)
                    url = url_base + url_incident

                    #compile info for notification post+go live
                    deviceId = data['deviceInfo']['deviceId']
                    device = data['deviceInfo']['deviceName']
                    score = data['threatInfo']['score']
                    description = data['threatInfo']['summary']

                    #compile url for vt lookup
                    actorHash = data['threatInfo']['threatCause']['actor']
                    vt_url = 'https://www.virustotal.com/en/file/{}/analysis/'.format(actorHash)

                    #compile URL for Go Live
                    lr_url_base = 'https://defense-prod05.conferdeploy.net/live-response/{}'.format(deviceId)


                    #convert epoch time to local time for alert
                    sec = data['eventTime']
                    epoch = str(sec)[0:(len(str(sec))-3)]
                    adj_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(epoch)))



                    #generate emoji for alert based on severity
                    score_emoji = []

                    if score > 0:
                        score_emoji = ':hugging_face:'

                    if score > 2:
                        score_emoji = ':thinking_face:'

                    if score > 4:
                        score_emoji = ':fearful:'

                    if score > 6:
                        score_emoji = ':poop:'

                    if score > 8:
                        score_emoji = ':skull_and_crossbones: :skull_and_crossbones: :skull_and_crossbones:'

                    a.close()

                    #post CbD alert to slack
                    sc.chat_postMessage(
                        channel = channel,
                        blocks=[
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*You have a new PSC alert:*\n_*<{}|Alert ID: {}>*_".format(url, incidId)
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*Alert Severity:*\n_{}_ {} \n*Device:*\n_{}_\n*When:*\n_{}_\n*Comments:*\n \"_{}_\"".format(score,str(score_emoji), device, adj_time, description)
                                },
                                "accessory": {
                                    "type": "image",
                                    "image_url": "https://chiefit.me/wp-content/uploads/2019/11/VMware-Carbon-Black835x396.jpg",
                                    "alt_text": "cb oldschool"
                                }
                            },

                        ]

                    )

                    #Generate slack bot response to above post for actions to take
                    requests.post(url= webhook,
                                        json={
                                            "text": "Would you like to investigate or take action on the above?",
                                            "attachments": [
                                                {
                                                    "text": "Choose an action to take",
                                                    "fallback": "You are unable to take further action",
                                                    "callback_id": "psc_actions",
                                                    "color": "#3AA3E3",
                                                    "attachment_type": "default",
                                                    "actions": [
                                                        {
                                                            "name": "action",
                                                            "text": "Investigate",
                                                            "type": "button",
                                                            "value": "investigate",
                                                            "url": url
                                                        },
                                                        {
                                                            "name": "action",
                                                            "text": "Virus Total Lookup",
                                                            "type": "button",
                                                            "value": "vt check",
                                                            "url": vt_url
                                                        },
                                                        {
                                                            "name": "action",
                                                            "text": "Go Live",
                                                            "style": "danger",
                                                            "type": "button",
                                                            "value": "go live",
                                                            "confirm": {
                                                                "title": "Are you sure?",
                                                                "text": "Proceed with Go Live prior to investigate?",
                                                                "ok_text": "Yes",
                                                                "dismiss_text": "No"
                                                                },
                                                            "url": lr_url_base
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    )

                #if not CbD alert, assume CbTH alert
                else:
                    #compile url for investigate
                    TH_incidId = data['threatHunterInfo']['incidentId']
                    url_incident = '[INCIDENT_ID][0]={}&s[c][DISMISSED][0]=true&s[c][DISMISSED][1]=false'.format(TH_incidId)
                    url = url_base + url_incident


                    #compile info for notification post+go live
                    TH_deviceId = data['deviceInfo']['deviceId']
                    device = data['deviceInfo']['deviceName']
                    TH_score = data['threatHunterInfo']['score']
                    TH_report = data['threatHunterInfo']['reportName']
                    TH_description =  data['threatHunterInfo']['threatCause']['reason']

                    #compile url for vt lookup
                    TH_actorHash = data['threatHunterInfo']['threatCause']['actor']
                    vt_url = 'https://www.virustotal.com/en/file/{}/analysis/'.format(TH_actorHash)

                    #compile URL for Go Live
                    lr_url_base = 'https://defense-prod05.conferdeploy.net/live-response/{}'.format(TH_deviceId)


                    #convert epoch time to local time for alert
                    sec = data['eventTime']
                    epoch = str(sec)[0:(len(str(sec))-3)]
                    adj_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(epoch)))




                    #generate emoji for alert based on severity
                    TH_score_emoji = []

                    if TH_score > 0:
                        TH_score_emoji = ':hugging_face:'

                    if TH_score > 2:
                        TH_score_emoji = ':thinking_face:'

                    if TH_score > 4:
                        TH_score_emoji = ':fearful:'

                    if TH_score > 6:
                        TH_score_emoji = ':poop:'

                    if TH_score > 8:
                        TH_score_emoji = ':skull_and_crossbones: :skull_and_crossbones: :skull_and_crossbones:'

                    a.close()

                    #post CbD alert to slack
                    sc.chat_postMessage(
                        channel = channel,
                        blocks=[
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*You have a new PSC alert:*\n_*<{}|Alert ID: {}>*_".format(url, TH_incidId)
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": "*Alert Severity:*\n_{}_ {} \n*Device:*\n_{}_\n*When:*\n_{}_\n*Report Name:*\n \"_{}_\n*Description:*\n_{}_".format(TH_score,str(TH_score_emoji), device, adj_time, TH_report, TH_description)
                                },
                                "accessory": {
                                    "type": "image",
                                    "image_url": "https://chiefit.me/wp-content/uploads/2019/11/VMware-Carbon-Black835x396.jpg",
                                    "alt_text": "cb oldschool"
                                }
                            },

                        ]

                    )

                    #Generate slack bot response to above post for actions to take
                    requests.post(url= webhook,
                                        json={
                                            "text": "Would you like to investigate or take action on the above?",
                                            "attachments": [
                                                {
                                                    "text": "Choose an action to take",
                                                    "fallback": "You are unable to take further action",
                                                    "callback_id": "psc_actions",
                                                    "color": "#3AA3E3",
                                                    "attachment_type": "default",
                                                    "actions": [
                                                        {
                                                            "name": "action",
                                                            "text": "Investigate",
                                                            "type": "button",
                                                            "value": "investigate",
                                                            "url": url
                                                        },
                                                        {
                                                            "name": "action",
                                                            "text": "Virus Total Lookup",
                                                            "type": "button",
                                                            "value": "vt check",
                                                            "url": vt_url
                                                        },
                                                        {
                                                            "name": "action",
                                                            "text": "Go Live",
                                                            "style": "danger",
                                                            "type": "button",
                                                            "value": "go live",
                                                            "confirm": {
                                                                "title": "Are you sure?",
                                                                "text": "Proceed with Go Live prior to investigate?",
                                                                "ok_text": "Yes",
                                                                "dismiss_text": "No"
                                                                },
                                                            "url": lr_url_base
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    )

if __name__ == "__main__":
    sys.exit(main())
