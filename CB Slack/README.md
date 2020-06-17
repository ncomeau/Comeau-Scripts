# CBC Slack App

## Instructions
​
### 1. Configure CbAPI  
 * Instructions here: https://cbapi.readthedocs.io/en/latest/installation.html
 * Download associated [CB+Slack python script]().
​
### 2. In the Carbon Black Cloud Console, create a CBC API Key
 * Navigate in CBC Console to **Settings > API Keys > Add API Key**
   * Create API Key with `‘Access Level’` SIEM
   * Copy Keys Created for Configuration:
      * API ID (Connector ID)
      * API Secret Key (API Key)
​
### 3. Create CBC Notification
 * Navigate in CBC Console to **Settings > Notifications > Add Notification**
 * Set-up desired notification
 * Under “How do you want to be notified?” Select SIEM connector made in step 1, under API Keys
​
### 4. Configure API Credentials File
 * Open Terminal or Command and cd to CbAPI directory
 * cbapi-defense configure
    * Enter Hostname: Copy CbPSC URL i.e. https://defense-prod05.conferdeploy.net/ (See the [Authentication Guide]({{< relref "reference/carbon-black-cloud/authentication.md#constructing-your-request" >}}) for guidance)
    * Enter Connector ID (Now called API ID)
    * Enter API Key (Now called API Secret Key)
 * Once configured change extension from `credentials.defense` to `credentials.psc`
 * VI into `credentials.psc` to identify the ‘profile’ name (in brackets above the api keys) – you might not have to do this with the updated Cbapi, please check.
 * Adjust line 12 of CB+Slack py script with the correct ‘profile’ name
​
### 5. In Slack, Create a new workspace (skip if you have already done this)
 * Create Channel titled ‘cb_alerts’
  * If Channel name is different than ‘cb_alerts’ adjust line 24 of CB+Slack py script
​
### 6. Install slack python client:
 * https://python-slackclient.readthedocs.io/en/latest/
 * Generate API Token:
   * https://api.slack.com/custom-integrations/legacy-tokens
   * Save this API Token as an environmental variable (tutorial link below):
      * Windows: https://www.youtube.com/watch?v=IolxqkL7cD8
      * Mac & Linux: https://www.youtube.com/watch?v=5iWhQWVXosU
   * Enter Slack API environmental variable to line 15 of CB+Slack py script
​
### 7. Creating SLACK App for Carbon Black Cloud Integration
 * Select Workspace (far left of Slack Desktop)  
 * Select ‘Customize Slack’
 * In Left Nav. Panel select ‘API’
 * Select ‘Start Building’
 * Create an App  
    * ENTER App Name: <example PSC Alerts>
    * ENTER Dev. Slack Workspace
    * Select ‘Create App’
​
### 8. Customize SLACK App
 * Select the App you just created
 * Select “Basic Information”  
 * “Add Features and Functionality”  
   * Turn ON ‘Incoming Webhooks’  
   * Select ‘Add New Webhook to Workspace’  
      * Select Channel of ‘cb_alerts’  
   * Copy Webhook URL to line 27 of CB+Slack py script
​
### 9. Repeat 8b Select "Basic Information" and 8cc Select Channel ‘Bots’
 * Add Bot User
​
### 10. Add newly created all to your workspace (if not already)
​
Now run the script!
​
The Cb notification listener will check every 30 seconds to see if a new alert has been generated — if so it will post it right within slack, and the bot will carry out the suggested actions.
