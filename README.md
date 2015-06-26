# PREREQUISITES

* Ensure you have registered to Orange Partners and obtained your API usage parameters (client id, client secret and redirect uri) to use
 the Orange Cloud API  (see https://www.orangepartner.com/)
* Ensure you have a user account on http://le-cloud.orange.fr and that you have accepted the terms and conditions of this service.
* Check user consent retrieval works for your account. To this end use the url (replacing brackets content):
https://api.orange.com/oauth/v2/authorize?prompt=login%20consent&state=orangecloud&redirect_uri=[http:/your/redirect/uri]&response_type=code&client_id=[yourclientid]&scope=openid%20cloud.

# INSTALLING

Go to directory of the distribution and run 'python setup.py install'. 
This will copy pyorangecloud.py to your python site so that it is permanently available. 
Since it is a simple python module you may alternatively copy to your work directory
and use it without installation. 
Also if not already installed, install the third party "requests" python module (under Apache-2.0 license)
(see http://docs.python-requests.org)

# QUICK TEST

Open the pyorangecloud_launcher.py in your favorite editor, and edit the configuration
variables CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, and if needed edit PROXIES, 
TOKEN_STORAGE_DEFAULT and PATHS_STORAGE_DEFAULT.
Ensure you have a user account on Orange Cloud and that as a user you have accepted terms and conditions
Ensure you have just obtained a fresh authorization code from a user 

Then launch:
* python pyorangecloud_launcher.py -c {userAuthCode} freeservice
    This will display user free space.
* python pyorangecloud_launcher.py -c {userAuthCode} listFolder
    This will display user root directory
Pass -d H to get http traces, pass -h to get the list of all commands

# USAGE DOCUMENTATION 

See the included html file pyorangecloud_doc.html or visit doc provided online.

# LICENSE
The sofware is licensed under Apache-2.0 terms.
See the file "LICENSE.txt" for a copy of licensing info.

Have fun!


