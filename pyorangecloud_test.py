# Copyright (C) 2014 Orange
#
# This software is distributed under the terms and conditions of the 'Apache-2.0'
# license which can be found in the file 'LICENSE.txt' in this package distribution or
# at 'http://www.apache.org/licenses/LICENSE-2.0'.
#

from pyorangecloud import OrangeCloudClient

### BEGIN OF CONFIGURATION

CLIENT_ID = '12345678901234567890123456789012' ## replace this by your clientId
CLIENT_SECRET = 'ABCDEFGHIJKLMNO' ## replace this by your client secret
REDIRECT_URI = 'http://my-host/my-receive-permission-path' ## replace this by redirectUri

### Additional configuration: You may want to change this
PROXIES = None ## { 'http':'...','https':'...'}
DEBUG_FLAGS_DEFAULT = pyorangecloud.DEBUG_FLAGS_DEFAULT ## -> "","H","C" or "HC" (H: http data, C: this module)
TOKEN_STORAGE_DEFAULT = pyorangecloud.TOKEN_STORAGE_DEFAULT  ## default is CURRDIR
PATHS_STORAGE_DEFAULT = pyorangecloud.PATHS_STORAGE_DEFAULT  ## default is CURRDIR
DEBUG_FLAGS = '' #'HC'
AUTH_CODE = '' ## Provide the user auth code

## END OF CONFIGURATION


## Instantiates the client. 
## To see http traces, pass debugFlags='H', for other traces: debugFlags='C', for both: debugFlags='HC'
## To change default location of token persistence, pass tokenStorage='/my/token/storage/location'
app = {'clientId': CLIENT_ID, 'clientSecret': CLIENT_SECRET, 'redirectUri' : REDIRECT_URI}
client = OrangeCloudClient(app,authCode=AUTH_CODE,proxies=PROXIES,debugFlags=DEBUG_FLAGS)

## Calls and displays freespace
print("My available space is: %s" % client.freespace())

## Displays a detailed folder listing calling listFolder and getFileInfo
print("Default folder listing ...")
folderInfo = client.listFolder()
for d in folderInfo['subfolders']:
    print (d['name'])
files = folderInfo['files']
for f in files:
    details = client.getFileInfo(f['id'])
    print ("%(name)s: type:%(type)s size:%(size)s" % details)

## uploads a simple text file, then deletes it
filenames = [f['name'] for f in files]
testfilename = "MyTest2.txt"
if not testfilename in filenames:
    print ("uploading file '%s' in my default directory" % testfilename)
    newFileId = client.uploadFile(testfilename,folderInfo['id'],"This is my content...","text/plain")
    print ("new file uploaded, has id:%s" % newFileId)
    client.deleteFile(newFileId)
    print ("file deleted")
