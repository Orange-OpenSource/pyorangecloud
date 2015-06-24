# Copyright (C) 2014 Orange
#
# This software is distributed under the terms and conditions of the 'Apache-2.0'
# license which can be found in the file 'LICENSE.txt' in this package distribution or
# at 'http://www.apache.org/licenses/LICENSE-2.0'.
#
"""
The pyorangecloud module is a python encapsulation to the Orange Cloud API 
(http://doc-api.orangeadd.com/gettingstarted/cloud.html)
It gives straighforward access to all operations of the API, hiding complexity of token and session.
The basic operations are: freespace, listFolder, createFolder, getFileInfo, downloadFile, uploadFile, deleteFile.
Additional helper operations are: listAllFolders, listAllFiles (recursive inspection) and resolvePath 
(display file/folder paths versus file/folder ids).
"""

import os,urllib,base64,json,mimetypes,urlparse,urllib2,unicodedata,logging,time

## This module depends on Apache2 licensed requests library (see http://docs.python-requests.org)
import requests

DEBUG_FLAGS_DEFAULT = '' ## possible values: '' -> no debug at all, 'H' -> http debug, 'C' -> client debug, 'HC' -> http and client debug
## default directory for token and session persistent storage.  
## If None no storage is done, if CURRDIR, storage is done in current directory 

TOKEN_STORAGE_DEFAULT = 'CURRDIR' 
PATHS_STORAGE_DEFAULT = 'CURRDIR'

DEBUG_DUMP_UPLOAD = False

class PyOrangeCloudError(Exception): pass
class PyOrangeCloudSessionExpired(PyOrangeCloudError): pass
class PyOrangeCloudTokenInvalid(PyOrangeCloudError): pass
class PyOrangeCloudForbiddenAccess(PyOrangeCloudError): pass
class PyOrangeCloudAuthorizationCodeInvalid(PyOrangeCloudError): pass
class PyOrangeCloudCguNotAccepted(PyOrangeCloudError): pass

class PyOrangeCloudTokenObsolete(PyOrangeCloudError): pass
class PyOrangeCloudUserConsentRequired(PyOrangeCloudError): pass


class OrangeCloudRawClient:

    def __init__(self,app,proxies=None,debugFlags=DEBUG_FLAGS_DEFAULT,rawOutput=False,logger=None):
        ## 
        self.app = app
        self.clientId = app.get('clientId')
        self.clientSecret = app.get('clientSecret')
        self.redirectUri = app.get('redirectUri')
        
        self.proxies = proxies
        self.base64clientinfo = base64.encodestring("%s:%s" % (self.clientId,self.clientSecret)).strip()
        self.rawOutput = rawOutput 
        self.debugFlags = debugFlags
        self.logger = self.initLogger(logger)
        ## if rawOutput is true, errors are not raised on failures but full request responses are returned
        ## otherwise errors are raised on failures and only functional result is returned

    ## internal methods

    def initLogger(self,logger=None):
        if not logger:
            logging.basicConfig(format='%(message)s')
            logger = logging.getLogger(__name__)
        debugFlags = self.debugFlags
        if debugFlags: 
            if "C" in debugFlags: 
                logger.setLevel(logging.DEBUG)
            if "H" in debugFlags: 
                import httplib as http_client
                http_client.HTTPConnection.debuglevel = 1
                #logger.setLevel(logging.DEBUG)                
                requests_logger = logging.getLogger("requests.packages.urllib3")
                requests_logger.setLevel(logging.DEBUG)
                requests_logger.propagate = True
        return logger

    def treatResponse(self,r,errkey='error',errtop=True):
        err,res = None,None
        if not r.content: ## this is not necessarily an error
            return err,res
        try: res = r.json()
        except ValueError as e:
            return {'text':r.text,'message':'Cannot parse output as json'},None
        if res.has_key(errkey):
            if errtop: ## the top object is the error object
                err = res; res = None
            else: ## the error object is nested
                err = res[errkey]; res = None
        return err,res

    def treatCloudResponse(self,r):
        return self.treatResponse(r,'error',False)

    def treatOAuthResponse(self,r):
        return self.treatResponse(r,'error',True)

    def loadFileData(self,filepath,filename='',mimetype=''):
        if not mimetype:
            mtype,menc = mimetypes.guess_type(filepath)
            if mtype: mimetype = mtype
        isurl = filepath.startswith('http://') or filepath.startswith('https://')
        if not filename:
            if isurl:
                parts = urlparse.urlparse(filepath)
                fpath = parts.path
                if fpath: filename = fpath.split("/")[-1]
            else:
                filename = os.path.split(filepath)[1]
        if type(filename)==type(u''):
            filename = unicode(unicodedata.normalize("NFKD",filename).encode("ascii", "ignore"))
        if isurl:
            proxy = urllib2.ProxyHandler(self.proxies)
            opener = urllib2.build_opener(proxy)
            request = urllib2.Request(filepath)
            f = opener.open(request)
            data = f.read()
            f.close()
        else:
            f = open(filepath, "rb")
            data = f.read()
            f.close()
        size = len(data)
        self.debug("Size of file to upload", size)
        return {'filename':filename,'mimetype':mimetype,'data':data,'size':size}


    def raiseError(self,mess,err,*argvals):
        errlabel = err.get('label')
        if errlabel == 'SESSION_EXPIRED': 
            raise PyOrangeCloudSessionExpired(mess,err,*argvals)
        elif errlabel == 'INVALID_TOKEN':
            raise PyOrangeCloudTokenInvalid(mess,err,*argvals)
        elif errlabel == 'FORBIDDEN_ACCESS':
            raise PyOrangeCloudForbiddenAccess(mess,err,*argvals)
        elif errlabel == 'CGU_NOT_ACCEPTED':
            raise PyOrangeCloudCguNotAccepted(mess,err,*argvals)
        else: 
            errcode = err.get('error')
            if errcode == 'invalid_grant':
                raise PyOrangeCloudAuthorizationCodeInvalid(mess,err,*argvals)
            message = err.get('message')
            if message == 'Invalid credentials': 
                raise PyOrangeCloudTokenInvalid(mess,err,*argvals)
            else: 
                raise PyOrangeCloudError(mess,err,*argvals)

    ## authentification methods

    def getAuthorizeUrl(self,prompt='login consent',state='orangecloud',scope='openid cloud'):
        ## return the url to call to retrieve explicit authorization from user
        ## if prompt=='none' is passed to none the invoked url will return an already valid code or an error
        baseurl = 'https://api.orange.com/oauth/v2/authorize'
        params = {'scope' : scope, 'prompt' : prompt, 'response_type' : 'code', 'state': state,
                  'client_id' : self.clientId,'redirect_uri' : self.redirectUri}
        return baseurl + "?" + urllib.urlencode(params).replace("+","%20")
        
    def checkAuthorizationCode(self,prompt='none',state='orangecloud-check',scope='openid cloud'):
        baseurl = 'https://api.orange.com/oauth/v2/authorize'
        params = {'scope' : scope, 'prompt' : prompt, 'response_type' : 'code', 'state': state,
                  'client_id' : self.clientId,'redirect_uri' : self.redirectUri}
        r = requests.get(baseurl,params=params,proxies=self.proxies)
        return r.content

    def retrieveTokenInfo(self,authCode):
        baseurl = 'https://api.orange.com/oauth/v2/token'
        headers = {'Authorization':'Basic '+self.base64clientinfo}
        dataparams = {'grant_type':'authorization_code','code':authCode,'redirect_uri':self.redirectUri}
        r = requests.post(baseurl,headers=headers,data=dataparams,proxies=self.proxies)
        err,res = self.treatOAuthResponse(r)
        if err: self.raiseError("CouldNotRetrieveToken",err)
        return res

    def retrieveSessionId(self,accessToken):
        baseurl = 'https://api.orange.com/cloud/v1/session'
        headers = {'Authorization':'Bearer '+accessToken}
        r = requests.post(baseurl,headers=headers,data=None,proxies=self.proxies)
        err,res = self.treatCloudResponse(r)
        if err: self.raiseError("CouldNotCreateSession",err)
        return res.get("esid","")

    ## service methods

    def listFolder(self,accessToken,sessionId,folderId=''):
        self.logger.info("listFolder: " + folderId)
        self.logger.debug("listFolder details: %s %s %s" % (accessToken,sessionId,folderId))
        baseurl = 'https://api.orange.com/cloud/v1/folders'
        if folderId is None or folderId=="/": folderId = "" ## means root
        headers = {'Authorization':'Bearer '+accessToken,
                   'X-Orange-CA-ESID':sessionId}
        url = baseurl + "/" + folderId
        r = requests.get(url,headers=headers,proxies=self.proxies)
        if self.rawOutput: return r
        err,res = self.treatCloudResponse(r)
        if err: self.raiseError("CouldNotListFolder",err,folderId)
        return res

    def createFolder(self,accessToken,sessionId,name,parentFolderId):
        baseurl = 'https://api.orange.com/cloud/v1/folders'
        headers = {'Authorization':'Bearer '+accessToken,
                   'X-Orange-CA-ESID':sessionId,
                   'Content-Type' : 'application/json'}
        data = {'name':name,'parentFolderId':parentFolderId}
        r = requests.post(baseurl,headers=headers,data=json.dumps(data),proxies=self.proxies)
        if self.rawOutput: return r
        err,res = self.treatCloudResponse(r)
        if err: self.raiseError("CouldNotCreateFolder",err,name)
        return res

    def deleteFolder(self,accessToken,sessionId,folderId):
        baseurl = 'https://api.orange.com/cloud/v1/folders'
        headers = {'Authorization':'Bearer '+accessToken,
                   'X-Orange-CA-ESID':sessionId}
        url = baseurl + "/" + folderId
        r = requests.delete(url,headers=headers,proxies=self.proxies)
        if self.rawOutput: return r
        err,res = self.treatCloudResponse(r)
        if err: self.raiseError("CouldNotDeleteFolder",err,folderId)
        return res

    def getFileInfo(self,accessToken,sessionId,fileId):
        baseurl = 'https://api.orange.com/cloud/v1/files'
        headers = {'Authorization':'Bearer '+accessToken,
                   'X-Orange-CA-ESID':sessionId}
        url = baseurl + "/" + fileId
        r = requests.get(url,headers=headers,proxies=self.proxies)
        if self.rawOutput: return r
        err,res = self.treatCloudResponse(r)
        if err: self.raiseError("CouldNotRetrieveFileInfo",err,fileId)
        return res

    def downloadFile(self,accessToken,sessionId,fileId,targetFile):
        fileInfo = None
        if fileId.startswith('https://'): 
            downloadUrl = fileId
        else:
            fileInfo = OrangeCloudRawClient.getFileInfo(self,accessToken,sessionId,fileId)
            downloadUrl = fileInfo.get('downloadUrl','')
        headers = {'Authorization':'Bearer '+accessToken,'X-Orange-CA-ESID':sessionId}
        if fileInfo and os.path.isdir(targetFile):
            targetFile = os.path.join(targetFile,fileInfo.get('name',''))
        with open(targetFile, 'wb') as handle:
            r = requests.get(downloadUrl,headers=headers,proxies=self.proxies,verify=False)
            if not r.ok: 
                r.raise_for_status()
            for block in r.iter_content(1024):
                if not block: break
                handle.write(block)
        return fileInfo



    def uploadFile(self,accessToken,sessionId,name,folderId,content,contentType=''):
        self.debug("uploadFile",(accessToken,sessionId,name,folderId,content,contentType))
        if content.startswith('@') and len(content)>1: 
            fileinfo = self.loadFileData(content[1:],filename=name)
            contentType = fileinfo.get('mimetype')
            size = fileinfo.get('size')
            if not name: name = fileinfo.get('filename')
            content = fileinfo.get('data')
        else:
            size = len(content)

        baseurl = 'https://cloudapi.orange.com/cloud/v1/files/content' ## note that host is not api.orange.com
        headers = {'Authorization':'Bearer '+accessToken,
                   'X-Orange-CA-ESID':sessionId,
                   'Content-Type': 'multipart/form-data;boundary=UploadBoundary'}
        bindata = bytearray('')
        bindata.extend('--UploadBoundary\r\n')
        bindata.extend('Content-Disposition: form-data; name="description"\r\n\r\n')
        argdict = {'name':name,'size':str(size),'folder':folderId}
        bindata.extend(json.dumps(argdict,ensure_ascii=True)+'\r\n')
        bindata.extend('--UploadBoundary\r\n')
        if type(name)==type(u''): xname = name.encode('utf-8')
        else: xname = name
        bindata.extend('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % xname)

        if contentType: bindata.extend('Content-Type: ' + str(contentType) + '\r\n')
        bindata.extend('\r\n')
        #self.debug("bindata", bindata + "..." + '--UploadBoundary--\r\n')
        bindata.extend(content)
        bindata.extend('--UploadBoundary--')
        if DEBUG_DUMP_UPLOAD: ## for DEBUG
            fcontentpath = os.path.join(os.getcwd(),"upload_file_content.dump")
            self.debug("Dumping upload content to",fcontentpath)
            f = open(fcontentpath,"wb")
            f.write(bindata)
            f.close()

        #self.debug("bindata", bindata)
        r = requests.post(baseurl,headers=headers,data=bindata,proxies=self.proxies,verify=False)
        if self.rawOutput: return r
        err,res = self.treatCloudResponse(r)
        if err: self.raiseError("CouldNotUploadFile",err,(name,folderId,contentType))
        return res.get('fileId','')


    def deleteFile(self,accessToken,sessionId,fileId):
        baseurl = 'https://api.orange.com/cloud/v1/files'
        headers = {'Authorization':'Bearer '+accessToken,
                   'X-Orange-CA-ESID':sessionId}
        url = baseurl + "/" + fileId
        r = requests.delete(url,headers=headers,proxies=self.proxies)
        if self.rawOutput: return r
        err,res = self.treatCloudResponse(r)
        if err: raise PyOrangeCloudError("CouldNotDeleteFile",fileId,err)
        return r

    def freespace(self,accessToken,sessionId):
        baseurl = 'https://api.orange.com/cloud/v1/freespace'
        headers = {'Authorization':'Bearer '+accessToken,
                   'X-Orange-CA-ESID':sessionId}
        r = requests.get(baseurl,headers=headers,proxies=self.proxies)
        err,res = self.treatCloudResponse(r)
        if self.rawOutput: return r
        if err: self.raiseError("CouldNotRetrieveFreeSpace",err)
        return res.get('freespace','')


class OrangeCloudClient(OrangeCloudRawClient):
    """This class is a python encapsulation to the Orange Cloud API (http://doc-api.orangeadd.com/gettingstarted/cloud.html)
    It gives straighforward access to all operations of the API, hiding complexity of token and session.
    The basic operations are: freespace, listFolder, createFolder, getFileInfo, downloadFile, uploadFile, deleteFile.
    Additional helper operations are: listAllFolders, listAllFiles (recursive inspection) and resolvePath 
    (display paths versus file/folder ids).
    This module depends on 'requests' module. 
    """
    
    def __init__(self,app,authCode='',accessToken='',sessionId='',proxies=None,
                 tokenStorage=TOKEN_STORAGE_DEFAULT,debugFlags=DEBUG_FLAGS_DEFAULT,logger=None,pathsStorage=PATHS_STORAGE_DEFAULT):
        """Constructor. Requires the application keys (client id, secret, redirect uri), as well as user consent
        information (the authorization code or the token).
        The tokenStorage parameter indicates a location for persistance of tokens (by default the current directory)
        Default persistence management can be skipped (tokenStorage to None) and replaced by programmer own function.
        The logger parameter is used to display HTTP request (debugFlags assigned to 'H').
        The proxies parameter allow to pass proxies for the HTTP requests.
        """
        OrangeCloudRawClient.__init__(self,app,proxies,debugFlags,False,logger=logger)
        self.authCode = authCode
        self.accessToken = accessToken
        self.sessionId = sessionId
        self.tokenStorage = tokenStorage
        self.pathsStorage = pathsStorage
        self.clientDebug = debugFlags and ("C" in debugFlags)
        self._sessionSolved = False
        self._tokenSolved = False
        self.storedAuthCode = ''
        self.pathsData = None ## memorizing resolved paths
        self.storedPaths = None

    ## internal methods

    def solveValidTokenIsMissing(self):
        if not self.authCode:
            raise PyOrangeCloudUserConsentRequired("User consent required to obtain access token","CONSENT_REQUIRED")
        try:
            self.debug("solveValidTokenIsMissing: calling retrieveTokenInfo")
            tokenInfo = self.retrieveTokenInfo(self.authCode)
            self._tokenSolved = True
        except:
            raise
        self.accessToken = tokenInfo.get('access_token','')
        self.debug("accessToken", self.accessToken)
        ## now retry to start a session, will raise error if fails
        self.debug("solveValidTokenIsMissing: calling retrieveSessionId")
        self.sessionId = self.retrieveSessionId(self.accessToken)
        self.debug("sessionId", self.sessionId)
        self._sessionSolved = True
        if self.tokenStorage: self.storePermissionInfo()

    def solveValidSessionIsMissing(self):
        try: ## first try to obtain a session 
            self.debug("solveValidSessionIsMissing: calling retrieveSessionId")
            self.sessionId = self.retrieveSessionId(self.accessToken)
            self.debug("sessionId", self.sessionId)
            self._sessionSolved = True
        except:
            self.solveValidTokenIsMissing()        
        if self.tokenStorage: self.storePermissionInfo()

    def trySolveTokenOrSession(self):
        result = False
        try:
            if not self._sessionSolved: ## avoids retrieving session more than once
                self.solveValidSessionIsMissing()
                result = True
            elif not self._tokenSolved: ## avoids retrieving token more than once
                self.solveValidTokenIsMissing()
                result = True
        except PyOrangeCloudError as e:
            self.debug("Could not solve Token Or Session",(type(e),e.args))
        self.debug("exiting trySolveTokenOrSession",result)
        return result

    def getTokenStorageDir(self):
        if self.tokenStorage == "CURRDIR": tokenStorageDir = os.getcwd()
        else: tokenStorageDir = os.path.realpath(self.tokenStorage)
        return tokenStorageDir

    def getTokenStorageFilePath(self,storageDir=None):
        if storageDir is None: storageDir = self.getTokenStorageDir()
        return os.path.join(storageDir,"pyorangecloud_session.txt")

    def retrieveStoredPermissionInfo(self,fpath=None):
        if fpath is None:
            storageDir = self.getTokenStorageDir()
            fpath = self.getTokenStorageFilePath(storageDir)
            if not os.path.isfile(fpath):
                if not os.path.isdir(storageDir):
                    raise PyOrangeCloudError("SessionDirShouldBeAnExistingDirectory",storageDir)
                return None
        f = open(fpath,"r")
        txt = f.read().strip()
        f.close()
        fields = txt.split()
        if len(fields)==1: authCode,accessToken,sessionId='',fields[0],''
        elif len(fields)==2: authCode,accessToken,sessionId='',fields[0],fields[1]
        else: authCode,accessToken,sessionId = fields[0],fields[1],fields[2]
        self.debug("retrieving %s %s from %s" % (accessToken,sessionId,fpath))
        return {'authCode':authCode,'accessToken':accessToken,'sessionId':sessionId}

    def storePermissionInfo(self,fpath=None):
        if fpath is None:
            storageDir = self.getTokenStorageDir()
            if not os.path.isdir(storageDir):
                raise PyOrangeCloudError("SessionDirShouldBeAnExistingDirectory",storageDir)
            fpath = self.getTokenStorageFilePath(storageDir)
        f = open(fpath,"w")
        authCode = self.authCode or self.storedAuthCode or 'null'
        f.write("%s\n%s\n%s" % (authCode,self.accessToken,self.sessionId))
        f.close()
        self.debug("storing %s %s at %s" % (self.accessToken,self.sessionId,fpath))
        return fpath


    def loadStoredPaths(self):
        if self.pathsStorage == "CURRDIR": pathsStorage = os.getcwd()
        else: pathsStorage = os.path.realpath(self.pathsStorage)
        fpath = os.path.join(pathsStorage,"pyorangecloud_paths.json")
        file_exists = os.path.isfile(fpath)
        if not file_exists:
            if not os.path.isdir(pathsStorage):
                raise PyOrangeCloudError("PathStorageDirShouldBeAnExistingDirectory",pathsStorage)
            return None
        self.debug("loading paths from '%s'" % fpath)
        f = open(fpath,'r')
        paths = json.load(f)
        return paths

    def storePaths(self,pathsData=None):
        if self.pathsStorage == "CURRDIR": pathsStorage = os.getcwd()
        else: pathsStorage = os.path.realpath(self.pathsStorage)
        if pathsData is None: pathsData = self.pathsData
        fpath = os.path.join(pathsStorage,"pyorangecloud_paths.json")
        f = open(fpath,"w")
        json.dump(pathsData,f,ensure_ascii=True)
        f.close()
        self.debug("storing paths at '%s'" % fpath)
        return fpath

    def dumpFolderPaths(self):
        self._listAllFolders(isTop=True)
        self.storePaths(self.pathsData)

    def dumpFilePaths(self):
        self._listAllFiles(isTop=True)
        self.storePaths(self.pathsData)

    def getStoredPaths(self):
        if not self.storedPaths is None: return self.storedPaths
        self.storedPaths = self.loadStoredPaths()
        return self.storedPaths

    # def initialize_OLD(self,authCode='',accessToken=''):
    #     self.debug("initialize")
    #     retrieved = False
    #     if self.authCode: 
    #         ## will ignore authCode if it is the same than the stored one to avoid duplicate use of auth code which will cause an error
    #         storedAuthCode,storedAccessToke,storedSessionId = self.retrieveStoredPermissionInfo()
    #         retrieved = True
    #         if self.authCode == storedAuthCode: self.authCode = ''

    #     if authCode: self.authCode = authCode
    #     if accessToken: self.accessToken = accessToken
    #     if not self.accessToken:
    #         ## if authCode is passed, previous stored token and sessions are ignored so that they can be recomputed
    #         if self.tokenStorage and not self.authCode: 
    #             if not retrieved:
    #                 self.storedAuthCode,self.accessToken,self.sessionId = self.retrieveStoredPermissionInfo()
    #             else: self.storedAuthCode,self.accessToken,self.sessionId = storedAuthCode,storedAccessToke,storedSessionId
    #             #self.debug("=> self.accessToken,self.sessionId :",(self.accessToken,self.sessionId))
    #         if not self.accessToken:
    #             self.solveValidTokenIsMissing()            
    #     if not self.sessionId:
    #         self.solveValidSessionIsMissing()

    def initialize(self,authCode='',accessToken=''):
        self.debug("initialize")
        retrieved = False

        xauthCode = authCode if authCode else self.authCode
        xaccessToken = accessToken if accessToken else self.accessToken
        xsessionId = self.sessionId


        ## The code below attempts automatic retrieval of stored authCode,accessToken and sessionId when necessary
        ## while ensuring (as much as possible) that the retrieved data is not obsolete
        ## Also for flexibility, allows the user to pass authCode more than once, while ensuring that it is not
        ## used more than one

        isObsolete = False ##  True if the passed authCode or accesToken is in fact obsolete

        if xauthCode:
            retrieved = True
            storedPermissionInfo = self.checkStoredPermissionInfo() if self.tokenStorage else None
            if storedPermissionInfo:
                storedIsObsolete = storedPermissionInfo.get('isObsolete',False)
                storedAuthCode = storedPermissionInfo.get('authCode','')
                if xauthCode == storedAuthCode: 
                    xauthCode = '' ## this means that we will ignore the code and use the access token instead
                    if storedIsObsolete: 
                        isObsolete = True
                        xaccessToken = ""
                    else:
                        self.storedAuthCode = xauthCode
                        if not xaccessToken: 
                            xaccessToken = storedPermissionInfo.get('accessToken','')
                            xsessionId = storedPermissionInfo.get('sessionId','')
                        elif not self.sessionId:
                            xsessionId = storedPermissionInfo.get('sessionId','')
                else: 
                    ## we will retrieve a new token with the new authCode (replacement)
                    xaccessToken = ''
            else: 
                ## we will retrieve a new token using authCode (accessToken ignored)
                xaccessToken = ''
        else:
            if not xaccessToken:
                storedPermissionInfo = self.checkStoredPermissionInfo() if self.tokenStorage else None
                if storedPermissionInfo:
                    storedIsObsolete = storedPermissionInfo.get('isObsolete',False)
                    if storedIsObsolete:
                        isObsolete = True
                    else: 
                        self.storedAuthCode = xauthCode
                        xaccessToken = storedPermissionInfo.get('accessToken','')
                        xsessionId = storedPermissionInfo.get('sessionId','')
                else: pass
                    
            
        ## now we reassign instance variables
        self.authCode,self.accessToken,self.sessionId = xauthCode,xaccessToken,xsessionId
        if isObsolete:
            ## not need to attempt call, just raises an error
            raise PyOrangeCloudTokenObsolete("Obsolete Access Token, should ask again user consent","OBSOLETE_TOKEN")

        if not self.accessToken:
            self.solveValidTokenIsMissing()
        if not self.sessionId:
            self.solveValidSessionIsMissing()
        self.authCode = '' ## enforced to avoid double usage and to optimize next call of initialize()


    def rawCall(self,opname,*arglist):
        try:
            method = getattr(OrangeCloudRawClient,opname,None)
            self.debug("Calling", (opname, arglist))
            res = method(self,self.accessToken,self.sessionId,*arglist)
        except (PyOrangeCloudTokenInvalid,PyOrangeCloudSessionExpired,PyOrangeCloudForbiddenAccess) as e:
            self.debug("First call failed, trying solution",type(e))
            if self.trySolveTokenOrSession():
                self.debug("Attempting second Call", (opname, arglist))
                res = method(self,self.accessToken,self.sessionId,*arglist)
                self.debug("Second call done")
            else: 
                self.debug("Raising again")
                raise
        except:
            self.debug("First call failed")
            raise
        return res

    def debug(self,mess,var=None):
        if self.clientDebug: 
            if not var is None: self.logger.debug("%s: %s" % (mess,var))
            else: self.logger.debug(mess)
                
    ## retrieval of stored token and session

    def getAccessToken(self,authCode=''):
        self.initialize(authCode)
        return self.accessToken

    def getSessionId(self,accessToken=''):
        self.initialize('',accessToken)
        return self.sessionId

    def checkStoredPermissionInfo(self,forceReset=False,removeObsolete=True):
        fpath = self.getTokenStorageFilePath()
        if not os.path.isfile(fpath): return None
        if forceReset: os.remove(fpath); return None
        permissionInfo = self.retrieveStoredPermissionInfo(fpath)
        ## removes if obsolete
        mtime = os.stat(fpath).st_mtime
        actualtime = time.time()
        tokenDuration = 3600 ## TODO: This may change
        if actualtime-mtime>3600:
            permissionInfo['isObsolete'] = True
            self.debug("Removing obsolete permission info file",fpath)
            if removeObsolete: os.remove(fpath)
        return permissionInfo

    # def resetObsoleteStoredTokenInfo(self,forceReset=False): ## resets if obsolete
    #     ## internal method to update the stored token if obsolete
    #     fpath = os.path.join(tokenStorage,"pyorangecloud_session.txt")
    #     if not os.path.isfile(fpath): 
    #         return
    #     if forceReset: os.remove(fpath); return None
    #     mtime = os.stat(fpath)
    #     tokenDuration = 3600 ## TODO: This may change
    #     if mtime-actualtime>3600:
    #         os.remove(fpath)

    ## service methods

    def listFolder(self,folderId=''):
        'Lists files and sub-folders of the given folder, (of the root folder if not provided)'
        self.initialize()
        if folderId.startswith('@'): folderId = self.resolvePath(folderId,isFolder=True)
        return self.rawCall('listFolder',folderId)                

    def createFolder(self,name,parentFolderId):
        'Creates a new sub-folder of the given parent folder'
        self.initialize()
        if parentFolderId.startswith('@'): parentFolderId = self.resolvePath(parentFolderId,isFolder=True)
        return self.rawCall('createFolder',name,parentFolderId)

    def deleteFolder(self,folderId):
        'Deletes a given folder'
        self.initialize()
        if folderId.startswith('@'): folderId = self.resolvePath(folderId,isFolder=True)
        return self.rawCall('deleteFolder',folderId)

    def getFileInfo(self,fileId):
        'Retrieves information on a file'
        self.initialize()
        if fileId.startswith('@'): fileId = self.resolvePath(fileId)
        return self.rawCall('getFileInfo',fileId)

    def downloadFile(self,fileId,targetFile):
        'Downloads a file, copying content into a local file given by its file path'
        self.initialize()
        if fileId.startswith('@'): fileId = self.resolvePath(fileId)
        return self.rawCall('downloadFile',fileId,targetFile)

    def uploadFile(self,name,folderId,content,contentType=''):
        'Uploads a given local content and creates a file. Uses @filepath convention to retrieve content from a file'
        self.initialize()
        if folderId.startswith('@'): folderId = self.resolvePath(folderId)
        return self.rawCall('uploadFile',name,folderId,content,contentType)

    def deleteFile(self,fileId):
        'Deletes a given local file'
        self.initialize()
        if fileId.startswith('@'): fileId = self.resolvePath(fileId)
        return self.rawCall('deleteFile',fileId)

    def freespace(self):
        'Retrieves the available space of the user'
        self.initialize()
        return self.rawCall('freespace')

    def listAllFolders(self,folderId='',topPath=''):
        'List a given folder and all subfolders recursively'
        if folderId.startswith('@'): folderId = self.resolvePath(folderId)
        return self._listAllFolders(folderId,topPath,True)

    def listAllFiles(self,folderId='',topPath='',withDetails=False):
        'List all folders and files recursively'
        if folderId.startswith('@'): folderId = self.resolvePath(folderId)
        return self._listAllFiles(folderId,topPath,withDetails,True)

    def resolvePath(self,path,topPath='',isFolder=False):
        path = path.replace('@','') ## path should not contain @ character
        ident = self._resolvePath(path,topPath,isFolder)
        if not ident:
            self.debug("cannot resolve path '%s' (isFolder:%s)" % (path,isFolder),self.pathsData)
            raise PyOrangeCloudError("UnknownFolderOrFilePathInUserCloud",path)
        return ident

    def _resolvePath(self,path,topPath='',isFolder=False):
        'Returns the file or folder if of a given path'
        ## normalizes the path
        self.debug("_resolvePath path:",(path,isFolder))

        if topPath and not path.startswith('/'): path=topPath+"/"+path

        if len(path)>1 and path.endswith('/'): path = path[:-1]
        self.debug("_resolvePath normalized path:",path)
        ## possibly loading paths for all folders
        if self.pathsData is None: 
            parentid = ''
            if self.pathsStorage and self.pathsStorage.lower()!='none':
                storedPaths = self.getStoredPaths()
                if storedPaths:
                    self.debug("_resolvePath: retrieving storedPaths",storedPaths)
                    ident = storedPaths.get(path)
                    if ident:
                        self.debug("_resolvePath: found in storedPaths",ident)
                        return ident
                    ## try parentpath if it is a file path
                    if not isFolder:
                        pos = path.rfind('/')
                        if pos!=-1: 
                            parentpath,fname = path[:pos],path[pos+1:]
                            parentid = storedPaths.get(parentpath)
                            if parentid: self.pathsData = storedPaths
            ## always inspect folders unless for files with parent folder not available
            if not parentid:
                self._listAllFolders(isTop=True) ## this updates self.pathData
                self.debug("_resolvePath self.pathsData",self.pathsData)
        ## returning stored path if available
        ident = self.pathsData.get(path)
        if ident: return ident
        ## do not attempt more if a folder is requested
        if isFolder: return None
        self.debug("_resolvePath 1")
        ## otherwise trying to obtain listing the parent folder 
        if path=='/': return None
        pos = path.rfind('/')
        if pos==-1: 
            self.debug("_resolvePath 2")
            
            return None
        parentpath,fname = path[:pos],path[pos+1:]
        parentid = self.resolvePath(parentpath)
        if not parentid: 
            self.debug("_resolvePath 3 KO")
            return None
        self.debug("_resolvePath 3 OK parentid",parentid)
        folderInfo = self.listFolder(parentid)
        if not folderInfo: 
            self.debug("_resolvePath 4")
            return None
        found = None
        self.debug("_resolvePath 5",folderInfo)
        if self.pathsData is None: self.pathsData = {}
        for f in folderInfo['files']:
            xname = f['name']
            xid = f['id']
            if xname == fname:
                self.pathsData[parentpath+'/'+xname] = xid
                found = xid
        self.debug("_resolvePath END",found)
        return found

    ## internal recursive operations

    def _listAllFolders(self,folderId='',topPath='',isTop=False,res=None):
        if self.pathsData is None: self.pathsData = {}
        if res is None: res = []
        folderInfo = self.listFolder(folderId)
        folderPath = topPath
        if isTop: ## root
            if not folderId: folderId = folderInfo['id']
            topName = folderInfo['name']
            topFolder = {'id':folderId,'name':topName}
            if not folderPath: folderPath = topName
            else:
                if folderPath.endswith('/'): folderPath += topName
                else: folderPath += '/' + topName
            topFolder['path'] = folderPath
            self.pathsData[folderPath] = folderId
            #raise Exception("Coucou",self.pathsData)
            res.append(topFolder)
        subFolders = folderInfo.get('subfolders',())
        for sub in subFolders:
            subId = sub.get('id')
            subPath = folderPath + '/' + sub.get('name')
            sub['path'] = subPath
            self.pathsData[subPath] = subId
            res.append(sub)
            self._listAllFolders(sub.get('id'),subPath,False,res)
        return res

    def _listAllFiles(self,folderId='',topPath='',withDetails=False,isTop=False,res=None):
        if self.pathsData is None: self.pathsData = {}
        if res is None: res = []
        folderInfo = self.listFolder(folderId)
        folderPath = topPath
        #self.debug("folderPath 1",folderPath)
        if isTop: ## root
            if not folderId: folderId = folderInfo['id']
            topName = folderInfo['name']
            topFolder = {'id':folderId,'name':topName}
            if not folderPath: folderPath = topName
            else:
                if folderPath.endswith('/'): folderPath += topName
                else: folderPath += '/' + topName
            topFolder['path'] = folderPath
            self.pathsData[folderPath] = folderId
            res.append(topFolder)
        subFolders = folderInfo.get('subfolders',())
        #self.debug("folderPath 2",folderPath)
        for sub in subFolders:
            subId = sub.get('id')
            subPath = folderPath + '/' + sub.get('name')
            self.pathsData[subPath] = subId
            sub['path'] = subPath
            res.append(sub)
            self._listAllFiles(sub.get('id'),subPath,withDetails,False,res)
        files = folderInfo.get('files',())
        for f in files:
            fileId = f.get('id')
            filePath = folderPath + '/' + f.get('name')
            if withDetails:
                f = self.getFileInfo(fileId)
            f['path'] = filePath
            res.append(f)
        return res


