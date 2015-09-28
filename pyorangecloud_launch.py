# Copyright (C) 2014 Orange
#
# This software is distributed under the terms and conditions of the 'Apache-2.0'
# license which can be found in the file 'LICENSE.txt' in this package distribution or
# at 'http://www.apache.org/licenses/LICENSE-2.0'.
#
"""
The pyorangecloud_launch module is a command line launcher for testing the pyorangecloud module.
(see pyorangecloud documentation for more information)
Example of use: python pyorangecloud_launcher.py freespace
To get some usage help: python pyorangecloud_launcher.py -h
"""

import sys,argparse
import pyorangecloud

### BEGIN OF CONFIGURATION

CLIENT_ID = '12345678901234567890123456789012' ## replace this by your clientId
CLIENT_SECRET = 'ABCDEFGHIJKLMNO' ## replace this by your client secret
REDIRECT_URI = 'http://my-host/my-receive-permission-path' ## replace this by redirectUri


### Additional configuration: You may want to change this
PROXIES = None ## { 'http':'...','https':'...'}
DEBUG_FLAGS_DEFAULT = pyorangecloud.DEBUG_FLAGS_DEFAULT ## -> "","H","C" or "HC" (H: http data, C: this module)
TOKEN_STORAGE_DEFAULT = pyorangecloud.TOKEN_STORAGE_DEFAULT  ## default is CURRDIR
PATHS_STORAGE_DEFAULT = pyorangecloud.PATHS_STORAGE_DEFAULT  ## default is CURRDIR

## END OF CONFIGURATION


## main 

service_operations = [
    'freespace','listFolder','createFolder','deleteFolder',
    'getFileInfo','downloadFile','uploadFile','deleteFile'
]

client_operations = service_operations + [
    'listAllFolders','listAllFiles','resolvePath','dumpFolderPaths',
    'initialize','getSessionId','getAccessToken'
]

raw_client_operations = service_operations  + [
    'retrieveSessionId','retrieveTokenInfo'
]

client_operations_infos = {
    'freespace':('Retrieves the available space of the user','freespace',(0,0)),
    'listFolder':('Lists files and sub-folders of the given folder, (of the root folder if not provided)','listFolder [<folderId>]',(0,1)),
    'createFolder':('Creates a new sub-folder of the given parent folder','createFolder <parentFolderId>',(1,1)),
    'deleteFolder':('Deletes a given folder','deleteFolder <folderId>',(1,1)),
    'getFileInfo':('Retrieves information on a file','getFileInfo <fileId>',(1,1)),
    'downloadFile':('Downloads a file, copying content into a local file given by its file path','downloadFile <fileId> <targetFile>',(2,2)),
    'uploadFile':('Uploads a given local content and creates a file. Uses @filepath convention to retrieve content from a file','uploadFile <name> <folder> <content> [<contentType>]',(3,4)),
    'deleteFile':('Deletes a given local file','deleteFile <fileId>',(1,1)),
    'listAllFolders':('List a given folder and all subfolders recursively','listAllFolders [<folderId>] [<topPath>]',(0,2)),
    'listAllFiles':('List all folders and files recursively','listAllFiles [<folderId>] [<topPath>] [withDetails]',(0,3)),
    'resolvePath':('Returns the file or folder if of a given path','resolvePath [<path>] [<topPath>]',(0,2)),
    'dumpFolderPaths':('Dumps the files paths in disk to enable cache path resolution','dumpFolderPaths',(0,0)),
}

raw_client_operations_infos = {
    'freespace':('Retrieves the available space of the user','freespace',(0,0)),
    'listFolder':('Lists files and sub-folders of the given folder, (of the root folder if not provided)','listFolder [<folderId>]',(0,1)),
    'createFolder':('Creates a new sub-folder of the given parent folder','createFolder <parentFolderId>',(1,1)),
    'deleteFolder':('Deletes a given folder','deleteFolder <folderId>',(1,1)),
    'getFileInfo':('Retrieves information on a file','getFileInfo <fileId>',(1,1)),
    'downloadFile':('Downloads a file, copying content into a local file given by its file path','downloadFile <fileId> <targetFile>',(2,2)),
    'uploadFile':('Uploads a given local content and creates a file. Uses @filepath convention to retrieve content from a file','uploadFile <name> <folder> <content> [<contentType>]',(3,4)),
    'deleteFile':('Deletes a given local file','deleteFile <fileId>',(1,1)),
}

def checkOperation(opname,arglist,oplist,opinfos,parser):
    #print "checkOperation", opname, arglist
    if not opname in oplist:
        return fmtOperationsUsage(opname,"operation unknown : %s" % opname,oplist,opinfos,parser)
    opinfo = opinfos.get(opname)
    min,max = opinfo[2]
    if not len(arglist) in range(min,max+1):
        return fmtOneOperationUsage(opname,"unexpected number of arguments for operation '%s' min: %s max: %s" % (opname,min,max),oplist,opinfos,parser)
    return None ## means operation call OK

def fixOperationUsage(s):
    pos = s.find(' ')
    if pos==-1: return s
    return s[0:pos] + s[pos:].replace('<','').replace('>','').upper()

def fmtOperationsUsage(opname,errmess,oplist,opinfos,parser):
    #print "fmtOperationsUsage", opname, errmess
    s = 'list of opnames and valid arguments\n'
    for x in oplist:
        if not opinfos.has_key(x): continue
        opinfo = opinfos[x]
        s += "  %s\n    %s\n" % (fixOperationUsage(opinfo[1]),opinfo[0])
    s += "\nerror: %s\n" % errmess
    return s

def fmtOneOperationUsage(opname,errmess,oplist,opinfos,parser):
    s = ''
    s += "usage: pyorangecloud.py [...] %s\n" % fixOperationUsage(opinfos[opname][1])
    s += "\nerror: %s\n" % errmess
    return s

def getArgs():

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--raw",action='count',default=0)
    parser.add_argument("-p", "--proxies",default=PROXIES)
    parser.add_argument("-i", "--clientId",default=CLIENT_ID)
    parser.add_argument("-x", "--clientSecret",default=CLIENT_SECRET)
    parser.add_argument("-u", "--redirectUri",default=REDIRECT_URI)
    parser.add_argument("-c", "--authCode")
    parser.add_argument("-t", "--accessToken")
    parser.add_argument("-s", "--sessionId")
    parser.add_argument("-d", "--debugFlags",default=DEBUG_FLAGS_DEFAULT)
    parser.add_argument("-z", "--tokenStorage",default=TOKEN_STORAGE_DEFAULT)
    parser.add_argument("-w", "--pathsStorage",default=PATHS_STORAGE_DEFAULT)
    parser.add_argument("opname", help="operation to call")
    parser.add_argument("arglist",nargs="*")
    args = parser.parse_args(sys.argv[1:])

    extraUsage = ''
    if not args.raw:
        extraUsage = checkOperation(args.opname,args.arglist,client_operations,client_operations_infos,parser)
    else:
        extraUsage = checkOperation(args.opname,args.arglist,raw_client_operations,raw_client_operations_infos,parser)
    if extraUsage: 
        parser.print_usage()
        sys.stderr.write(extraUsage+'\n');sys.exit(1)
    return args

def main(args):
    app = {'clientId':args.clientId,'clientSecret':args.clientSecret,'redirectUri':args.redirectUri}
    if not args.raw:
        client = pyorangecloud.OrangeCloudClient(
            app,args.authCode,args.accessToken,args.sessionId,
            proxies=args.proxies,debugFlags=args.debugFlags,tokenStorage=args.tokenStorage,pathsStorage=args.pathsStorage)
        arglist = args.arglist
    else: 
        client = pyorangecloud.OrangeCloudRawClient(
            app,proxies=args.proxies,debugFlags=args.debugFlags,rawOutput=True)
        arglist = args.arglist
        if args.opname in service_operations: arglist.append(args.accessToken);arglist.append(args.sessionId)
    op = getattr(client,args.opname,None)
    if not op: raise pyorangecloud.PyOrangeCloudError("UnknownOperation",args.opname)
    res = op(*arglist)
    import pprint
    pprint.pprint(res)
    return res

if __name__=="__main__": 
    main(getArgs())
