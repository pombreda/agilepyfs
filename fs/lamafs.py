"""
pyfilesystem module for agile

"""
DEBUG = True

import os, sys, stat, logging
import urlparse
import datetime, time
from functools import wraps

from ConfigParser import SafeConfigParser

from jsonrpc import ServiceProxy, JSONRPCException

# from fs.base import FS
# from fs.path import normpath
# from fs.errors import ResourceNotFoundError, ResourceInvalidError, UnsupportedError
# from fs.remote import RemoteFileBuffer, CacheFS
# from fs.opener import Opener

from fs.base import *
from fs.path import *
from fs.errors import *
from fs.remote import *
from fs.filelike import LimitBytesFile

CFG = SafeConfigParser()
sysconf = os.path.join('/etc/agile/pyfs.ini')
cfgfiles = [sysconf]

boolval = lambda s: str(s).lower() in [ '1', 'true', 'yes', 'on' ]

HOME = os.environ.get('HOME')
if HOME:
	userconfdir = os.path.join(HOME, '.agile')
	userconf = os.path.join(userconfdir, 'pyfs.ini')
	cfgfiles.append(userconf)
else:
	userconfdir = None
CFG.read(cfgfiles)



FTYPE_DIR = 1
FTYPE_FILE = 2

if DEBUG:
	logger = logging.getLogger()
	logformat = "[%(process)d] %(levelname)s %(name)s:%(lineno)d %(message)s"
	formatter = logging.Formatter(logformat)

	stderr_handler = logging.StreamHandler()
	stderr_handler.setFormatter(formatter)
	logger.addHandler(stderr_handler)

	logger.setLevel(logging.DEBUG)

def FuncLog(name):
	def wrapper(func):
		"""
			A wrapper wrapper for decoration.
		"""
		if name: func.__name__ = name
		@wraps(func)
		def wrapper2(*args, **kwargs):
			wrapper2._logger = logging.getLogger('%s.%s' % (func.__module__, func.__name__))
			if len(args) == 0:
				wrapper2._logger.info("params: %s" % (str(kwargs)))
			else:
				wrapper2._logger.info("params: %s" % (str(args)))
			ret = func(*args, **kwargs)
			wrapper2._logger.info("--> return: %s" % (repr(ret)))
			return ret
		return wrapper2
	return wrapper


class LAMAFS(FS):
	"""
	lama file system
	"""
	
	_meta = { 'thread_safe' : False,
			  'network' : True,
			  'virtual': False,
			  'read_only' : False,
			  'unicode_paths' : True,
			  'case_insensitive_paths' : False,
			  'atomic.move' : True,
			  'atomic.copy' : True,			  
			  'atomic.makedir' : True,
			  'atomic.rename' : False,
			  'atomic.setcontents' : False,
			  'file.read_and_write' : False,
			  }
			  
	def __init__(self, url, username = None, password = None):		
		self.log = logging.getLogger(self.__class__.__name__)
		self.root_url = url
		self.api_url = "%s/jsonrpc" % (self.root_url)

		secure_upload = False

		urlp = list(urlparse.urlparse(self.root_url))
		if secure_upload:
			self.post_url = "https://%s/post/file" % (urlp.netloc)
		else:
			tmp = urlp[1].split(":")
			fqdn = tmp[0]
			if len(tmp) > 1:
				port = int(tmp[1])
			else:
				port = 8080
			self.post_url = "http://%s:%d/post/file" % (fqdn, port)

		self.log.info("api url %s, post url %s" % (self.api_url, self.post_url))

		self.apicfg = dict(CFG.items('api'))
		self.egress_url = self.apicfg.get('egress_url')

		# TODO: Support persisted tokens somewhere
		persisted_token = self.apicfg.get('token')
		persisted_token = None

		self.username = username
		self.password = password
		self.persisted_token = persisted_token

		a = ServiceProxy( self.api_url )
		self._api = a
		self.api = AuthProxy(a, username, password, None, persisted_token, update_token_cb = self._update_token_cb )
		self.api.noisy = False # DEBUG

		self.log.info("Using API at %s" % (self.api_url))

		self.cache_paths = {}
		self.open_files = {}

	def _update_token_cb(self, token):
		if token == None:
			self.log.warn("No token received after login")
			return
		self.log.debug("new token %s" % (repr(token)))
		self.token = token
		return token
	   
	#@FuncLog(None)
	def getsize(self, path):
		#item = self.__getNodeInfo( path )
		st = self.api.stat(path)
		return st.get('size',0)

	def _check_path(self, path):
		path = normpath(path)
		base, fname = pathsplit(abspath(path))
		
		dirlist = self._readdir(base)
		if fname and fname not in dirlist:
			raise ResourceNotFoundError(path)
		return dirlist, fname

	#@FuncLog(None)
	def getinfo(self, path, overrideCache = False):

		if path in self.open_files:
			#Create a fake stat object for open files
			fst = {}
			fst['size'] = 0
			fst['modified_time'] = datetime.datetime.fromtimestamp(time.time())
			fst['created_time'] = fst['modified_time']
			fst['st_mode'] = 0700 | stat.S_IFREG
			return fst

		#node = self.__getNodeInfo(path, overrideCache = overrideCache)
		st = self.api.stat(path)
		if not st['code'] == 0:
		   raise ResourceNotFoundError
		node = {}
		node['size'] = st.get('size', 0)
		node['modified_time'] = datetime.datetime.fromtimestamp(st['mtime'])
		node['created_time'] = node['modified_time']
		if st['type'] == FTYPE_DIR:
		   node['st_mode'] = 0700 | stat.S_IFDIR
		else:
		   node['st_mode'] = 0700 | stat.S_IFREG
		return node
		
	#@FuncLog(None)
	def open(self, path, mode="r"):

		path = normpath(path)
		mode = mode.lower()		
		if self.isdir(path):
			self.log.warn("ResourceInvalidError %s" % (path))
			raise ResourceInvalidError(path)		

		if 'a' in mode:
			self.log.warn("UnsupportedError write %s" % (path))
			raise UnsupportedError('write')
			
		if 'r' in mode:
			if not self.isfile(path):
				self.log.warn("ResourceNotFoundError %s" % (path))
				raise ResourceNotFoundError(path)

		lf = LamaFile(self, path, mode) 

		if 'w' in mode or 'r+' in mode:
			self.open_files[path] = lf

		#lbf = LimitBytesFile(0, lf, "r")
		#f = RemoteFileBuffer(self, path, mode, lbf) 
		return lf 
 
	#@FuncLog(None)
	def exists(self, path):
		return self.isfile(path) or self.isdir(path)
	
	#@FuncLog(None)
	def isdir(self, path):
		r = self.api.stat(path )
		if r['code']  == -1: 
			return False
		if r['type'] == FTYPE_DIR:
			return True
		elif r['type'] == FTYPE_FILE:
			return False
		else:
			return False

	#@FuncLog(None)
	def isfile(self, path):
		r = self.api.stat(path)
		if r['code']  == -1: 
			return False
		if r['type'] == FTYPE_FILE:
			return True
		elif r['type'] == FTYPE_DIR:
			return False
		else:
			return False

	#@FuncLog(None)
	def makedir(self, path, recursive=False, allow_recreate=False):
		path = normpath(path)
		if path in ('', '/'):
			return
		r = self.api.makeDir( path )
		return (r==0)

	#@FuncLog(None)
	def rename(self, src, dst, overwrite=False, chunk_size=16384):
		if not overwrite and self.exists(dst):
			raise DestinationExistsError(dst)
		r = self.api.rename(  src, dst )
		return (r==0)

	#@FuncLog(None)
	def refreshDirCache(self, path):
		(root1, file) = self.__getBasePath( path )
		# reload cache for dir
		self.listdir(root1, overrideCache=True)

	#@FuncLog(None)
	def removedir(self, path):		
		if not self.isdir(path):
			raise ResourceInvalidError(path)

		r = self.api.deleteDir( path )
		return (r == 0)
		
	#@FuncLog(None)
	def remove(self, path, checkFile = True):		
		if not self.exists(path):
			raise ResourceNotFoundError(path)
		if checkFile and not self.isfile(path):
			raise ResourceInvalidError(path)
		
		r = self.api.deleteFile( path )
		return (r == 0)
		
	#@FuncLog(None)
	def __getBasePath(self, path):
		parts = path.split('/')
		root = './'
		file = path
		if len(parts)>1:
			root = '/'.join(parts[:-1])
			file = parts[-1]
		return root, file
		
	#@FuncLog(None)
	def __getNodeInfo(self, path, overrideCache = False):
		# check if file exists in cached data or fecth target dir
		(root, file) = self.__getBasePath( path )
		 
		cache = self.cache_paths.get( root )
		# check if in cache
		item = None
		if cache and not overrideCache:
			item = [item for item in cache if item['stat']['type']==2] or None
			if item: 
				item = item[0]
		else:
			# fetch listdir in cache then restart
			res = self.listdir( root )
			if res:
				item = self.__getNodeInfo( path )
		return item
			
	#@FuncLog(None)
	def close(self):
		self.log.info("closing down")
		return True

	#@FuncLog(None)
	def listdir(self, path="./",
					  wildcard=None,
					  full=False,
					  absolute=False,
					  dirs_only=False,
					  files_only=False,
					  overrideCache=True
					  ):
		djson=[]
		fjson=[]
		df =[]
		d=[]
		f=[]
		list = []
		if not files_only: 
			djson = self.api.listDir( path, 1000, 0, False )
			d=[f['name'] for f in djson['list']]
			list.extend(d)

		if not dirs_only:  
			fjson = self.api.listFile( path, 1000, 0, False )
			f=[f['name'] for f in fjson['list']]
			list.extend(f)

		return self._listdir_helper(path, list, wildcard, full, absolute, dirs_only, files_only)

	#@FuncLog(None)
	def listdirinfo(self, path="./",
					  wildcard=None,
					  full=False,
					  absolute=False,
					  dirs_only=False,
					  files_only=False,
					  overrideCache=True
					  ):
		djson=[]
		fjson=[]
		df =[]
		d=[]
		f=[]
		list = []
		if not files_only:
			djson = self.api.listDir( path, 1000, 0, True)
			for f in djson['list']:
			   s = f['stat']
			   st = {
				  'size' : s['size'],
				  'created_time' : datetime.datetime.fromtimestamp(s['mtime']),
				  'accessed_time' : datetime.datetime.fromtimestamp(time.time()),
				  'modified_time' : datetime.datetime.fromtimestamp(s['mtime']),
				  'st_mode' : 0700 | stat.S_IFDIR
			   }
			   list.append((f['name'], st))

		if not dirs_only: 
			fjson = self.api.listFile( path, 1000, 0, True )
			for f in fjson['list']:
			   s = f['stat']
			   st = {
				  'size' : s['size'],
				  'created_time' : datetime.datetime.fromtimestamp(s['mtime']),
				  'accessed_time' : datetime.datetime.fromtimestamp(time.time()),
				  'modified_time' : datetime.datetime.fromtimestamp(s['mtime']),
				  'st_mode' : 0700 | stat.S_IFREG
			   }
			   list.append((f['name'], st))

		#return self._listdir_helper(path, list, wildcard, full, absolute, dirs_only, files_only)
		return list

class AuthProxy(object):
	"""
	Provides a Debug proxy class that logs requests and responses

	"""
	noisy = True

	def __init__(self, api, user = None, password = None, name = None, token = None, update_token_cb = None):
		self.log = logging.getLogger(self.__class__.__name__)
		self.api = api
		self.user = user
		self.password = password
		self.name = name
		self.token = token
		self.user_object = None

		if update_token_cb == None:
			update_token_cb = lambda token: token
		self.update_token_cb = update_token_cb

		if name == None and token:
			self.update_token_cb(token)

	def __getattr__(self, name):
		if not self.token:
			self._login()
		return AuthProxy(self.api, self.user, self.password, name, self.token, self.update_token_cb)

	def _get_token(self):
		return self.token

	def _login(self):
		"""
		login if the token is not set
		"""
		if self.token:
			self.log.debug("already logged in with token %s" % (self.token))
			return False
		self.log.debug("Logging in with %s %s" % (repr(self.user), repr(self.password)))
		token, user_object = self.api.login(self.user, self.password)
		self.token = token
		self.update_token_cb(token)
		self.user_object = user_object
		self.log.debug("login token %s" % (self.token))
		return True

	def __call__(self, *args):
		#auth = request_authorization(self.name, self.key, self.secret)
		newargs = [ self.token ] + list(args)
		method = getattr(self.api, self.name)
		ret = None

		# self.log.debug("%s %s" % (method, newargs))

		try:
			ret = method(*newargs)

		except JSONRPCException, e:
			if hasattr(e, 'error'):
				self.log.error("%s: %s" % (self.name, e.error))
			raise e

		if self.noisy:
			frame = 1
			caller = sys._getframe(frame).f_code.co_name
			self.log.debug("[%s] %s%s -> %s" % (caller, self.name, repr(args), repr(ret)))

		return ret


