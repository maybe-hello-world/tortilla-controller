from typing import Callable, Awaitable

from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from ldap3.core.exceptions import LDAPException
from functools import wraps
import dataclasses
import ldap3
import random
import string
import uvicorn
from controller import connectors, config
import logging
import redis
import json

logging.basicConfig(level=config.LOGGING_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("main")

global_r: redis.Redis
cookie_expire_time_hours: int


app = FastAPI(
	title="Tortilla Controller",
	description="Internal controller of Tortilla project. Dispatch requests to different VM providers.",
	version="0.1.0"
)


def authenticated(func: Callable[..., Awaitable]):
	"""
	Decorator for protecting methods and pages.
	Check if user is already logged in by having special header.
	Must be used before function (after app.route).

	:param func: page or method to be protected
	:return: function pointer
	"""
	@wraps(func)
	async def wrapper(*args, request: Request, **kwargs):
		# check if the user is logged in
		if "sesskey" not in request.cookies or not global_r.exists(request.cookies['sesskey']):
			logger.debug("Unauthenticated request to " + str(request.url))
			return JSONResponse(
				status_code=401,
				content={
						'status': 'error',
						'reason': 'unauthenticated',
						'human_reason': 'Unauthenticated access to protected resource'
					}
			)

		return await func(*args, request=request, **kwargs)
	return wrapper


def authorized(func: Callable[..., Awaitable]):
	"""
	Decorator for protecting methods and pages.
	Check if user have privileges to access requested resource
	Must be used after "authenticated"

	:param func: page or method to be protected
	:return: function pointer
	"""
	@wraps(func)
	async def wrapper(*args, request: Request, **kwargs):
		# check if user has access to requested resource

		sesskey = request.cookies['sesskey']

		resource = None
		if request.method == "POST":
			json_result = await request.json()
			if 'vmid' in json_result:
				resource = json_result['vmid']
		elif request.method == "GET":
			resource = request.query_params.get("vmid", None)
		else:
			return JSONResponse(
				status_code=500,
				content={
						'status': 'error',
						'reason': 'method',
						'human_reason': 'Attempt to get authorized access to protected endpoint with not implemented method'
					}
			)

		userdata = global_r.get(sesskey)
		vmlist = json.loads(userdata)['vmlist']
		if vmlist is None:
			await list_vms()

		if resource is None or resource not in vmlist:
			logger.debug("Unauthorized request to " + str(request.url))
			return JSONResponse(
				status_code=403,
				content={
						'status': 'error',
						'reason': 'unauthorized',
						'human_reason': 'Unauthorized access to protected resource'
					}
			)

		return await func(*args, request=request, **kwargs)
	return wrapper


def json_check(func: Callable[..., Awaitable]):
	"""
	Decorator for checking payload (if Content-Type is set and JSON is readable)

	:param func: endpoint that wait for JSON data
	:return: function pointer
	"""
	@wraps(func)
	async def wrapper(*args, request: Request, **kwargs):
		# check Content-Type
		if not request.headers.get('content-type', "") == 'application/json':
			logger.warning("Wrong Content-Type, url: {}".format(request.url))
			return JSONResponse(
				status_code=400,
				content={
						'status': 'error',
						'reason': 'content-type',
						'human_reason': 'Content-type must be application/json'
					}
			)

		# check data parsing
		try:
			await request.json()
		except json.JSONDecodeError:
			logger.warning("Invalid content, url: {}".format(request.url))
			return JSONResponse(
				status_code=400,
				content={
						'status': 'error',
						'reason': 'content',
						'human_reason': "Content is incorrect, check sent data."
					}
			)

		return await func(*args, request=request, **kwargs)
	return wrapper


@app.on_event("startup")
async def __init__():
	global global_r, cookie_expire_time_hours

	cookie_expire_time_hours = config.COOKIE_EXPIRE_TIME_HOURS
	logger.debug("COOKIE_EXPIRE_TIME_HOURS = {}".format(cookie_expire_time_hours))

	global_r = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT)
	logger.debug(f"Redis instantiated, host: {config.REDIS_HOST}, port: {config.REDIS_PORT}")

	for c in connectors.modules.values():
		await c.async_open()


@app.on_event("shutdown")
async def __del__():
	global global_r
	global_r.close()

	for c in connectors.modules.values():
		await c.async_close()


@app.exception_handler(StarletteHTTPException)
async def exception_handler(request, exc):
	status_code = exc.status_code
	payload = {
		'status': 'error',
		'reason': 'unknown',
		'human_reason': str(exc.detail)
	}
	if status_code == 404:
		payload['reason'] = 'not-found'
		payload['human_reason'] = 'Requested URL not found.'
	if status_code == 500:
		logger.exception(str(exc.details))
		payload['reason'] = 'internal'

	return JSONResponse(status_code=status_code, content=payload)


@app.post('/api/v1/login')
@json_check
async def login(request: Request):
	"""Handle login requests, set needed cookies and return whether you are logged in"""

	def check_credentials(_domain: str, _username: str, _password: str) -> bool:
		try:
			server = ldap3.Server(config.LDAP_URL, mode=ldap3.IP_V4_PREFERRED, use_ssl=True)
			conn = ldap3.Connection(
				server,
				user="{}\\{}".format(_domain, _username),
				password=_password,
				auto_referrals=False,
				read_only=True,
				authentication=ldap3.NTLM
			)
			if not conn.bind():
				return False
			else:
				conn.unbind()
				return True
		except LDAPException as e:
			logger.warning("LDAP Error: {}".format(str(e)))
			return False

	def parse_domain(_userfield: str) -> (str, str):
		if '@' in _userfield:
			_username, _domain = _userfield.split(sep='@', maxsplit=1)
			_username = str(_username)		# 'someone@' handling
			_domain = str(_domain)
			if '.' in _domain:
				_domain = _domain[:_domain.rindex('.')]
		elif '\\' in _userfield:
			_userfield = _userfield.split(sep='\\')
			_domain = str(_userfield[0])
			_username = str(_userfield[1])
		else:
			_username = str(_userfield)
			_domain = config.DEFAULT_DOMAIN
		return _domain.lower(), _username.lower()

	def generate_random_string(n: int) -> str:
		return ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(n))

	data = await request.json()

	# check payload
	if type(data) != dict or 'username' not in data or 'password' not in data or "serverkey" not in data or \
		type(data['username']) != str or type(data['password']) != str or type(data['serverkey']) != str:
		logger.warning("Wrong payload in login request")
		logger.debug("Payload data: " + str(data))
		return JSONResponse(
			status_code=400,
			content={
					'status': 'error',
					'reason': 'payload',
					'human_reason': 'Payload is invalid'
				}
		)

	# get payload
	userfield = data['username']
	password = data['password']

	# divide username and domain
	domain, username = parse_domain(userfield)

	# check credentials
	if not check_credentials(_domain=domain, _username=username, _password=password):
		logger.info("User {}\\{} didn't authenticate due to wrong credentials".format(domain, username))
		return JSONResponse(
			status_code=403,
			content={
						'status': 'error',
						'reason': 'unauthenticated',
						'human_reason': 'Wrong domain, username or password'
					}
		)

	# generate unique token (cookie auth)
	sesskey = generate_random_string(24)
	while global_r.exists(sesskey):
		sesskey = generate_random_string(24)

	# generate random string to xor user password with and save with user token to database
	serverkey = data['serverkey']

	# data to be saved to cookie db
	data = {
		'domain': domain,
		'username': username,
		'serverkey': serverkey,
		'vmlist': None
	}

	data = json.dumps(data)
	global_r.set(sesskey, data, ex=cookie_expire_time_hours*3600)

	resp = JSONResponse(
		status_code=200,
		content={
				'status': 'success',
				'reason': 'authenticated',
				'human_reason': 'Successfully authenticated'
			}
	)

	resp.set_cookie(key="sesskey", value=sesskey, expires=cookie_expire_time_hours*3600)

	logger.info("{}\\{} successfully authenticated".format(domain, username))
	return resp


@app.get('/api/v1/vm')
@authenticated
async def list_vms(request: Request):
	"""Returns list of virtual machines, available for current user"""
	sesskey = request.cookies['sesskey']

	userdata = global_r.get(sesskey)
	userdata = json.loads(userdata)
	domain = userdata['domain']
	username = userdata['username']

	vm_list = []
	for m in connectors.modules.values():
		vm_list.extend(await m.list_vms(domain, username))

	# save VM info for authorization checks and for connecting to VMs
	if userdata['vmlist'] is None:
		userdata['vmlist'] = {}

	for vm in vm_list:
		userdata['vmlist'][vm.vmid] = dataclasses.asdict(vm)

	remaining_ttl = global_r.ttl(sesskey)
	global_r.set(sesskey, json.dumps(userdata), ex=remaining_ttl)

	logger.debug("VM list returned to {}\\{}, length of list: {} elements".format(domain, username, len(vm_list)))
	return JSONResponse(
		status_code=200,
		content={
			"status": "success",
			"reason": "success",
			"human_reason": "Successfully got list of VMs",
			"list": [dataclasses.asdict(x) for x in vm_list]
		}
	)


@app.post('/api/v1/vm', status_code=204)
@authenticated
@json_check
@authorized
async def command_vm(request: Request):
	"""Executes some command on virtual machine."""
	available_actions = {
		"list": "list_vms",
		"list_vms": "list_vms",
		"start": "start",
		"shutdown": "shutdown",
		"poweroff": "poweroff",
		"save": "save",
		"remove_checkpoint": "remove_checkpoint",
		"create_checkpoint": "create_checkpoint",
		"list_checkpoints": "list_checkpoints"
	}

	data = await request.json()

	# check payload
	if (
			"vmid" not in data or
			"vmprovider" not in data or
			"action" not in data or
			data["action"] not in available_actions
	):
		logger.warning("Wrong payload in VM action request. Data: " + str(data))
		return JSONResponse(
			status_code=400,
			content={
				"status": "error",
				"reason": "payload",
				"human_reason": "Request is invalid"
			}
		)

	required_action = available_actions[data['action']]
	vmid = data['vmid']
	vmprovider = data['vmprovider']

	try:
		connector = connectors.modules[vmprovider]
		action = getattr(connector, required_action)
		result = await action(vmid)
	except NotImplementedError:
		logger.warning(
			"Unimplemented action requested, action: {}, provider: {}".format(data['action'], data['vmprovider']))
		return JSONResponse(
			status_code=400,
			content={
				"status": "error",
				"reason": "notimplemented",
				"human_reason": "Action is not available for this VM provider."
			}
		)

	if not result:
		logger.warning("Error occurred during executing VM action, action: {}, vmid: {}, provider: {}".format(
			data['action'], data['vmid'], data['vmprovider'])
		)
		return JSONResponse(
			status_code=503,
			content={
				"status": "error",
				"reason": "action",
				"human_reason": "Error occurred during processing of request. Contact site owner."
			}
		)


@app.get('/api/v1/vminfo')
@authenticated
@authorized
async def get_vm_info(vmid: str, request: Request):
	"""Return information about virtual machine"""
	sesskey = request.cookies['sesskey']

	vminfo = json.loads(global_r.get(sesskey))["vmlist"][vmid]

	return JSONResponse(
		status_code=200,
		content=vminfo
	)


@app.get('/api/v1/key')
@authenticated
async def get_server_key(request: Request):
	"""Return server part of the key for password recombining."""
	sesskey = request.cookies["sesskey"]
	userinfo = json.loads(global_r.get(sesskey))

	return JSONResponse(
		status_code=200,
		content={
			"domain": userinfo["domain"],
			"username": userinfo["username"],
			"serverkey": userinfo["serverkey"]
		}
	)


if __name__ == '__main__':
	uvicorn.run(app=app, host='0.0.0.0', port=5678)
