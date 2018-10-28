from flask import Flask, request, make_response, jsonify
from ldap3.core.exceptions import LDAPException
from werkzeug.exceptions import BadRequest
from werkzeug.contrib.fixers import ProxyFix
import ldap3
import random
import string
import datetime
import threading
import connectors
import logging
import config

logging.basicConfig(level=config.LOGGING_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("main")

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

cookie_expire_time_hours = config.COOKIE_EXPIRE_TIME_HOURS
logger.debug("COOKIE_EXPIRE_TIME_HOURS = {}".format(cookie_expire_time_hours))

cookie_clean_timer_minutes = config.COOKIE_CLEAN_TIMER_MINUTES
logger.debug("COOKIE_CLEAN_TIMER_MINUTES = {}".format(cookie_clean_timer_minutes))

app = Flask(__name__)


def clean_cookie():
	threading.Timer(60.0 * cookie_clean_timer_minutes, clean_cookie).start()
	curtime = datetime.datetime.now()

	for key in list(cookie_storage.keys()):
		if cookie_storage[key]['expiretime'] < curtime:
			del cookie_storage[key]

	logger.debug("Cookie cleaned")


cookie_storage = {}
clean_cookie()


def authenticated(func):
	"""
	Decorator for protecting methods and pages.
	Check if user is already logged in by having special header.
	Must be used before function (after app.route).

	:param func: page or method to be protected
	:return: function pointer
	"""
	def wrapper(*args, **kwargs):
		# check if the user is logged in

		if "sesskey" not in request.cookies or request.cookies['sesskey'] not in cookie_storage:
			logger.debug("Unauthenticated request to " + request.url)
			return make_response(
				jsonify(
					{
						'status': 'error',
						'reason': 'unauthenticated',
						'human_reason': 'Unauthenticated access to protected resource'
					}),
				401)

		return func(*args, **kwargs)
	wrapper.__name__ = func.__name__
	return wrapper


def authorized(func):
	"""
	Decorator for protecting methods and pages.
	Check if user have privileges to access requested resource
	Must be used after "authenticated"

	:param func: page or method to be protected
	:return: function pointer
	"""
	def wrapper(*args, **kwargs):
		# check if user has access to requested resource

		sesskey = request.cookies['sesskey']

		resource = None
		if request.method == "POST":
			if 'vmid' in request.json:
				resource = request.json['vmid']
		elif request.method == "GET":
			resource = request.args.get("vmid", None)
		else:
			return make_response(
				jsonify(
					{
						'status': 'error',
						'reason': 'method',
						'human_reason': 'Attempt to get authorized access to protected endpoint with not implemented method'
					}),
				500)

		if cookie_storage[sesskey]['vmlist'] is None:
			list_vms()

		if resource is None or resource not in cookie_storage[sesskey]['vmlist']:
			logger.debug("Unauthorized request to " + request.url)
			return make_response(
				jsonify(
					{
						'status': 'error',
						'reason': 'unauthorized',
						'human_reason': 'Unauthorized access to protected resource'
					}),
				403)

		return func(*args, **kwargs)

	wrapper.__name__ = func.__name__
	return wrapper


def json_check(func):
	"""
	Decorator for checking payload (if Content-Type is set and JSON is readable)

	:param func: endpoint that wait for JSON data
	:return: function pointer
	"""
	def wrapper(*args, **kwargs):
		# check Content-Type
		if not request.content_type == 'application/json':
			logger.warning("Wrong Content-Type, url: {}".format(request.url))
			logger.debug("Data: " + str(request.data))
			return make_response(
				jsonify(
					{
						'status': 'error',
						'reason': 'content-type',
						'human_reason': 'Content-type must be application/json'
					}),
				400)

		# check data parsing
		try:
			request.get_json()
		except BadRequest:
			logger.warning("Invalid content, url: {}".format(request.url))
			logger.debug("Data: " + str(request.data) + str(request.form))
			return make_response(
				jsonify(
					{
						'status': 'error',
						'reason': 'content',
						'human_reason': "Content is incorrect, check sent data."
					}),
				400)

		return func(*args, **kwargs)
	wrapper.__name__ = func.__name__
	return wrapper


@app.errorhandler(404)
def page_not_found(e):
	logger.debug("404 answer - " + request.url)
	return make_response(
		jsonify(
			{
				'status': 'error',
				'reason': 'not-found',
				'human_reason': str(e)
			}),
		404)


@app.errorhandler(500)
def internal_error(e):
	logger.warning("Internal error occurred. URL: {}, error: {}".format(request.url, e))
	return make_response(
		jsonify(
			{
				'status': 'error',
				'reason': 'internal',
				'human_reason': 'Internal error occurred. Contact site owner.' + str(e)
			}),
		500)


@app.route('/api/v1/login', methods=['POST'])
@json_check
def login():

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
				logger.info("User {}\\{} couldn't authenticate".format(_domain, _username))
				return False
			else:
				logger.info("User {}\\{} authenticated successfully".format(_domain, _username))
				conn.unbind()
				return True
		except LDAPException as e:
			logger.warning("LDAP Error: {}".format(str(e)))
			return False

	def parse_domain(_userfield: str) -> (str, str):
		if '@' in _userfield:
			_userfield = _userfield.split(sep='@')
			_domain = str(_userfield[1]).split('.')[-2]
			_username = str(_userfield[0])
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

	data = request.get_json()

	# check payload
	if type(data) != dict or 'username' not in data or 'password' not in data or \
		type(data['username']) != str or type(data['password']) != str:
		logger.warning("Wrong payload in login request")
		logger.debug("Payload data: " + str(data))
		return make_response(
			jsonify(
				{
					'status': 'error',
					'reason': 'payload',
					'human_reason': 'Payload is invalid'
				}),
			400)

	# get payload
	userfield = data['username']
	password = data['password']

	# divide username and domain
	domain, username = parse_domain(userfield)

	# check credentials
	if not check_credentials(_domain=domain, _username=username, _password=password):
		logger.info("User {}\\{} didn't authenticate due to wrong credentials".format(domain, username))
		return make_response(
			jsonify(
					{
						'status': 'error',
						'reason': 'unauthenticated',
						'human_reason': 'Wrong domain, username or password'
					}),
			403)

	# generate unique token (cookie auth)
	sesskey = generate_random_string(24)
	while sesskey in cookie_storage:
		sesskey = generate_random_string(24)

	# generate random string to xor user password with and save with user token to database
	serverkey = generate_random_string(len(password))
	userkey = [ord(password[i]) ^ ord(serverkey[i]) for i in range(len(password))]

	cookieextime = datetime.datetime.now() + datetime.timedelta(hours=cookie_expire_time_hours)

	# data to be saved to cookie db
	data = {
		'domain': domain,
		'username': username,
		'serverkey': serverkey,
		'vmlist': None,
		'expiretime': cookieextime
	}

	cookie_storage[sesskey] = data

	resp = make_response(
		jsonify(
			{
				'status': 'success',
				'reason': 'authenticated',
				'human_reason': 'Successfully authenticated',
				'userkey': userkey
			}),
		200)

	resp.set_cookie(key="sesskey", value=sesskey, expires=cookieextime)

	logger.info("{}\\{} successfully authenticated".format(domain, username))
	return resp


@app.route('/api/v1/vm', methods=['GET'])
@authenticated
def list_vms():
	sesskey = request.cookies['sesskey']

	userdata = cookie_storage[sesskey]
	domain = userdata['domain']
	username = userdata['username']

	vm_list = []
	for m in connectors.modules.values():
		vm_list.extend(m.methods['list'](domain, username))

	# save VM info for authorization checks and for connecting to VMs
	if cookie_storage[sesskey]['vmlist'] is None:
		cookie_storage[sesskey]['vmlist'] = {}

	for vm in vm_list:
		cookie_storage[sesskey]['vmlist'][vm['vmid']] = vm

	logger.debug("VM list returned to {}\\{}, list: {}".format(domain, username, vm_list))
	return make_response(jsonify(
		{
			"status": "success",
			"reason": "success",
			"human_reason": "Successfully got list of VMs",
			"list": vm_list
		}
	), 200)


@app.route('/api/v1/vm', methods=['POST'])
@authenticated
@json_check
@authorized
def command_vm():
	data = request.get_json()

	# check payload
	if "vmid" not in data or "vmprovider" not in data or "action" not in data:
		logger.warning("Wrong payload in VM action request. Data: " + str(data))
		return make_response(jsonify(
			{
				"status": "error",
				"reason": "payload",
				"human_reason": "Request is invalid"
			}
		), 400)

	# check that method is allowed for this VM provider
	if data['action'] not in connectors.modules[data['vmprovider']].methods:
		logger.warning("Unimplemented action requested, action: {}, provider: {}".format(data['action'], data['vmprovider']))
		return make_response(jsonify(
			{
				"status": "error",
				"reason": "notimplemented",
				"human_reason": "Action is not available for this VM provider."
			}
		), 400)

	if not connectors.modules[data['vmprovider']].methods[data['action']](data['vmid']):
		logger.error("Error occurred during executing VM action, action: {}, vmid: {}, provider: {}".format(
			data['action'], data['vmid'], data['vmprovider'])
		)
		return make_response(jsonify(
			{
				"status": "error",
				"reason": "action",
				"human_reason": "Error occurred during processing of request. Contact site owner."
			}
		), 500)

	return '', 204


@app.route('/api/v1/vminfo', methods=['GET'])
@authenticated
@authorized
def get_vm_info():
	sesskey = request.cookies['sesskey']
	vmid = request.args.get("vmid")

	vminfo = cookie_storage[sesskey]["vmlist"][vmid]

	return jsonify(vminfo), 200


@app.route('/api/v1/key', methods=['GET'])
@authenticated
def get_server_key():
	sesskey = request.cookies["sesskey"]
	userinfo = cookie_storage[sesskey]

	return jsonify({
		"domain": userinfo["domain"],
		"username": userinfo["username"],
		"serverkey": userinfo["serverkey"]
	}), 200


app.wsgi_app = ProxyFix(app.wsgi_app)
if __name__ == '__main__':
	app.run()
