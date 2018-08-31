from flask import Flask, request, make_response, jsonify
from flask_cors import CORS
from werkzeug.exceptions import BadRequest
import random
import string
import datetime
import threading
import config
import connectors

cookie_clean_timer_minutes = config.cookie_clean_timer_minutes
cookie_expire_time_hours = config.cookie_expire_time_hours

app = Flask(__name__)

# TODO: change domain to production
CORS(app, origins=config.origin_CORS_domain, supports_credentials=True)


def clean_cookie():
	threading.Timer(60.0 * cookie_clean_timer_minutes, clean_cookie).start()
	curtime = datetime.datetime.now()
	for i in cookie_storage.keys():
		if cookie_storage[i]['expiretime'] < curtime:
			del cookie_storage[i]


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

		if "sesskey" not in request.cookies:
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

		# TODO: there might be a better way
		""" В cookiestorage добавить поле "список id виртуалок", которые доступны этому юзеру с None по умолчанию
			При каждом /list_vm его обновлять. Для проверки брать id виртуальной машины и проверять, есть ли в этом поле
			Если поле None - вызывать принудительно лист и заполнять
			Если не None и id нету - отказать, иначе пропустить
		"""
		resource = None
		if 'resource' in request.json:
			resource = request.json['resource']

		# TODO: implement
		if sesskey == resource or resource is None:
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
def page_not_found():
	return make_response(
		jsonify(
			{
				'status': 'error',
				'reason': 'not-found',
				'human_reason': 'Requested endpoint or resource is not found'
			}),
		404)


@app.errorhandler(500)
def internal_error(e):
	return make_response(
		jsonify(
			{
				'status': 'error',
				'reason': 'internal',
				'human_reason': 'Internal error occurred. Contact site owner.' + e
			}),
		500)


@app.route('/api/v1/login', methods=['POST'])
@json_check
def login():

	# TODO: LDAP
	def check_credentials(_domain: str, _username: str, _password: str) -> bool:
		if _domain.lower() == 'avalon' and _username.lower() == 'test' and _password == 'test':
			return True
		return False

	def generate_random_string(n: int) -> str:
		return ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(n))

	data = request.get_json()

	# check payload
	if type(data) != dict or 'domain' not in data or 'username' not in data or 'password' not in data or \
		type(data['domain']) != str or type(data['username']) != str or type(data['password']) != str:
		return make_response(
			jsonify(
				{
					'status': 'error',
					'reason': 'payload',
					'human_reason': 'Payload is invalid'
				}),
			400)

	# get payload
	domain = data['domain']
	username = data['username']
	password = data['password']

	# check credentials
	if not check_credentials(_domain=domain, _username=username, _password=password):
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
	userkey = [chr(ord(password[i]) ^ ord(serverkey[i])) for i in range(len(password))]

	cookieextime = datetime.datetime.now() + datetime.timedelta(hours=cookie_expire_time_hours)

	# data to be saved to cookie db
	data = {
		'domain': domain,
		'username': username,
		'serverkey': serverkey,
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

	# damn cross server requests
	resp.headers['Access-Control-Allow-Credentials'] = 'true'
	resp.headers['Access-Control-Allow-Origin'] = request.environ['HTTP_ORIGIN']
	resp.headers['Access-Control-Allow-Methods'] = 'GET, POST'
	resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'

	return resp


@app.route('/api/v1/vm', methods=['GET'])
@authenticated
def list_vms():
	sesskey = request.cookies['sesskey']
	if sesskey not in cookie_storage:
		return make_response(
			jsonify(
				{
					'status': 'error',
					'reason': 'unauthenticated',
					'human_reason': 'Provided cookie is missing in database, please relogin'
				}),
			401)

	userdata = cookie_storage[sesskey]
	domain = userdata['domain']
	username = userdata['username']

	vm_list = []
	for m in connectors.modules.values():
		vm_list.extend(m.list_vms(domain, username))

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
@authorized
@json_check
def command_vm():
	# TODO: Implement
	print("POST - command VM")
	return "OK", 200


if __name__ == '__main__':
	app.run(host="0.0.0.0", port=5876, debug=True)
