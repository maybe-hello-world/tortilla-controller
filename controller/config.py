import os
import sys
import logging

__logger = logging.getLogger("config_parser")

# ldap server url
LDAP_URL = ""
if "LDAP_URL" in os.environ:
	LDAP_URL = os.environ["LDAP_URL"]
else:
	logging.error("Environment variable LDAP_URL not provided! Exiting...")
	sys.exit(1)

# parsing SCVMM config
SCVMM_URL = "http://scvmmapi:5555/api"
if "SCVMM_API" in os.environ:
	SCVMM_URL = os.environ['SCVMM_API']

# parsing redis address
REDIS_HOST = "redis"
if "REDIS_HOST" in os.environ:
	REDIS_HOST = os.environ['REDIS_HOST']

# parsing redis address
REDIS_PORT = 6379
if "REDIS_PORT" in os.environ:
	try:
		REDIS_PORT = int(os.environ['REDIS_PORT'])
	except (TypeError, ValueError):
		__logger.exception("Value of REDIS_PORT is erroneous.")

# parsing logging level
LOGGING_LEVEL = logging.INFO
__levels = {
		"DEBUG": logging.DEBUG,
		"INFO": logging.INFO,
		"WARNING": logging.WARNING,
		"ERROR": logging.ERROR,
		"CRITICAL": logging.CRITICAL
	}
if "LOG_LEVEL" in os.environ and os.environ['LOG_LEVEL'] in __levels:
	LOGGING_LEVEL = __levels[os.environ['LOG_LEVEL']]

# parsing cookies config
COOKIE_EXPIRE_TIME_HOURS = 6
if "COOKIE_EXPIRE_TIME_HOURS" in os.environ:
	try:
		COOKIE_EXPIRE_TIME_HOURS = int(os.environ['COOKIE_EXPIRE_TIME_HOURS'])
	except (ValueError, TypeError):
		__logger.exception("Value of COOKIE_EXPIRE_TIME_HOURS is erroneous.")

DEFAULT_DOMAIN = ""
if "DEFAULT_DOMAIN" in os.environ:
	DEFAULT_DOMAIN = os.environ['DEFAULT_DOMAIN']
