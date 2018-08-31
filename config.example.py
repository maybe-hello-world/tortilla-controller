import logging

# Domain from which requests are sent (main domain of site)
origin_CORS_domain = 'http://localhost:8000'

# How often to check cookies for expiring
cookie_clean_timer_minutes = 20

# After what time cookie expires
cookie_expire_time_hours = 6

# logging settings
log_level = logging.INFO   # level
log_file = "tortilla.log"  # log filename
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

