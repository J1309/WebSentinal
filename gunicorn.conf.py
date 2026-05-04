# Gunicorn configuration
bind = "0.0.0.0:5000"
workers = 3
threads = 2
timeout = 300  # 5 minutes for long-running scans
keepalive = 2
