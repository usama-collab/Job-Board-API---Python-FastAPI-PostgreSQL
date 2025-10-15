from celery import Celery

celery_app = Celery(
    'worker',
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

celery_app.conf.timezone = "Asia/Karachi"

from utils import send_email
from utils import send_app_email
from utils import send_app_status_email