from celery import Celery
from phishwatch.app.core.config import get_settings

settings = get_settings()
celery_app = Celery("phishwatch", broker=settings.redis_url, backend=settings.redis_url, include=["phishwatch.app.workers.tasks"])
celery_app.conf.update(task_track_started=True, task_always_eager=settings.task_always_eager, task_serializer="json", accept_content=["json"], result_serializer="json")
