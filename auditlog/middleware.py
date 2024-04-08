import threading

from django.contrib.auth import get_user_model

from auditlog.cid import set_cid
from auditlog.context import set_actor

_thread_locals = threading.local()


def get_current_request():
    return getattr(_thread_locals, "current_request", None)

class AuditlogMiddleware:
    """
    Middleware to couple the request's user to log items. This is accomplished by currying the
    signal receiver with the user from the request (or None if the user is not authenticated).
    """

    def __init__(self, get_response=None):
        self.get_response = get_response

    @staticmethod
    def _get_remote_addr(request):
        # In case there is no proxy, return the original address
        if not request.headers.get("X-Forwarded-For"):
            return request.META.get("REMOTE_ADDR")

        # In case of proxy, set 'original' address
        remote_addr: str = request.headers.get("X-Forwarded-For").split(",")[0]

        # Remove port number from remote_addr
        if "." in remote_addr and ":" in remote_addr:  # IPv4 with port (`x.x.x.x:x`)
            remote_addr = remote_addr.split(":")[0]
        elif "[" in remote_addr:  # IPv6 with port (`[:::]:x`)
            remote_addr = remote_addr[1:].split("]")[0]

        return remote_addr

    @staticmethod
    def _get_actor(request):
        user = getattr(request, "user", None)
        if isinstance(user, get_user_model()) and user.is_authenticated:
            return user
        return None

    @staticmethod
    def _get_path_info(request):
        path_info = getattr(request, "path_info", "")
        path_info = path_info.split("/")
        try:
            path = path_info[2]
        except IndexError:
            path = None
        try:
            domain_object_id = path_info[3] if path_info[3].isnumeric() else None
        except IndexError:
            domain_object_id = None
        return path, domain_object_id

    def __call__(self, request):
        _thread_locals.current_request = request

        remote_addr = self._get_remote_addr(request)
        user = self._get_actor(request)
        path, domain_object_id = self._get_path_info(request)

        set_cid(request)

        with set_actor(actor=user, remote_addr=remote_addr, path=path, domain_object_id=domain_object_id):
            return self.get_response(request)
