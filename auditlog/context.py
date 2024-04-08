import contextlib
import time
from contextvars import ContextVar
from functools import partial

from django.contrib.auth import get_user_model
from django.db.models.signals import pre_save

from auditlog.models import LogEntry

auditlog_value = ContextVar("auditlog_value")
auditlog_disabled = ContextVar("auditlog_disabled", default=False)


@contextlib.contextmanager
def set_actor(actor, remote_addr=None, path=None, domain_object_id=None, request=None, approval_id=None):
    """Connect a signal receiver with current user attached."""
    # Initialize thread local storage
    _log_entry_signal_handler(
        actor=actor,
        remote_addr=remote_addr,
        path=path,
        domain_object_id=domain_object_id,
        request=request,
        approval_id=approval_id
    )

    try:
        yield
    finally:
        try:
            auditlog = auditlog_value.get()
        except LookupError:
            pass
        else:
            pre_save.disconnect(sender=LogEntry, dispatch_uid=auditlog["signal_duid"])

def _log_entry_signal_handler(
    actor=None,
    remote_addr=None,
    path=None,
    domain_object_id=None,
    request=None,
    approval_id=None,
):
    from auditlog.middleware import AuditlogMiddleware

    if request:
        actor = AuditlogMiddleware._get_actor(request)
        path, domain_object_id = AuditlogMiddleware._get_path_info(request)
    context_data = {
        "signal_duid": ("set_actor", time.time()),
        "remote_addr": AuditlogMiddleware._get_remote_addr(request) if request else remote_addr,
        "path": path,
        "domain_object_id": domain_object_id,
        "approval_id": approval_id,
    }
    auditlog_value.set(context_data)

    # Connect signal for automatic logging
    set_actor = partial(_set_actor, user=actor, signal_duid=context_data["signal_duid"])
    pre_save.connect(
        set_actor,
        sender=LogEntry,
        dispatch_uid=context_data["signal_duid"],
        weak=False,
    )

def _set_actor(user, sender, instance, signal_duid, **kwargs):
    """Signal receiver with extra 'user' and 'signal_duid' kwargs.

    This function becomes a valid signal receiver when it is curried with the actor and a dispatch id.
    """
    try:
        auditlog = auditlog_value.get()
    except LookupError:
        pass
    else:
        if signal_duid != auditlog["signal_duid"]:
            return
        auth_user_model = get_user_model()
        if (
            sender == LogEntry
            and isinstance(user, auth_user_model)
            and instance.actor is None
        ):
            instance.actor = user

        instance.remote_addr = auditlog["remote_addr"]
        instance.path = auditlog["path"]
        instance.domain_object_id = auditlog["domain_object_id"]
        if auditlog["approval_id"]:
            instance.approval_id = auditlog["approval_id"]


@contextlib.contextmanager
def disable_auditlog():
    token = auditlog_disabled.set(True)
    try:
        yield
    finally:
        try:
            auditlog_disabled.reset(token)
        except LookupError:
            pass

@contextlib.contextmanager
def approval(approval_id):
    from auditlog.middleware import get_current_request

    request = get_current_request()
    _log_entry_signal_handler(request=request, approval_id=approval_id)

    try:
        yield
    finally:
        try:
            auditlog = auditlog_value.get()
        except LookupError:
            pass
        else:
            pre_save.disconnect(sender=LogEntry, dispatch_uid=auditlog["signal_duid"])