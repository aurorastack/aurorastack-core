import logging
import logging.config
import copy

from aurorastack.core import config
from aurorastack.core.error import *
from aurorastack.core.utils import *
from aurorastack.core.logger.filters import *

__all__ = ["set_logger"]

DEFAULT_LOGGER = "aurorastack"

HANDLER_DEFAULT_CONSOLE = {
    "class": "logging.StreamHandler",
    "formatter": "standard",
    "filters": ["transaction", "masking", "exclude", "parameter", "traceback"],
}

HANDLER_DEFAULT_FILE = {
    "class": "logging.handlers.RotatingFileHandler",
    "filename": "",
    "filters": [
        "transaction",
        "masking",
        "exclude",
        "error_message",
        "parameter_log",
        "message",
        "traceback_log",
    ],
    "formatter": "file",
    "maxBytes": 10485760,  # 10 MB
    "backupCount": 10,
}

HANDLER_DEFAULT_TMPL = {
    "console": HANDLER_DEFAULT_CONSOLE,
    "file": HANDLER_DEFAULT_FILE,
}

FORMATTER_DEFAULT_TMPL = {
    "standard": {
        "format": "%(asctime)s.%(msecs)03dZ [%(levelname)s] %(trace_id)s %(tenant_id)s %(audience)s %(role_type)s %(workspace_id)s %(tnx_method)s (%(filename)s:%(lineno)d) %(message)s %(params)s %(traceback)s",
        "datefmt": "%Y-%m-%dT%H:%M:%S",
    },
    "file": {
        "format": '{"time": "%(asctime)s.%(msecs)03dZ", "level": "%(levelname)s", "peer": "%(peer)s", "trace_id": "%(trace_id)s", "tenant_id": "%(tenant_id)s", "audience": "%(audience)s", "role_type": "%(role_type)s", "tnx_method": "%(tnx_method)s", "file_name": "%(filename)s", "line": %(lineno)d, "parameter": %(params_log)s, "message": %(msg_dump)s, "error": { "code": "%(error_code)s", "message": "%(error_message)s", "traceback": %(traceback_log)s }}',
        "datefmt": "%Y-%m-%dT%H:%M:%S",
    },
}

FILTER_DEFAULT_TMPL = {
    "masking": {"()": MaskingFilter, "rules": {}},
    "transaction": {"()": TransactionFilter},
    "traceback": {"()": TracebackFilter},
    "traceback_log": {"()": TracebackLogFilter},
    "parameter": {"()": ParameterFilter},
    "parameter_log": {"()": ParameterLogFilter},
    "error_message": {"()": ErrorFilter},
    "message": {"()": MessageJsonFilter},
    "exclude": {
        "()": ExcludeFilter,
        "rules": {
            "tnx_method": [],
        },
    },
}

_LOGGER = {
    "version": 1,
    "formatters": {},
    "filters": {},
    "handlers": {"console": HANDLER_DEFAULT_CONSOLE},
    "loggers": {},
}

LOGGER_DEFAULT_TMPL = {"level": "DEBUG", "propagate": True, "handlers": ["console"]}


def set_logger(transaction=None):
    _set_config(transaction)
    logging.config.dictConfig(_LOGGER)


def _set_default_logger(default_logger):
    _LOGGER["loggers"] = {default_logger: LOGGER_DEFAULT_TMPL}
    _LOGGER["formatters"] = FORMATTER_DEFAULT_TMPL


def _set_loggers(loggers):
    for _logger in loggers:
        _LOGGER["loggers"][_logger] = deep_merge(
            loggers[_logger], copy.deepcopy(LOGGER_DEFAULT_TMPL)
        )


def _set_transaction_filter(transaction):
    if transaction:
        _LOGGER["filters"]["transaction"]["transaction"] = transaction


def _set_handlers(handlers):
    for _handler in handlers:
        _default = copy.deepcopy(HANDLER_DEFAULT_TMPL)

        if "type" in handlers[_handler]:
            if handlers[_handler]["type"] not in HANDLER_DEFAULT_TMPL:
                raise ERROR_LOG_CONFIG(reason="Logger handler type is not supported")

            _default = copy.deepcopy(HANDLER_DEFAULT_TMPL[handlers[_handler]["type"]])

        _default = deep_merge(handlers[_handler], _default)

        if "type" in _default:
            del _default["type"]

        _LOGGER["handlers"][_handler] = _default


def _set_formatters(formatters):
    for _formatter in formatters:
        _default = {}

        if "type" in formatters[_formatter]:
            if formatters[_formatter]["type"] not in FORMATTER_DEFAULT_TMPL:
                raise ERROR_LOG_CONFIG(reason="Logger formatter type is not supported")

            _default = copy.deepcopy(
                FORMATTER_DEFAULT_TMPL[formatters[_formatter]["type"]]
            )

        _default = deep_merge(formatters[_formatter]["args"], _default)

        if "type" in _default:
            del _default["type"]

        _LOGGER["formatters"][_formatter] = _default


def _set_filters(filters):
    _LOGGER["filters"] = deep_merge(filters, copy.deepcopy(FILTER_DEFAULT_TMPL))


def _set_config(transaction):
    global_log_conf = config.get_global("LOG", {})

    _set_default_logger(DEFAULT_LOGGER)

    if "loggers" in global_log_conf:
        _set_loggers(global_log_conf["loggers"])

    if "handlers" in global_log_conf:
        _set_handlers(global_log_conf["handlers"])

    if "formatters" in global_log_conf:
        _set_formatters(global_log_conf["formatters"])

    _set_filters(global_log_conf.get("filters", {}))
    _set_transaction_filter(transaction)
