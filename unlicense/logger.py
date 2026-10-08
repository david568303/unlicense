import logging
import os
import sys

import lief


def setup_logger(logger: logging.Logger, verbose: bool) -> None:
    lief.logging.disable()
    if verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logger.setLevel(log_level)

    # Create a console handler with a higher log level
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)

    stream_handler.setFormatter(
        CustomFormatter(_supports_color(stream_handler.stream)))

    logger.addHandler(stream_handler)


class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    green = "\x1b[1;32m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_problem_str = "%(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: grey + "%(levelname)s - %(message)s" + reset,
        logging.INFO: green + "%(levelname)s" + reset + " - %(message)s",
        logging.WARNING: yellow + format_problem_str + reset,
        logging.ERROR: red + format_problem_str + reset,
        logging.CRITICAL: bold_red + format_problem_str + reset
    }

    def __init__(self, use_color: bool = True):
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        if self.use_color:
            log_fmt = self.FORMATS.get(record.levelno)
        else:
            log_fmt = self.format_problem_str
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def _supports_color(stream: object) -> bool:
    is_a_tty = getattr(stream, "isatty", lambda: False)()
    if not is_a_tty:
        return False
    if os.name != "nt":
        return True
    # Windows 7 consoles print ANSI escape sequences literally. Windows 10+
    # terminals used by the existing releases generally support them.
    return sys.getwindowsversion().major >= 10
