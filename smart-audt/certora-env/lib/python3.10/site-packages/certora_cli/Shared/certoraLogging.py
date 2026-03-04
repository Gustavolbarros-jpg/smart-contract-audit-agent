#     The Certora Prover
#     Copyright (C) 2025  Certora Ltd.
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, version 3 of the License.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.

import logging
import sys
from typing import Dict, Any, Set, Optional, Iterable, List
from Shared.certoraUtils import write_json_file, red_text, orange_text, get_debug_log_file
from Shared.certoraUtils import get_resource_errors_file


class ColoredString(logging.Formatter):
    def __init__(self, msg_fmt: str = "%(name)s - %(message)s") -> None:
        super().__init__(msg_fmt)

    def format(self, record: logging.LogRecord) -> str:
        to_ret = super().format(record)
        if record.levelno == logging.WARN:
            return orange_text("WARNING") + ": " + to_ret
        elif record.levelno >= logging.ERROR:  # aka ERROR, FATAL, and CRITICAL
            return red_text(record.levelname) + ": " + to_ret
        else:  # aka WARNING, INFO, and DEBUG
            return record.levelname + ": " + to_ret


class TopicFilter(logging.Filter):
    def __init__(self, names: Iterable[str]) -> None:
        super().__init__()
        self.logged_names = set(names)

    def filter(self, record: logging.LogRecord) -> bool:
        return (record.name in self.logged_names) or record.levelno >= logging.WARN


class ResourceErrorHandler(logging.NullHandler):
    """
    A handler that creates a JSON error report for all problems concerning resources, like Solidity and spec files.
    The handler gathers log messages, filters them, and maintain a local data state.
    To generate the report, dump_to_log must be called. It should be called in the shutdown code of certoraRun.py
    This class is a Singleton, which should prevent most concurrency issues.
    ~~~~
    Filter logic:
    We only care about messages with a topic in resource topics, that are of logging level CRITICAL.
    We prettify the message string itself to be concise and less verbose.
    TODO - fetch typechecking errors from a file. The typechecking jar should generate an errors file, giving us more
    control.
    Note - we have no choice but to filter SOLC errors, for example.
    """
    resource_topics = ["solc", "type_check"]

    """
    errors_info is a JSON object that should look like this:
    {
        "topics": [
            {
                "name": "",
                "messages": [
                    {
                        "message": "",
                        "location": []
                    }
                ]
            }
        ]
    }
    """
    errors_info: Dict[str, Any] = {
        "topics": []
    }

    # ~~~ Message editing constants
    """
    If one of this identifiers is present in the message, we log it. This is to avoid superfluous messages like
    "typechecking failed".
    "Severe compiler warning:" is there to handle errors originating from certoraBuild.check_for_errors_and_warnings()
    """
    error_identifiers = ["Syntax error", "Severe compiler warning:", "error:\n"]

    # We delete these prefixes and everything that came before them
    prefix_delimiters = ["ERROR ALWAYS - ", "ParserError:\n", "error:\n"]

    def __init__(self) -> None:
        super(ResourceErrorHandler, self).__init__()

    def handle(self, record: logging.LogRecord) -> bool:
        if (record.name in self.resource_topics) and record.levelno >= logging.CRITICAL:
            message = record.getMessage()
            for identifier in self.error_identifiers:
                if identifier in message:
                    for delimiter in self.prefix_delimiters:
                        if delimiter in message:
                            message = message.split(delimiter)[1].strip()

                    message = message.splitlines()[0]  # Removing all but the first remaining line

                    # Adding the message to errors_info
                    error_dict = {
                        "message": message,
                        "location": []  # TODO - add location in the future, at least for Syntax errors
                    }

                    topic_found = False
                    for topic in self.errors_info["topics"]:
                        if topic["name"] == record.name:
                            topic["messages"].append(error_dict)
                            topic_found = True
                            break

                    if not topic_found:
                        topic_dict = {
                            "name": record.name,
                            "messages": [
                                error_dict
                            ]
                        }
                        self.errors_info["topics"].append(topic_dict)

                    break  # Do not log the same error twice, even if it has more than one identifier
        return True

    def dump_to_log(self) -> None:
        write_json_file(self.errors_info, get_resource_errors_file())

    def close(self) -> None:
        self.dump_to_log()
        super().close()


class DebugLogHandler(logging.FileHandler):
    """
    A handler that writes all errors, of all levels Debug-critical, to the debug log file and sends it to the cloud.
    The problems reported are concerning the topics depicted below at the logging_setup() function.
    """

    def __init__(self) -> None:
        super().__init__(get_debug_log_file())
        self.set_name("debug_log")
        self.level = logging.DEBUG  # Always set this handler's log-level to debug
        self.addFilter(TopicFilter(["arguments",
                                    "build_conf",
                                    "build_cache",
                                    "finder_instrumentaton",
                                    "rpc",
                                    "run",
                                    "solc",
                                    "type_check",
                                    "verification"
                                    ]))


class LoggingManager():
    """
    A class that manages logs, be they file logs or stdout logs. Used for:
    * Adding or removing logs
    * Setting log levels and outputs
    * Checking whether we are in debug mode via LoggingManager().is_debugging
    """

    def __init__(self, quiet: bool = False, debug: bool = False,
                 debug_topics: Optional[List[str]] = None,
                 show_debug_topics: bool = False) -> None:
        """
        @param quiet: if true, we show minimal log messages, and logging level is WARNING.
        @param debug:
            Ignored if quiet is True.
            If it is None, we are not in DEBUG mode, and logging level is WARNING.
            Otherwise, logging level is DEBUG, and it is a list of debug topic names.
            Only debug messages related to loggers of those topics are recorded.
            If it is an empty list, we record ALL topics.
        @param show_debug_topics: Ignored if either quiet is True or debug is None. If True, sets the logging message
                                  format to show the topic of the logger that sent them.
        """
        self.debug_log_handler = DebugLogHandler()
        self.resource_error_handler = ResourceErrorHandler()
        self.stdout_handler = logging.StreamHandler(stream=sys.stdout)
        self.handlers: Set[logging.Handler] = set()

        root_logger = logging.root
        self.orig_root_log_level = root_logger.level  # used to restore the root logger's level after exit
        root_logger.setLevel(logging.NOTSET)  # We record all logs in the debug log file

        handler_list: List[logging.Handler] = [self.debug_log_handler, self.stdout_handler, self.resource_error_handler]
        for handler in handler_list:
            self.__add_handler(handler)

        self.set_log_level_and_format(quiet, debug, debug_topics, show_debug_topics)

    def __tear_down(self) -> None:
        """
        A destructor - releases all resources and restores the root logger to the state it was in before this class
        was constructed
        """
        root_logger = logging.root
        root_logger.setLevel(self.orig_root_log_level)

        while self.handlers:
            _handler = next(iter(self.handlers))
            self.__remove_handler(_handler)

    def __add_handler(self, handler: logging.Handler) -> None:
        """
        Adds a new handler to the root logger
        """
        if handler not in self.handlers:
            self.handlers.add(handler)
            logging.root.addHandler(handler)
        else:
            logging.warning(f"Tried to add a handler that was already active: {handler}")

    def __remove_handler(self, handler: logging.Handler) -> None:
        """
        Closes and removes a handler from the root logger
        """
        if handler in self.handlers:
            try:
                handler.close()
            except Exception as e:
                logging.warning(f"Failed to close {handler}: {repr(e)}")
            self.handlers.remove(handler)
            logging.root.removeHandler(handler)
        else:
            logging.warning(f"Tried to remove a handler that is not active: {handler}")

    def set_log_level_and_format(
            self,
            is_quiet: bool = False,
            debug: bool = False,
            debug_topics: Optional[List[str]] = None,
            show_debug_topics: bool = False) -> None:
        """
        Sets the logging level and log message format.
        @param is_quiet: if true, we show minimal log messages, and logging level is WARNING. No debug topics can be
            enabled.
        @param debug: if true, we show debug information (for all topics)
        @param debug_topics:
            Ignored if is_quiet is True.
            If it is None, we are not in DEBUG mode, and logging level is WARNING.
            Otherwise, logging level is DEBUG, and it is a list of debug topic names.
            Only debug messages related to loggers of those topics are recorded.
            If it is an empty list, we record ALL topics.
        @param show_debug_topics: Ignored if either quiet is True or debug is None. If True, sets the logging message
                                  format to show the topic of the logger that sent them.
        """
        self.__format_stdout_log_messages(show_debug_topics)
        self.__set_logging_level(is_quiet, debug, debug_topics)

    def remove_debug_logger(self) -> None:
        self.__remove_handler(self.debug_log_handler)

    def __format_stdout_log_messages(self, show_debug_topics: bool) -> None:
        """
        Sets the log message format.
        @param show_debug_topics:
            If True, sets the logging message format to show the topic of the logger that sent them.
        """
        if show_debug_topics:
            base_message = "%(name)s - %(message)s"
        else:
            base_message = "%(message)s"

        if sys.stdout.isatty():
            self.stdout_handler.setFormatter(ColoredString(base_message))
        else:
            self.stdout_handler.setFormatter(logging.Formatter(f'%(levelname)s: {base_message}'))

    def __set_logging_level(self, is_quiet: bool, debug: bool = False, debug_topics: Optional[List[str]] = None) \
            -> None:
        """
        Sets the logging level.
        @param is_quiet: if true, we show minimal log messages, and logging level is WARNING. No debug topics can be
            enabled
        @param debug: is debug enabled
        @param debug_topics:
            Ignored if is_quiet is True.
            If it is None, we are not in DEBUG mode, and logging level is WARNING.
            Otherwise, logging level is DEBUG, and it is a list of debug topic names.
            Only debug messages related to loggers of those topics are recorded.
            If it is an empty list, we record ALL topics.
        """
        if is_quiet or not debug:
            self.__set_handlers_level(logging.INFO)
            self.is_debugging = False
        else:
            self.__set_handlers_level(logging.DEBUG)
            self.is_debugging = True

        self.__set_topics_filter(debug_topics)

    def __set_handlers_level(self, level: int) -> None:
        """
        Sets the level of all handlers to the given logging level, except the debug log handler
        @param level - A logging level such as logging.DEBUG
        We assume the level is a number that represents valid logging level!
        """
        for handler in self.handlers:
            if handler != self.debug_log_handler:
                handler.setLevel(level)

    def __set_topics_filter(self, debug_topics: Optional[List[str]] = None) -> None:
        """
        Adds a filter to the stdout logger to ignore logging topics not provided.
        @param debug_topics -
            If it is None, we are not in DEBUG mode, and logging level is WARNING.
            Otherwise, logging level is DEBUG, and it is a list of debug topic names.
            Only debug messages related to loggers of those topics are recorded.
            If it is an empty list, we record ALL topics.
        """
        for _filter in self.stdout_handler.filters:
            self.stdout_handler.removeFilter(_filter)
        if self.is_debugging and debug_topics is not None and len(debug_topics) > 0:
            topics = [n.strip() for n in debug_topics]
            self.stdout_handler.addFilter(TopicFilter(topics))

    def __del__(self) -> None:
        self.__tear_down()
