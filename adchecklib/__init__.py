"""
Sample module for writing your own A—D checker.
"""

import asyncio
import enum
import logging
import sys
import traceback

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(filename)s:%(lineno)d: %(message)s'
)


class CheckerStatus(enum.Enum):
    """Checker exitcodes."""
    OK = 101
    CORRUPT = 102
    DOWN = 104
    FAILED = 110


class CheckerException(Exception):
    """Base class for defining check results."""
    def __init__(self, code, message=""):
        super().__init__()
        self.code = code
        self.message = message

    def process(self):
        """Print message and raise SystemExit with provided code."""
        print(self.message)
        print("Check finished with code", self.code.value, file=sys.stderr)
        sys.exit(self.code.value)


class OK(CheckerException):
    """Check completed successfully."""
    def __init__(self):
        super().__init__(CheckerStatus.OK)


class SetFlagId(CheckerException):
    """PUT completed successfully, with custom flag_id."""
    def __init__(self, flag_id):
        super().__init__(CheckerStatus.OK, flag_id)


class Corrupt(CheckerException):
    """GET can't retrieve old flag."""
    def __init__(self, message):
        super().__init__(CheckerStatus.CORRUPT, message)


class Down(CheckerException):
    """Service is down or broken."""
    def __init__(self, message):
        super().__init__(CheckerStatus.DOWN, message)


class CheckerError(CheckerException):
    """Internal error in checker."""
    def __init__(self):
        super().__init__(CheckerStatus.FAILED)


class BaseChecker:
    """
    Base class for writing your own checker.

    Arguments:
    - vulns - if there is several places to store flags, pass here ratio for PUT queries.
      for example, [1, 2, 3] means that there will be half flags of type 3,
      a third of flags of type 2 and a sixth of flags of type 1
    """
    def __init__(self, *, vulns=None):
        self.vulns = f'vulns:{":".join(map(str, vulns or [1]))}'
        self.logger = logging.getLogger('checker')

    async def get(self, host, flag_id, flag, vuln):
        """
        Checks if flag is present at host.

        Arguments:
        - host - IP address of vulnbox
        - flag_id - unique flag identifier (see PUT)
        - flag - value of stored flag
        - vuln - ID of vulnerability

        You should always exit raising subclass of CheckerException.
        """
        raise NotImplementedError

    async def put(self, host, flag_id, flag, vuln):
        """
        Puts a flag to host.

        Arguments:
        - host - IP address of vulnbox
        - flag_id - unique flag identifier
        - flag - value of stored flag
        - vuln - ID of vulnerability

        You should always exit raising subclass of CheckerException.

        You must be able to extract the flag later by using ONLY flag_id in `get`. Use either
        flag_id value passed as argument, or raise `SetFlagId` with new flag_id value.

        Avoid using punctuation or non-Unicode characters.
        """
        raise NotImplementedError

    async def check(self, host):
        """
        Checks a host is working correctly.

        Arguments:
        - host - IP address of vulnbox

        You should always exit raising subclass of CheckerException.
        """
        raise NotImplementedError

    async def async_run(self, argline=None):
        """Runs a check inside an asynchronous loop."""
        if argline is None:
            argline = sys.argv
        _, action, *args = argline

        try:
            if action == "info":
                raise CheckerException(CheckerStatus.OK, self.vulns)
            elif action == "check":
                host, = args
                await self.check(host)
            elif action == "put":
                host, flag_id, flag, vuln = args
                await self.put(host, flag_id, flag, vuln)
            elif action == "get":
                host, flag_id, flag, vuln = args
                await self.get(host, flag_id, flag, vuln)
            else:
                self.logger.error("Unknown action %s", action)
                self.logger.error("All args: %s", argline)
                raise CheckerError

            self.logger.error("Action handler must throw a subclass of CheckerException.")
            raise CheckerError
        except CheckerException as exc:
            if exc.code != 101:
                self.logger.exception(exc)
            exc.process()
        except: # pylint: disable=bare-except
            traceback.print_exc()
            CheckerError().process()

    def run(self, argline=None):
        """
        Runs a check.

        You may pass argline to use instead sys.argv if you're using some library which corrupts it
        (like pwntools).
        """
        asyncio.get_event_loop().run_until_complete(self.async_run(argline))
