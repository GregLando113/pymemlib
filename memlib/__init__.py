
import sys

# probably a better way
_PROCESS_IS_64_BITS = sys.maxsize > 2 ** 32

from .win32   import *
from .process import *
from .module  import *
from .scanner import *
from .thread  import *
from .memory  import *
from .function_caller import *