import sys

if not sys.version.startswith(('3.8', '3.9', '3.10', '3.11', '3.12')):
    sys.exit('FCDM requires Python 3.8+')

from .fcdm_controller import main

sys.exit(main())