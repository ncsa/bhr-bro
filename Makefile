bhr-bro.pex: bhr.py setup.py
	pex --python-shebang='/usr/bin/env python' -o bhr-bro.pex . ../bhr-client -c bhr-bro
