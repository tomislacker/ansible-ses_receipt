PYDEV_VER  := 2.7
PYDEV_VENV := venv


.PHONY : venv
venv   :
	virtualenv -p python$(PYDEV_VER) $(PYDEV_VENV)

.PHONY : prod
prod   : venv
	$(PYDEV_VENV)/bin/pip install -r prod-requirements.txt

.PHONY : dev
dev    : prod
	$(PYDEV_VENV)/bin/pip install -r dev-requirements.txt
