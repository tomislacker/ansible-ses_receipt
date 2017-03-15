PYDEV_VER  := 2.7
PYDEV_VENV := venv


.DEFAULT_GOAL := run

.PHONY : venv
venv   :
	virtualenv -p python$(PYDEV_VER) $(PYDEV_VENV)

.PHONY : prod
prod   : venv
	$(PYDEV_VENV)/bin/pip install -r prod-requirements.txt

.PHONY : dev
dev    : prod
	$(PYDEV_VENV)/bin/pip install -r dev-requirements.txt

.PHONY : deps
deps   :
	make -C library

.PHONY : run
run    : deps
	ansible-playbook \
		-i inventory/ \
		-l us-east-1 \
		site.yml \
		--diff \
		-vv
