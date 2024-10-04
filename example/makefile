.PHONY: all tests test setup
S = source
T = tests
B = build.test
D = build.prod
VENV = venv
COVER = coverage

PYTHON = ./$(VENV)/bin/python
TEST = ./$(B)/sniffer_test

all:
	cmake --build $(D)

$(TEST):
	cmake --build $(B)

test: deltest $(TEST)
	$(TEST) --gtest_filter=$(T)

deltest:
	-rm $(TEST)

clearcover:
	-rm $(COVER)/*.html
	-rm $(COVER)/*.css

tests: deltest clearcover $(TEST)
	$(TEST)
	$(PYTHON) -m gcovr --print-summary --exclude-throw-branches --source-encoding utf-8 --txt-metric branch --filter $(S)/ --html-details -o $(COVER)/coverage.html .

setup: setup_cmake setup_python setup_pip

setup_cmake:
	cmake -S $(T) -B $(B)
	cmake -S $(S) -B $(D)

setup_pip:
	$(PYTHON) -m pip install -r requirements.txt

setup_python:
	python3 -m venv ./$(VENV)
