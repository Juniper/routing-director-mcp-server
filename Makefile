all: build

build:
	python3 setup.py sdist --dist-dir dist/

clean:
	rm -rf build dist *.egg-info