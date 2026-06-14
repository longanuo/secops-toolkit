.PHONY: install test lint docker docker-up docker-down clean

install:
	pip install -e secops-core/ -e secops-offense/ -e secops-defense/ -e secops-cli/

test:
	python -m unittest discover -s secops-core/tests -v
	python -m unittest discover -s secops-offense/tests -v
	python -m unittest discover -s secops-defense/tests -v
	python -m unittest discover -s secops-cli/tests -v

lint:
	flake8 secops-core/ secops-offense/ secops-defense/ secops-cli/

docker:
	docker build -t secops-toolbox .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-scan:
	docker-compose run --rm secops --scan http://target-web

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf *.egg-info dist build
