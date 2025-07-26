.PHONY: help install install-dev test test-cov test-integration clean build upload-test upload format lint type-check docs

help:
	@echo "Comandos disponibles:"
	@echo "  install         Instalar el paquete"
	@echo "  install-dev     Instalar con dependencias de desarrollo"
	@echo "  test            Ejecutar tests"
	@echo "  test-cov        Ejecutar tests con cobertura"
	@echo "  test-integration Ejecutar tests de integración"
	@echo "  clean           Limpiar archivos generados"
	@echo "  build           Construir distribución"
	@echo "  upload-test     Subir a TestPyPI"
	@echo "  upload          Subir a PyPI"
	@echo "  format          Formatear código"
	@echo "  lint            Verificar estilo de código"
	@echo "  type-check      Verificar tipos"
	@echo "  docs            Generar documentación"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,docs]"
	pre-commit install

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=gcp_secrets_manager --cov-report=html --cov-report=term

test-integration:
	pytest tests/ -v -m integration

clean:
	rm -rf build/ dist/ *.egg-info
	rm -rf htmlcov/ .coverage .pytest_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

upload-test: build
	python -m twine upload --repository testpypi dist/*

upload: build
	python -m twine upload dist/*

format:
	black gcp_secrets_manager/ tests/ examples/
	isort gcp_secrets_manager/ tests/ examples/

lint:
	flake8 gcp_secrets_manager/ tests/
	black --check gcp_secrets_manager/ tests/
	isort --check-only gcp_secrets_manager/ tests/

type-check:
	mypy gcp_secrets_manager/

docs:
	cd docs && make clean && make html

all: format lint type-check test