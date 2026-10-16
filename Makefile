# 常用开发命令。CI 使用同一组命令（见 .github/workflows/ci.yml）。
# 依赖由 uv 管理：`uv sync --group dev` 按 uv.lock 安装；没有 uv 时可 `PY=python3 make test`（需自行装好 dev 依赖）。
UV ?= uv
RUN ?= $(UV) run --group dev
PY ?= $(RUN) python

.PHONY: help sync test cov lint node-test rules-check integrity pin lock check clean web web-demo

help:
	@echo "make web         # 启动可视化工作台 http://127.0.0.1:8765 （需 Python>=3.10，uv 会自动选择）"
	@echo "make web-demo    # 强制使用演示数据启动并打开浏览器"
	@echo "make sync        # 按 uv.lock 安装开发依赖"
	@echo "make test        # Python 单测 + 属性测试 + 契约测试 + 端到端（真实 vulnlab + 假网关）"
	@echo "make cov         # 同上并统计覆盖率（门槛见 pyproject.toml）"
	@echo "make lint        # ruff（含安全规则）+ 字节码编译"
	@echo "make node-test   # 探针库与入口烟测（node --test）"
	@echo "make rules-check # rules.json <-> 01_rules.md 规则 ID 一致"
	@echo "make integrity   # 判定代码清单与 integrity/pins.json 一致"
	@echo "make pin         # 评审后更新 integrity/pins.json（并打印带外固定值）"
	@echo "make lock        # 依赖变更后更新 uv.lock"
	@echo "make check       # 以上全部（提交前运行）"

sync:
	$(UV) sync --group dev

test:
	$(PY) -m pytest tests

cov:
	$(PY) -m pytest tests --cov --cov-report=term-missing

lint:
	$(RUN) ruff check src tools vulnlab webui tests
	$(PY) -m compileall -q src tools vulnlab webui tests

node-test:
	cd services/retest-probe && node --test "test/*.test.js"

rules-check:
	$(PY) tools/check_rules_consistency.py

integrity:
	$(PY) tools/verify_integrity.py

pin:
	$(PY) tools/pin_integrity.py

lock:
	$(UV) lock

check: lint cov node-test rules-check integrity

web:
	$(UV) run python -m webui --open

web-demo:
	$(UV) run python -m webui --source demo --open

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
