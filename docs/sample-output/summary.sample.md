# 漏洞复测摘要（20261013151645-27575）

- 生成时间：2026-10-13T15:16:45+0800
- 规则版本：2.0　代码清单摘要：`36bf1c725b47d959`（完整性：OK）
- 汇总：{"total": 4, "VULNERABLE": 2, "SURFACE_PATCH": 1, "WAF_FULL_BLOCK": 0, "PATCHED": 1, "INCONCLUSIVE": 0}

| 漏洞 | 类型 | 判定 | 关键度量 | 证据 |
|---|---|---|---|---|
| VULN-2026-001 用户查询接口布尔盲注 | boolean_blind | **VULNERABLE** | ratio=0.625；delta=45；sha_identical=False | probe_VULN-2026-001_tautology.json<br>probe_VULN-2026-001_contradiction.json<br>probe_VULN-2026-001_baseline.json |
| VULN-2026-002 搜索接口反射型 XSS（历史处置：WAF 关键字拦截） | reflection_diff | **SURFACE_PATCH** | waf_active=True；bypass_reflected=True；literal_state=blocked；bypass_state=reflected | probe_VULN-2026-002_literal_script.json<br>probe_VULN-2026-002_variant_onerror.json |
| VULN-2026-003 管理接口越权访问（伪造凭据） | idem_forge | **PATCHED** | sha_identical=True；plain_status=403；forged_status=403 | probe_VULN-2026-003_plain.json<br>probe_VULN-2026-003_forged_cookie.json |
| VULN-2026-004 订单接口水平越权（IDOR） | idor | **VULNERABLE** | own_status=200；cross_status=200；victim_status=200；cross_equals_victim=True | probe_VULN-2026-004_own.json<br>probe_VULN-2026-004_cross.json<br>probe_VULN-2026-004_victim.json |

## 相对上一轮的变化

- VULN-2026-001：（首次） → **VULNERABLE**（new）
- VULN-2026-002：（首次） → **SURFACE_PATCH**（new）
- VULN-2026-003：（首次） → **PATCHED**（new）
- VULN-2026-004：（首次） → **VULNERABLE**（new）

> 本文件由 `src/state.py` 确定性生成。LLM 解读（如有）见 `outputs/interpretation.md`。
