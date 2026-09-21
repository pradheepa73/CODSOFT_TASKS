from aegis.modules.code_sentinel.scan import scan_source


def test_taint_detects_eval_of_user_input():
    src = "x = input()\neval(x)\n"
    rep = scan_source(src)
    sinks = {f["sink"] for f in rep["taint_findings"]}
    assert "code execution" in sinks


def test_hardcoded_secret():
    src = 'API_KEY = "abcdef1234567890"\n'
    rep = scan_source(src)
    rules = {f["rule"] for f in rep["rule_findings"]}
    assert "Hardcoded secret" in rules


def test_parameterized_sql_not_flagged():
    src = 'cur.execute("SELECT * FROM u WHERE id = ?", (uid,))\n'
    rep = scan_source(src)
    assert all(f["sink"] != "SQL injection" for f in rep["taint_findings"])