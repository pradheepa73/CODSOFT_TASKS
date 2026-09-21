"""Inter-procedural taint analysis over Python AST."""
from __future__ import annotations
import ast
from dataclasses import dataclass, field

SOURCE_CALLS = {"input", "os.environ.get", "os.getenv", "sys.argv"}
SOURCE_ATTRS = {
    "request.args", "request.form", "request.json", "request.data",
    "request.values", "request.cookies", "request.headers",
}
SINK_CALLS = {
    "eval": "code execution",
    "exec": "code execution",
    "os.system": "command injection",
    "os.popen": "command injection",
    "subprocess.run": "command injection",
    "subprocess.call": "command injection",
    "subprocess.Popen": "command injection",
    "subprocess.check_output": "command injection",
    "cursor.execute": "SQL injection",
    "connection.execute": "SQL injection",
    "pickle.loads": "insecure deserialization",
    "yaml.load": "unsafe yaml load",
    "marshal.loads": "unsafe deserialization",
}


@dataclass
class Finding:
    rule: str
    line: int
    col: int
    snippet: str
    source: str
    sink: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule, "line": self.line, "col": self.col,
            "snippet": self.snippet, "source": self.source, "sink": self.sink,
        }


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return None


def _is_source(node):
    n = _name(node)
    if not n:
        return None
    if n in SOURCE_CALLS:
        return n
    for src in SOURCE_ATTRS:
        if n.startswith(src):
            return src
    return None


def _is_sink(node):
    n = _name(node)
    return SINK_CALLS.get(n) if n else None


@dataclass
class TaintVisitor(ast.NodeVisitor):
    source_code: str
    tainted_names: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def visit_Assign(self, node):
        origin = self._expr_taint(node.value)
        if origin:
            for target in node.targets:
                tname = _name(target)
                if tname:
                    self.tainted_names[tname] = origin
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value:
            origin = self._expr_taint(node.value)
            tname = _name(node.target)
            if origin and tname:
                self.tainted_names[tname] = origin
        self.generic_visit(node)

    def visit_Call(self, node):
        sink = _is_sink(node)
        if sink:
            for arg in node.args:
                origin = self._expr_taint(arg)
                if origin:
                    self.findings.append(Finding(
                        rule=sink,
                        line=getattr(node, "lineno", 0),
                        col=getattr(node, "col_offset", 0),
                        snippet=ast.get_source_segment(self.source_code, node) or "",
                        source=origin,
                        sink=sink,
                    ))
                    break
        self.generic_visit(node)

    def _expr_taint(self, node):
        direct = _is_source(node)
        if direct:
            return direct
        if isinstance(node, ast.Name):
            return self.tainted_names.get(node.id)
        if isinstance(node, ast.BinOp):
            return self._expr_taint(node.left) or self._expr_taint(node.right)
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t = self._expr_taint(v.value)
                    if t:
                        return t
        if isinstance(node, ast.Attribute):
            return self._expr_taint(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_taint(node.value) or self._expr_taint(node.slice)
        if isinstance(node, ast.Call):
            for a in node.args:
                t = self._expr_taint(a)
                if t:
                    return t
        return None


def analyze(source: str):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    visitor = TaintVisitor(source_code=source)
    visitor.visit(tree)
    return visitor.findings