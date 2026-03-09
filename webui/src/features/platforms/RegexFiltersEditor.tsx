import { Plus, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Button } from "../../components/ui/Button";
import { Input } from "../../components/ui/Input";
import { Select } from "../../components/ui/Select";
import { Textarea } from "../../components/ui/Textarea";
import { parseLinesToList } from "./formParsers";

type RuleAction = "include" | "exclude";
type RuleScope = "full" | "name" | "tag";

type RuleDraft = {
  action: RuleAction;
  scope: RuleScope;
  pattern: string;
};

type RegexFiltersEditorProps = {
  value: string | undefined;
  onChange: (next: string) => void;
  idPrefix: string;
};

function parseRuleLine(line: string): RuleDraft {
  let raw = line.trim();
  let action: RuleAction = "include";
  if (raw.startsWith("!")) {
    action = "exclude";
    raw = raw.slice(1).trim();
  }

  let scope: RuleScope = "full";
  const m = raw.match(/^(full|name|tag)\s*:(.*)$/i);
  if (m) {
    const candidate = m[1].toLowerCase();
    if (candidate === "name" || candidate === "tag" || candidate === "full") {
      scope = candidate;
    }
    raw = m[2].trim();
  }

  return { action, scope, pattern: raw };
}

function stringifyRule(rule: RuleDraft): string {
  const pattern = rule.pattern.trim();
  if (!pattern) {
    return "";
  }
  const base = rule.scope === "full" ? pattern : `${rule.scope}:${pattern}`;
  return rule.action === "exclude" ? `!${base}` : base;
}

type RuleEval = {
  line: string;
  ok: boolean;
  detail: string;
};

function evaluateRules(lines: string[], subName: string, nodeTag: string): { ruleResults: RuleEval[]; passed: boolean } {
  const name = subName.trim();
  const tag = nodeTag.trim();
  const full = `${name}/${tag}`;
  const candidates = { full, name, tag };

  if (!name || !tag) {
    return { ruleResults: [], passed: false };
  }

  const includeMatched: boolean[] = [];
  const results: RuleEval[] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const rule = parseRuleLine(line);
    const target = rule.scope === "name" ? candidates.name : rule.scope === "tag" ? candidates.tag : candidates.full;
    const parts = rule.pattern.split("||").map((p) => p.trim()).filter(Boolean);
    let matched = false;
    let regexErr = "";
    for (const part of parts) {
      try {
        const re = new RegExp(part);
        if (re.test(target)) {
          matched = true;
          break;
        }
      } catch (err) {
        regexErr = String(err);
        break;
      }
    }

    if (regexErr) {
      results.push({ line, ok: false, detail: `正则错误: ${regexErr}` });
      includeMatched.push(false);
      continue;
    }

    if (rule.action === "exclude") {
      const ok = !matched;
      results.push({
        line,
        ok,
        detail: matched ? `命中排除(${rule.scope}) -> 拒绝` : `未命中排除(${rule.scope})`,
      });
      continue;
    }

    includeMatched.push(matched);
    results.push({
      line,
      ok: matched,
      detail: matched ? `命中包含(${rule.scope})` : `未命中包含(${rule.scope})`,
    });
  }

  const hasInclude = lines.some((line) => line.trim() && parseRuleLine(line).action === "include");
  const includeAllPass = hasInclude ? includeMatched.every(Boolean) : true;
  const excludePass = results.filter((r) => r.line.startsWith("!")).every((r) => r.ok);
  return {
    ruleResults: results,
    passed: includeAllPass && excludePass,
  };
}

export function RegexFiltersEditor({ value, onChange, idPrefix }: RegexFiltersEditorProps) {
  const [rawMode, setRawMode] = useState(false);
  const [testSubName, setTestSubName] = useState("");
  const [testNodeTag, setTestNodeTag] = useState("");

  const rules = useMemo(() => {
    const lines = parseLinesToList(value);
    return lines.map(parseRuleLine);
  }, [value]);
  const ruleLines = useMemo(() => parseLinesToList(value), [value]);
  const evalResult = useMemo(
    () => evaluateRules(ruleLines, testSubName, testNodeTag),
    [ruleLines, testSubName, testNodeTag],
  );

  const commit = (nextRules: RuleDraft[]) => {
    const lines = nextRules.map(stringifyRule).filter(Boolean);
    onChange(lines.join("\n"));
  };

  const addRule = () => {
    commit([...rules, { action: "include", scope: "full", pattern: "" }]);
  };

  const updateRule = (index: number, patch: Partial<RuleDraft>) => {
    const next = rules.map((rule, i) => (i === index ? { ...rule, ...patch } : rule));
    commit(next);
  };

  const removeRule = (index: number) => {
    const next = rules.filter((_, i) => i !== index);
    commit(next);
  };

  return (
    <div style={{ display: "grid", gap: "8px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "8px" }}>
        <div className="muted" style={{ fontSize: 12 }}>
          可视化规则支持 `name:` / `tag:` / `full:`、`!` 排除、`||` 或条件（写在模式里）。
        </div>
        <Button type="button" variant="secondary" size="sm" onClick={() => setRawMode((v) => !v)}>
          {rawMode ? "切回可视化" : "高级文本模式"}
        </Button>
      </div>

      {rawMode ? (
        <Textarea
          id={`${idPrefix}-raw`}
          rows={6}
          placeholder={"name:^(HK|JP)$\ntag:(?i)netflix||disney\n!tag:test"}
          value={value ?? ""}
          onChange={(event) => onChange(event.target.value)}
        />
      ) : (
        <div style={{ display: "grid", gap: "8px" }}>
          {rules.map((rule, index) => (
            <div
              key={`${idPrefix}-rule-${index}`}
              style={{
                border: "1px solid var(--border)",
                borderRadius: "8px",
                padding: "8px",
                display: "grid",
                gridTemplateColumns: "1.2fr 1fr 3fr auto",
                gap: "8px",
                alignItems: "end",
                background: "var(--surface-sunken, rgba(0,0,0,0.02))",
              }}
            >
              <div>
                <label className="field-label" style={{ marginBottom: 6 }}>规则</label>
                <Select
                  id={`${idPrefix}-action-${index}`}
                  value={rule.action}
                  onChange={(event) => {
                    updateRule(index, { action: event.target.value === "exclude" ? "exclude" : "include" });
                  }}
                >
                  <option value="include">包含</option>
                  <option value="exclude">排除</option>
                </Select>
              </div>
              <div>
                <label className="field-label" style={{ marginBottom: 6 }}>作用域</label>
                <Select
                  id={`${idPrefix}-scope-${index}`}
                  value={rule.scope}
                  onChange={(event) => {
                    const scope = event.target.value === "name" || event.target.value === "tag" ? event.target.value : "full";
                    updateRule(index, { scope });
                  }}
                >
                  <option value="full">full(订阅/节点)</option>
                  <option value="name">name(订阅名)</option>
                  <option value="tag">tag(节点名)</option>
                </Select>
              </div>
              <div>
                <label className="field-label" style={{ marginBottom: 6 }}>模式</label>
                <Input
                  id={`${idPrefix}-pattern-${index}`}
                  value={rule.pattern}
                  placeholder="例如 (?i)hk||sg"
                  onChange={(event) => updateRule(index, { pattern: event.target.value })}
                />
              </div>
              <Button type="button" variant="ghost" size="sm" onClick={() => removeRule(index)}>
                <Trash2 size={14} />
                删除
              </Button>
            </div>
          ))}
          <div>
            <Button type="button" variant="secondary" size="sm" onClick={addRule}>
              <Plus size={14} />
              新增规则
            </Button>
          </div>
        </div>
      )}

      <div
        style={{
          border: "1px dashed var(--border)",
          borderRadius: "8px",
          padding: "10px",
          display: "grid",
          gap: "8px",
        }}
      >
        <div style={{ fontWeight: 600 }}>规则调试器</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
          <div>
            <label className="field-label" style={{ marginBottom: 6 }}>订阅名(name)</label>
            <Input value={testSubName} placeholder="例如 Default" onChange={(e) => setTestSubName(e.target.value)} />
          </div>
          <div>
            <label className="field-label" style={{ marginBottom: 6 }}>节点名(tag)</label>
            <Input value={testNodeTag} placeholder="例如 hk-netflix-01" onChange={(e) => setTestNodeTag(e.target.value)} />
          </div>
        </div>
        <div className="muted" style={{ fontSize: 12 }}>
          full 值为：`{testSubName.trim() || "?"}/{testNodeTag.trim() || "?"}`
        </div>
        {testSubName.trim() && testNodeTag.trim() ? (
          <div style={{ display: "grid", gap: "6px" }}>
            <div style={{ fontWeight: 600, color: evalResult.passed ? "var(--success)" : "var(--danger)" }}>
              最终结果：{evalResult.passed ? "匹配通过" : "匹配不通过"}
            </div>
            {evalResult.ruleResults.map((item, idx) => (
              <div
                key={`${idPrefix}-eval-${idx}`}
                style={{
                  border: "1px solid var(--border)",
                  borderRadius: "6px",
                  padding: "6px 8px",
                  background: item.ok ? "rgba(16,185,129,0.08)" : "rgba(239,68,68,0.08)",
                }}
              >
                <div style={{ fontFamily: "monospace", fontSize: 12 }}>{item.line}</div>
                <div style={{ fontSize: 12 }}>{item.detail}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="muted" style={{ fontSize: 12 }}>输入订阅名和节点名后可实时调试规则。</div>
        )}
      </div>
    </div>
  );
}
