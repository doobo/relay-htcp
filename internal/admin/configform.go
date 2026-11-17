package admin

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Structured config form support.
//
// The provider only declares a schema (title, field paths, widget types and
// which fields are secrets). The generic code here projects the current
// canonical YAML into form values, masks every secret, and merges submitted
// values back into YAML. Adding a tunable to the panel is therefore a
// one-line schema change, with no front-end or handler changes.
//
// Masking rules:
//   - secret values are never returned to the browser: the API sends "";
//   - on submit, an empty secret keeps the stored value (scalar fields) or
//     the value of the row it came from (table rows, matched by "_id").
func buildConfigForm(p Provider) (ConfigForm, error) {
	schema := p.ConfigFormSchema()
	doc := map[string]any{}
	if err := yaml.Unmarshal([]byte(p.CurrentConfigYAML()), &doc); err != nil {
		return ConfigForm{}, fmt.Errorf("parse current config: %w", err)
	}
	values := map[string]any{}
	for _, sec := range schema.Sections {
		for _, f := range sec.Fields {
			if f.Type == FormTable {
				var rows []any
				if raw, ok := lookupPath(doc, f.Path); ok {
					rows, _ = raw.([]any)
				}
				out := make([]any, 0, len(rows))
				for i, item := range rows {
					row, ok := item.(map[string]any)
					if !ok {
						continue
					}
					o := map[string]any{"_id": i}
					for _, col := range f.Columns {
						v, ok := row[col.Path]
						if !ok || v == nil {
							o[col.Path] = zeroDisplayValue(col)
							continue
						}
						o[col.Path] = displayValue(col, v)
					}
					out = append(out, o)
				}
				values[f.Path] = out
				continue
			}
			raw, ok := lookupPath(doc, f.Path)
			if !ok || raw == nil {
				continue
			}
			values[f.Path] = displayValue(f, raw)
		}
	}
	return ConfigForm{Sections: schema.Sections, Values: values}, nil
}

// applyConfigForm merges submitted form values into the current config and
// returns the resulting YAML. It does not validate or apply it; the caller
// runs the usual ValidateConfigYAML/ApplyConfigYAML path.
func applyConfigForm(p Provider, values map[string]any) (string, error) {
	schema := p.ConfigFormSchema()
	doc := map[string]any{}
	if err := yaml.Unmarshal([]byte(p.CurrentConfigYAML()), &doc); err != nil {
		return "", fmt.Errorf("parse current config: %w", err)
	}
	for _, sec := range schema.Sections {
		for _, f := range sec.Fields {
			raw, present := values[f.Path]
			if !present {
				continue
			}
			if f.Type == FormTable {
				var oldRows []any
				if old, ok := lookupPath(doc, f.Path); ok {
					oldRows, _ = old.([]any)
				}
				rows, ok := raw.([]any)
				if !ok {
					return "", fmt.Errorf("%s: 期望一个列表", f.Label)
				}
				out := make([]any, 0, len(rows))
				for _, item := range rows {
					row, ok := item.(map[string]any)
					if !ok {
						return "", fmt.Errorf("%s: 行格式无效", f.Label)
					}
					nr := map[string]any{}
					for _, col := range f.Columns {
						cv, has := row[col.Path]
						if !has {
							continue
						}
						if col.Type == FormSecret {
							s := strings.TrimSpace(asString(cv))
							if s != "" {
								nr[col.Path] = s
								continue
							}
							// Empty means "unchanged": copy from the row this
							// editor row was rendered from.
							if old := oldRowAt(oldRows, row["_id"]); old != nil {
								if ov, ok := old[col.Path]; ok {
									nr[col.Path] = ov
								}
							}
							continue
						}
						conv, keep, err := convertFormValue(col, cv)
						if err != nil {
							return "", err
						}
						if keep {
							// An empty CSV list is omitted so the provider sees
							// the same nil slice as an unset list (e.g. "all
							// routes") instead of a non-nil empty slice. This
							// keeps deep-equality hot-apply reports quiet.
							if col.Type == FormCSV {
								if parts, ok := conv.([]any); ok && len(parts) == 0 {
									continue
								}
							}
							// An unchecked bool in a table cell means "not
							// set", not an explicit false: optional per-row
							// flags then keep inheriting the global default.
							if col.Type == FormBool {
								if b, ok := conv.(bool); ok && !b {
									continue
								}
							}
							nr[col.Path] = conv
						}
					}
					out = append(out, nr)
				}
				assignPath(doc, f.Path, out)
				continue
			}
			conv, keep, err := convertFormValue(f, raw)
			if err != nil {
				return "", err
			}
			if keep {
				assignPath(doc, f.Path, conv)
			}
		}
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("render config: %w", err)
	}
	return string(b), nil
}

// displayValue converts a YAML value into its browser representation.
func displayValue(f FormField, v any) any {
	if f.Type == FormSecret {
		return ""
	}
	switch f.Type {
	case FormCSV:
		switch x := v.(type) {
		case []any:
			parts := make([]string, 0, len(x))
			for _, p := range x {
				parts = append(parts, asString(p))
			}
			return strings.Join(parts, ", ")
		case []string:
			return strings.Join(x, ", ")
		}
		return asString(v)
	case FormNumber:
		return v
	case FormBool:
		if b, ok := v.(bool); ok {
			return b
		}
		return asString(v) == "true"
	default:
		return asString(v)
	}
}

func zeroDisplayValue(f FormField) any {
	switch f.Type {
	case FormBool:
		return false
	case FormNumber:
		return 0
	default:
		return ""
	}
}

// convertFormValue converts one submitted value to its YAML type. keep=false
// means "leave the existing value untouched" (e.g. an empty duration).
func convertFormValue(f FormField, raw any) (any, bool, error) {
	switch f.Type {
	case FormSecret, FormText, FormSelect:
		s := strings.TrimSpace(asString(raw))
		if s == "" && f.Type == FormSecret {
			return nil, false, nil
		}
		return s, true, nil
	case FormNumber:
		switch v := raw.(type) {
		case float64:
			return int(v), true, nil
		case int:
			return v, true, nil
		case int64:
			return int(v), true, nil
		case json.Number:
			n, err := v.Int64()
			if err != nil {
				return nil, false, fmt.Errorf("%s: 请输入整数", f.Label)
			}
			return int(n), true, nil
		case string:
			s := strings.TrimSpace(v)
			if s == "" {
				return nil, false, nil
			}
			n, err := strconv.Atoi(s)
			if err != nil {
				return nil, false, fmt.Errorf("%s: 请输入整数", f.Label)
			}
			return n, true, nil
		default:
			return nil, false, fmt.Errorf("%s: 无效的数字", f.Label)
		}
	case FormBool:
		switch v := raw.(type) {
		case bool:
			return v, true, nil
		case string:
			s := strings.ToLower(strings.TrimSpace(v))
			return s == "true" || s == "on" || s == "1" || s == "yes", true, nil
		default:
			return nil, false, fmt.Errorf("%s: 无效的布尔值", f.Label)
		}
	case FormDuration:
		s := strings.TrimSpace(asString(raw))
		if s == "" {
			return nil, false, nil
		}
		if _, err := time.ParseDuration(s); err != nil {
			return nil, false, fmt.Errorf("%s: 无效的时长 %q（示例：15s、1m30s）", f.Label, s)
		}
		return s, true, nil
	case FormCSV:
		var parts []string
		switch v := raw.(type) {
		case string:
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					parts = append(parts, p)
				}
			}
		case []any:
			for _, x := range v {
				if p := strings.TrimSpace(asString(x)); p != "" {
					parts = append(parts, p)
				}
			}
		case []string:
			parts = append(parts, v...)
		default:
			return nil, false, fmt.Errorf("%s: 期望逗号分隔的列表", f.Label)
		}
		out := make([]any, len(parts))
		for i, p := range parts {
			out[i] = p
		}
		return out, true, nil
	default:
		return asString(raw), true, nil
	}
}

func asString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case json.Number:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

// oldRowAt returns the previous row referenced by an editor row's "_id".
func oldRowAt(rows []any, id any) map[string]any {
	n, ok := idNumber(id)
	if !ok || n < 0 || n >= len(rows) {
		return nil
	}
	row, _ := rows[n].(map[string]any)
	return row
}

func idNumber(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case int64:
		return int(x), true
	case json.Number:
		n, err := x.Int64()
		return int(n), err == nil
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		return n, err == nil
	default:
		return 0, false
	}
}

func lookupPath(doc map[string]any, path string) (any, bool) {
	var cur any = doc
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func assignPath(doc map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	cur := doc
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = v
}
