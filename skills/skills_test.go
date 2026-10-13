package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// nameRe enforces the spec name rules in one pattern: 1+ lowercase alphanumeric
// runs joined by single hyphens — which rules out leading/trailing/consecutive
// hyphens and any uppercase or other characters.
var nameRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// refRe finds references to bundled files so we can confirm they exist.
var refRe = regexp.MustCompile(`(references|scripts|assets)/[A-Za-z0-9._\-/]+`)

const (
	maxNameLen        = 64
	maxDescriptionLen = 1024
	maxCompatLen      = 500
	maxBodyLines      = 500
)

func TestSkillsMatchSpecification(t *testing.T) {
	found, err := findSkills([]string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("no SKILL.md files found")
	}
	for _, path := range found {
		errs, _ := validate(path)
		for _, e := range errs {
			t.Errorf("%s: %s", path, e)
		}
	}
}

func TestValidateRejectsBrokenSkill(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my-skill")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "SKILL.md")
	body := "---\nname: other-name\ndescription: x\n---\nSee references/missing.md\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	errs, _ := validate(path)
	if len(errs) != 2 {
		t.Fatalf("errors = %q, want name mismatch and missing reference", errs)
	}
}

// findSkills returns the path to every SKILL.md under the given roots.
func findSkills(roots []string) ([]string, error) {
	var out []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && d.Name() == "SKILL.md" {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// validate checks a single SKILL.md and returns errors and warnings.
func validate(skillPath string) (errs, warns []string) {
	skillDir := filepath.Dir(skillPath)
	dirName := filepath.Base(skillDir)

	data, err := os.ReadFile(skillPath)
	if err != nil {
		return []string{fmt.Sprintf("cannot read file: %v", err)}, nil
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	// Frontmatter must be delimited by --- on the first line and a later --- line.
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return []string{"missing YAML frontmatter (file must start with '---')"}, nil
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return []string{"unterminated YAML frontmatter (missing closing '---')"}, nil
	}

	fm := strings.Join(lines[1:end], "\n")
	var meta map[string]any
	if err := yaml.Unmarshal([]byte(fm), &meta); err != nil {
		return []string{fmt.Sprintf("frontmatter is not valid YAML: %v", err)}, nil
	}

	// name (required)
	name, ok := meta["name"].(string)
	switch {
	case meta["name"] == nil:
		errs = append(errs, "missing required field: name")
	case !ok:
		errs = append(errs, "name must be a string")
	default:
		if name == "" || len(name) > maxNameLen {
			errs = append(errs, fmt.Sprintf("name must be 1-%d characters", maxNameLen))
			break
		}
		if !nameRe.MatchString(name) {
			errs = append(errs, "name must be lowercase alphanumeric with single hyphens (no leading/trailing/consecutive hyphens)")
		}
		if name != dirName {
			errs = append(errs, fmt.Sprintf("name %q must match parent directory name %q", name, dirName))
		}
	}

	// description (required)
	desc, ok := meta["description"].(string)
	switch {
	case meta["description"] == nil:
		errs = append(errs, "missing required field: description")
	case !ok:
		errs = append(errs, "description must be a string")
	default:
		if strings.TrimSpace(desc) == "" {
			errs = append(errs, "description must be non-empty")
		}
		if len(desc) > maxDescriptionLen {
			errs = append(errs, fmt.Sprintf("description must be at most %d characters (got %d)", maxDescriptionLen, len(desc)))
		}
	}

	// compatibility (optional)
	if v, present := meta["compatibility"]; present {
		s, ok := v.(string)
		if !ok {
			errs = append(errs, "compatibility must be a string")
		} else if strings.TrimSpace(s) == "" || len(s) > maxCompatLen {
			errs = append(errs, fmt.Sprintf("compatibility must be 1-%d characters", maxCompatLen))
		}
	}

	// license (optional)
	if v, present := meta["license"]; present {
		if s, ok := v.(string); !ok || strings.TrimSpace(s) == "" {
			errs = append(errs, "license must be a non-empty string")
		}
	}

	// allowed-tools (optional)
	if v, present := meta["allowed-tools"]; present {
		if _, ok := v.(string); !ok {
			errs = append(errs, "allowed-tools must be a space-separated string")
		}
	}

	// metadata (optional): map of string -> string
	if v, present := meta["metadata"]; present {
		m, ok := v.(map[string]any)
		if !ok {
			errs = append(errs, "metadata must be a mapping")
		} else {
			for k, val := range m {
				if _, ok := val.(string); !ok {
					errs = append(errs, fmt.Sprintf("metadata.%s must be a string (quote values like version: \"1.0\")", k))
				}
			}
		}
	}

	// Warn on unrecognized frontmatter keys — catches typos like "desciption"
	// that would otherwise silently fail their (missing) validation.
	known := map[string]bool{
		"name": true, "description": true, "compatibility": true,
		"license": true, "allowed-tools": true, "metadata": true,
	}
	for k := range meta {
		if !known[k] {
			warns = append(warns, fmt.Sprintf("unknown frontmatter field %q (possible typo?)", k))
		}
	}

	// Body size: keep the post-frontmatter body under the recommended ceiling.
	// Trim the trailing newline so a file ending in "\n" isn't counted as one
	// line longer than it is.
	body := strings.Join(lines[end+1:], "\n")
	bodyLines := len(strings.Split(strings.TrimRight(body, "\n"), "\n"))
	if bodyLines > maxBodyLines {
		errs = append(errs, fmt.Sprintf("SKILL.md body is %d lines; keep it under %d (move detail into references/)", bodyLines, maxBodyLines))
	}

	// Referenced files must exist, stay inside the skill directory, and be
	// shallow. The containment check rejects traversal (e.g. references/../..)
	// before os.Stat ever touches a path outside skillDir.
	seen := map[string]bool{}
	for _, m := range refRe.FindAllString(text, -1) {
		ref := strings.TrimRight(m, ".,);:'\"`")
		if seen[ref] {
			continue
		}
		seen[ref] = true
		target := filepath.Join(skillDir, ref)
		if rel, err := filepath.Rel(skillDir, target); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			errs = append(errs, fmt.Sprintf("reference %q escapes the skill directory", ref))
			continue
		}
		if _, err := os.Stat(target); err != nil {
			errs = append(errs, fmt.Sprintf("referenced file does not exist: %s", ref))
		}
		if strings.Count(ref, "/") > 1 {
			warns = append(warns, fmt.Sprintf("reference %q is more than one level deep; keep references shallow", ref))
		}
	}

	return errs, warns
}
