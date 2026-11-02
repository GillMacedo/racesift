// Command racesift groups and ranks Go race detector reports from
// `go test -race` or `go run -race` output. It only reads text.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const version = "0.1.0"

// Frame is one function in a stack, with its file and line when known.
type Frame struct {
	Func string `json:"func"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

// Access is one side of a race: a read or write, and the goroutine that did it.
type Access struct {
	Op        string  `json:"op"`
	Atomic    bool    `json:"atomic,omitempty"`
	Previous  bool    `json:"previous,omitempty"`
	Goroutine string  `json:"goroutine"`
	Frames    []Frame `json:"frames"`
	CreatedAt []Frame `json:"createdAt,omitempty"`
}

// Report is one WARNING: DATA RACE block.
type Report struct {
	Accesses  []Access `json:"accesses"`
	Package   string   `json:"package,omitempty"`
	Test      string   `json:"test,omitempty"`
	Input     string   `json:"input"`
	Line      int      `json:"line"`
	Truncated bool     `json:"truncated,omitempty"`

	runTest  string
	created  map[string][]Frame
	failSeen bool
}

// Location is where one side of a race happened in the user's code.
type Location struct {
	Op        string `json:"op"`
	Func      string `json:"func"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	Via       string `json:"via,omitempty"`
	Goroutine string `json:"goroutine"`
	CreatedAt string `json:"createdAt,omitempty"`
	NoUser    bool   `json:"noUserFrame,omitempty"`
}

// Hint is a pattern recognized in a race, with a suggestion.
type Hint struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	Try  string `json:"try"`
}

// Race is a group of reports with the same pair of locations.
type Race struct {
	Key       string     `json:"key"`
	Locations []Location `json:"locations"`
	Reports   int        `json:"reports"`
	Tests     []string   `json:"tests,omitempty"`
	Packages  []string   `json:"packages,omitempty"`
	Hints     []Hint     `json:"hints,omitempty"`
	First     *Report    `json:"first"`

	softKey string
	order   int
}

// Summary is the result of reviewing one or more logs.
type Summary struct {
	Reports   int       `json:"reports"`
	Races     []*Race   `json:"races"`
	Tests     []string  `json:"tests,omitempty"`
	Packages  []string  `json:"packages,omitempty"`
	HotSpots  []HotSpot `json:"hotSpots,omitempty"`
	Truncated int       `json:"truncated,omitempty"`
	JSONInput bool      `json:"jsonInput,omitempty"`
}

// HotSpot is a line of code that appears in more than one distinct race.
type HotSpot struct {
	Func  string `json:"func"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Races int    `json:"races"`
}

// ---------- reading input ----------

type logLine struct {
	text string
	pkg  string
	test string
	num  int
}

var (
	ciPrefix = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z ?`)
	ansi     = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")
)

type testEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
}

// readLines returns the log's lines grouped by package stream, in order.
// `go test -json` events are unpacked, and CI timestamps and colors removed.
func readLines(r io.Reader) (streams [][]logLine, isJSON bool, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	index := map[string]int{}
	partial := map[string]*strings.Builder{}
	partialTest := map[string]string{}
	add := func(l logLine) {
		i, ok := index[l.pkg]
		if !ok {
			i = len(streams)
			index[l.pkg] = i
			streams = append(streams, nil)
		}
		streams[i] = append(streams[i], l)
	}
	n := 0
	for sc.Scan() {
		n++
		raw := strings.TrimRight(sc.Text(), "\r")
		raw = ciPrefix.ReplaceAllString(raw, "")
		raw = ansi.ReplaceAllString(raw, "")
		if strings.HasPrefix(raw, "{") && strings.Contains(raw, `"Action"`) {
			var ev testEvent
			if json.Unmarshal([]byte(raw), &ev) == nil && ev.Action != "" {
				isJSON = true
				if ev.Action != "output" {
					continue
				}
				b := partial[ev.Package]
				if b == nil {
					b = &strings.Builder{}
					partial[ev.Package] = b
				}
				if b.Len() == 0 {
					partialTest[ev.Package] = ev.Test
				}
				b.WriteString(ev.Output)
				s := b.String()
				for {
					i := strings.IndexByte(s, '\n')
					if i < 0 {
						break
					}
					add(logLine{text: strings.TrimRight(s[:i], "\r"), pkg: ev.Package, test: partialTest[ev.Package], num: n})
					s = s[i+1:]
					partialTest[ev.Package] = ev.Test
				}
				b.Reset()
				b.WriteString(s)
				continue
			}
		}
		add(logLine{text: raw, num: n})
	}
	if err := sc.Err(); err != nil {
		return nil, false, err
	}
	for pkg, b := range partial {
		if b.Len() > 0 {
			add(logLine{text: b.String(), pkg: pkg, test: partialTest[pkg], num: n})
		}
	}
	return streams, isJSON, nil
}

// ---------- parsing reports ----------

var (
	accessRe  = regexp.MustCompile(`^(?i)(previous )?(atomic )?(read|write) at 0x[0-9a-f]+ by (main goroutine|goroutine \d+)`)
	createdRe = regexp.MustCompile(`^Goroutine (\d+) \([a-z ]+\) created at:`)
	fileRe    = regexp.MustCompile(`^\s+(\S.*):(\d+)(?: \+0x[0-9a-f]+)?$`)
	resultRe  = regexp.MustCompile(`^(?:FAIL|ok)\s+(\S+)(?:\s|$)`)
	failRe    = regexp.MustCompile(`^--- FAIL: (\S+)`)
	runRe     = regexp.MustCompile(`^=== (?:RUN|CONT)\s+(\S+)`)
)

const separator = "=================="

// Parse reads every race report in a log.
func Parse(r io.Reader, input string) ([]*Report, bool, error) {
	streams, isJSON, err := readLines(r)
	if err != nil {
		return nil, false, err
	}
	var all []*Report
	for _, s := range streams {
		all = append(all, parseStream(s, input)...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Line < all[j].Line })
	return all, isJSON, nil
}

type parser struct {
	input    string
	reports  []*Report
	cur      *Report
	access   int    // index of the access being read, or -1
	created  string // goroutine whose creation stack is being read
	waitTest []*Report
	waitPkg  []*Report
}

func (p *parser) frames() *[]Frame {
	if p.cur == nil {
		return nil
	}
	if p.access >= 0 {
		return &p.cur.Accesses[p.access].Frames
	}
	if p.created != "" {
		f := p.cur.created[p.created]
		return &f
	}
	return nil
}

func (p *parser) setFrames(f []Frame) {
	if p.access >= 0 {
		p.cur.Accesses[p.access].Frames = f
	} else if p.created != "" {
		p.cur.created[p.created] = f
	}
}

func (p *parser) finish(truncated bool) {
	r := p.cur
	if r == nil {
		return
	}
	// A race with no readable access still happened, so it must never look like a clean run.
	r.Truncated = truncated || len(r.Accesses) == 0
	for i := range r.Accesses {
		id := strings.TrimPrefix(r.Accesses[i].Goroutine, "goroutine ")
		r.Accesses[i].CreatedAt = r.created[id]
	}
	p.reports = append(p.reports, r)
	p.cur = nil
}

func parseStream(lines []logLine, input string) []*Report {
	p := &parser{input: input, access: -1}
	// Without -v, "--- FAIL: name" comes just before the race line.
	// With -v, it comes after, and "=== RUN name" names the test.
	curTest, justFailed := "", ""
	for _, l := range lines {
		t := l.text
		trim := strings.TrimSpace(t)
		lastFail := justFailed
		if p.cur == nil && trim != "" {
			justFailed = ""
		}
		if trim == "WARNING: DATA RACE" {
			p.finish(true)
			r := &Report{Input: input, Line: l.num, Package: l.pkg, Test: l.test, runTest: curTest, created: map[string][]Frame{}}
			p.cur, p.access, p.created = r, -1, ""
			if r.Test == "" {
				p.waitTest = append(p.waitTest, r)
			}
			if r.Package == "" {
				p.waitPkg = append(p.waitPkg, r)
			}
			continue
		}
		if p.cur != nil {
			if strings.HasPrefix(trim, separator) {
				p.finish(false)
				continue
			}
			if m := accessRe.FindStringSubmatch(trim); m != nil {
				p.cur.Accesses = append(p.cur.Accesses, Access{
					Op:        strings.ToLower(m[3]),
					Previous:  m[1] != "",
					Atomic:    m[2] != "",
					Goroutine: m[4],
				})
				p.access, p.created = len(p.cur.Accesses)-1, ""
				continue
			}
			if m := createdRe.FindStringSubmatch(trim); m != nil {
				p.access, p.created = -1, m[1]
				p.cur.created[m[1]] = []Frame{}
				continue
			}
			f := p.frames()
			if f == nil || trim == "" || strings.HasPrefix(trim, "[") {
				continue
			}
			if m := fileRe.FindStringSubmatch(t); m != nil && strings.HasPrefix(t, "    ") && len(*f) > 0 {
				last := &(*f)[len(*f)-1]
				last.File = m[1]
				last.Line, _ = strconv.Atoi(m[2])
				p.setFrames(*f)
				continue
			}
			if strings.HasPrefix(t, "  ") && strings.HasSuffix(trim, ")") {
				p.setFrames(append(*f, Frame{Func: funcName(trim)}))
			}
			continue
		}
		if m := runRe.FindStringSubmatch(trim); m != nil {
			curTest = m[1]
			continue
		}
		if m := failRe.FindStringSubmatch(trim); m != nil {
			justFailed = m[1]
			continue
		}
		if strings.Contains(trim, "race detected during execution of test") {
			name := l.test
			if name == "" {
				name = lastFail
			}
			if name == "" {
				name = curTest
			}
			for _, r := range p.waitTest {
				if r.Test == "" {
					r.Test = name
				}
			}
			p.waitTest = nil
			continue
		}
		if m := resultRe.FindStringSubmatch(t); m != nil {
			for _, r := range p.waitPkg {
				if r.Package == "" {
					r.Package = m[1]
				}
			}
			p.waitPkg = nil
		}
	}
	p.finish(true)
	for _, r := range p.reports {
		if r.Test == "" {
			r.Test = r.runTest
		}
	}
	return p.reports
}

// funcName turns "pkg.(*T).M(...)" into "pkg.(*T).M".
func funcName(s string) string {
	if strings.HasSuffix(s, ")") {
		if i := strings.LastIndex(s, "("); i > 0 && !strings.HasSuffix(s[:i], ".") {
			return s[:i]
		}
	}
	return s
}

// ---------- classifying frames ----------

var stdRoots = map[string]bool{}

func init() {
	for _, s := range strings.Fields(`archive bufio bytes cmp compress container context crypto database debug embed
		encoding errors expvar flag fmt go hash html image index internal io iter log maps math mime net os path
		plugin reflect regexp runtime slices sort strconv strings structs sync syscall testing text time unicode
		unique unsafe weak vendor`) {
		stdRoots[s] = true
	}
}

// pkgOf returns the package path of a function name such as
// "example.com/app/store.(*Cache).Get".
func pkgOf(fn string) string {
	slash := strings.LastIndex(fn, "/")
	dot := strings.Index(fn[slash+1:], ".")
	if dot < 0 {
		return fn
	}
	return fn[:slash+1+dot]
}

func isStd(fn string) bool {
	pkg := pkgOf(fn)
	root, _, _ := strings.Cut(pkg, "/")
	return stdRoots[root]
}

func isUser(f Frame) bool {
	if f.Func == "" || strings.HasPrefix(f.Func, "?") || isStd(f.Func) {
		return false
	}
	base := path.Base(f.File)
	return base != "_testmain.go" && !strings.HasPrefix(f.File, "<")
}

func firstUser(frames []Frame) int {
	for i, f := range frames {
		if isUser(f) {
			return i
		}
	}
	return -1
}

// shortFunc drops the package path's directories: "example.com/a/b.F" -> "b.F".
func shortFunc(fn string) string {
	return fn[strings.LastIndex(pkgOf(fn), "/")+1:]
}

// shortFile keeps the last directory and the file name.
func shortFile(f string) string {
	f = strings.ReplaceAll(f, "\\", "/")
	parts := strings.Split(f, "/")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return strings.Join(parts, "/")
}

func frameText(f Frame) string {
	if f.File == "" {
		return shortFunc(f.Func)
	}
	return fmt.Sprintf("%s (%s:%d)", shortFunc(f.Func), shortFile(f.File), f.Line)
}

func locate(a Access) Location {
	loc := Location{Op: a.Op, Goroutine: a.Goroutine}
	if a.Atomic {
		loc.Op = "atomic " + a.Op
	}
	i := firstUser(a.Frames)
	switch {
	case i >= 0:
		loc.Func, loc.File, loc.Line = a.Frames[i].Func, a.Frames[i].File, a.Frames[i].Line
		if i > 0 {
			loc.Via = a.Frames[i-1].Func
		}
	default:
		loc.NoUser = true
		for _, f := range a.Frames {
			if !strings.HasPrefix(f.Func, "?") {
				loc.Func, loc.File, loc.Line = f.Func, f.File, f.Line
				break
			}
		}
		if loc.Func == "" {
			loc.Func = "unknown"
		}
	}
	if j := firstUser(a.CreatedAt); j >= 0 {
		loc.CreatedAt = frameText(a.CreatedAt[j])
	}
	return loc
}

func (l Location) key() string {
	return fmt.Sprintf("%s %s:%d", l.Func, l.File, l.Line)
}

// ---------- grouping and hints ----------

func hasFrame(a Access, prefixes ...string) bool {
	for _, f := range a.Frames {
		for _, p := range prefixes {
			if strings.HasPrefix(f.Func, p) {
				return true
			}
		}
	}
	return false
}

func isAtomic(a Access) bool {
	return a.Atomic || hasFrame(a, "sync/atomic.", "internal/runtime/atomic.")
}

// typeOf returns "bytes.Buffer" for "bytes.(*Buffer).WriteString".
func typeOf(fn string) string {
	pkg := pkgOf(fn)
	rest := strings.TrimPrefix(fn, pkg+".")
	if !strings.HasPrefix(rest, "(") {
		return ""
	}
	end := strings.Index(rest, ")")
	if end < 0 {
		return ""
	}
	return path.Base(pkg) + "." + strings.TrimPrefix(rest[1:end], "*")
}

// parentFunc returns "pkg.F" for closures such as "pkg.F.func1" or "pkg.F.func1.2".
func parentFunc(fn string) string {
	pkg := pkgOf(fn)
	parts := strings.Split(strings.TrimPrefix(fn, pkg+"."), ".")
	for i, p := range parts {
		if strings.HasPrefix(p, "func") || strings.HasPrefix(p, "gowrap") {
			if i == 0 {
				return ""
			}
			return pkg + "." + strings.Join(parts[:i], ".")
		}
	}
	return ""
}

// stdType finds the standard library type whose method the user's code
// called, such as bytes.Buffer under fmt.Fprintf.
func stdType(a Access) (string, string) {
	end := firstUser(a.Frames)
	if end < 0 {
		end = len(a.Frames)
	}
	for i := end - 1; i >= 0; i-- {
		fn := a.Frames[i].Func
		if !isStd(fn) || strings.HasPrefix(fn, "runtime.") || strings.HasPrefix(fn, "internal/") || strings.HasPrefix(fn, "sync/atomic.") {
			continue
		}
		if t := typeOf(fn); t != "" {
			return t, fn
		}
	}
	return "", ""
}

func inTestFiles(accesses []Access) bool {
	seen := false
	for _, a := range accesses {
		for _, f := range a.Frames {
			if !isUser(f) {
				continue
			}
			seen = true
			if !strings.HasSuffix(f.File, "_test.go") {
				return false
			}
		}
	}
	return seen
}

func hints(r *Report, locs []Location) []Hint {
	var out []Hint
	acc := r.Accesses
	if len(acc) == 0 {
		return []Hint{{"RS000", "This report has no readable access, so the log may be cut off or changed.", "Rerun and keep the whole report."}}
	}
	if len(acc) < 2 {
		return []Hint{{"RS000", "This report has only one access, so the log may be cut off.", "Rerun and keep the whole report."}}
	}
	a, b := acc[0], acc[1]
	if hasFrame(a, "runtime.map", "internal/runtime/maps.") || hasFrame(b, "runtime.map", "internal/runtime/maps.") {
		out = append(out, Hint{"RS101", "A map is read and written by different goroutines.",
			"Guard the map with a sync.Mutex or sync.RWMutex, or use sync.Map if keys are mostly written once."})
	}
	if isAtomic(a) != isAtomic(b) {
		out = append(out, Hint{"RS102", "One side is an atomic operation and the other is a plain read or write.",
			"If your code calls sync/atomic, use it for every access, or switch to a type like atomic.Int64. If the atomic is inside sync.Once or a lock, the plain side is probably replacing or copying the value that holds it."})
	}
	if hasFrame(a, "runtime.growslice") || hasFrame(b, "runtime.growslice") {
		out = append(out, Hint{"RS103", "A slice is appended to while another goroutine uses it.",
			"Guard the slice with a mutex, or give each goroutine its own slice and merge them after wg.Wait."})
	}
	for _, a := range acc {
		if t, fn := stdType(a); t != "" {
			out = append(out, Hint{"RS104", fmt.Sprintf("Goroutines share one %s value. The race is inside %s.", t, shortFunc(fn)),
				fmt.Sprintf("Check the %s docs: most standard library types aren't safe for concurrent use. Guard it with a mutex or give each goroutine its own.", t)})
			break
		}
	}
	la, lb := locs[0], locs[1]
	if !la.NoUser && la.key() == lb.key() && (la.Op == "write" || lb.Op == "write") {
		out = append(out, Hint{"RS105", "The same line races with itself, so it runs in several goroutines with nothing guarding it.",
			"Common causes are a shared counter, a field every worker sets, or a result variable. Use a mutex, an atomic, or a channel to collect results."})
	}
	if !la.NoUser && !lb.NoUser {
		pa, pb := parentFunc(la.Func), parentFunc(lb.Func)
		if (pa != "" && pa == lb.Func) || (pb != "" && pb == la.Func) {
			out = append(out, Hint{"RS106", "A function and a closure it started both use the same variable.",
				"The closure captures the variable by reference. Pass a copy as an argument, or wait for the goroutine before the function uses the variable again."})
		}
	}
	if inTestFiles(acc) {
		out = append(out, Hint{"RS107", "Every frame from your code is in a _test.go file, so the race may be in the test itself.",
			"Look for variables the test shares with goroutines it starts, before changing the code under test."})
	}
	if la.NoUser || lb.NoUser {
		out = append(out, Hint{"RS108", "One side's stack has no frame from your code.",
			"Go's report lost the caller, which happens with frames inside the runtime and sync/atomic. Use the other side, and where this goroutine was started, to find it."})
	}
	return out
}

func mergeHints(have, more []Hint) []Hint {
	for _, h := range more {
		found := false
		for _, x := range have {
			found = found || x.ID == h.ID
		}
		if !found {
			have = append(have, h)
		}
	}
	sort.SliceStable(have, func(i, j int) bool { return have[i].ID < have[j].ID })
	return have
}

func addUnique(list []string, s string) []string {
	if s == "" {
		return list
	}
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// Review groups reports by the pair of code locations involved.
func Review(reports []*Report) *Summary {
	s := &Summary{Reports: len(reports), Races: []*Race{}}
	byKey := map[string]*Race{}
	for _, r := range reports {
		if r.Truncated {
			s.Truncated++
		}
		var locs []Location
		for _, a := range r.Accesses {
			locs = append(locs, locate(a))
		}
		for len(locs) < 2 {
			locs = append(locs, Location{Op: "unknown", Func: "unknown", NoUser: true})
		}
		keys := []string{locs[0].key(), locs[1].key()}
		soft := []string{locs[0].Func, locs[1].Func}
		sort.Strings(keys)
		sort.Strings(soft)
		key := strings.Join(keys, " | ")
		race := byKey[key]
		if race == nil {
			race = &Race{Key: key, Locations: locs[:2], First: r, Hints: hints(r, locs), softKey: strings.Join(soft, " | "), order: len(byKey)}
			byKey[key] = race
			s.Races = append(s.Races, race)
		}
		race.Reports++
		if race.First != r {
			race.Hints = mergeHints(race.Hints, hints(r, locs))
		}
		race.Tests = addUnique(race.Tests, r.Test)
		race.Packages = addUnique(race.Packages, r.Package)
		s.Tests = addUnique(s.Tests, r.Test)
		s.Packages = addUnique(s.Packages, r.Package)
	}
	sort.SliceStable(s.Races, func(i, j int) bool {
		a, b := s.Races[i], s.Races[j]
		if len(a.Tests) != len(b.Tests) {
			return len(a.Tests) > len(b.Tests)
		}
		if a.Reports != b.Reports {
			return a.Reports > b.Reports
		}
		return a.order < b.order
	})
	spots := map[string]*HotSpot{}
	var order []string
	for _, race := range s.Races {
		seen := map[string]bool{}
		for _, l := range race.Locations {
			if l.NoUser || seen[l.key()] {
				continue
			}
			seen[l.key()] = true
			h := spots[l.key()]
			if h == nil {
				h = &HotSpot{Func: l.Func, File: l.File, Line: l.Line}
				spots[l.key()] = h
				order = append(order, l.key())
			}
			h.Races++
		}
	}
	for _, k := range order {
		if spots[k].Races > 1 {
			s.HotSpots = append(s.HotSpots, *spots[k])
		}
	}
	sort.SliceStable(s.HotSpots, func(i, j int) bool { return s.HotSpots[i].Races > s.HotSpots[j].Races })
	return s
}

// Comparison lists races that are new, gone or still present between two logs.
type Comparison struct {
	New   []*Race `json:"new"`
	Gone  []*Race `json:"gone"`
	Still []*Race `json:"still"`
}

// Compare matches races by the functions involved, ignoring line numbers,
// so edits elsewhere in a file don't make an old race look new.
func Compare(base, head *Summary) *Comparison {
	c := &Comparison{New: []*Race{}, Gone: []*Race{}, Still: []*Race{}}
	inBase := map[string]bool{}
	inHead := map[string]bool{}
	for _, r := range base.Races {
		inBase[r.softKey] = true
	}
	for _, r := range head.Races {
		inHead[r.softKey] = true
		if inBase[r.softKey] {
			c.Still = append(c.Still, r)
		} else {
			c.New = append(c.New, r)
		}
	}
	for _, r := range base.Races {
		if !inHead[r.softKey] {
			c.Gone = append(c.Gone, r)
			inHead[r.softKey] = true
		}
	}
	return c
}

// ---------- output ----------

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func locText(l Location) string {
	where := shortFunc(l.Func)
	if l.File != "" {
		where += fmt.Sprintf(" (%s:%d)", shortFile(l.File), l.Line)
	}
	return where
}

func writeRace(w io.Writer, n int, r *Race, showHints bool) {
	ctx := ""
	if len(r.Tests) > 0 {
		ctx = "  in " + strings.Join(r.Tests, ", ")
	}
	fmt.Fprintf(w, "RACE %d  %s%s\n", n, plural(r.Reports, "report", "reports"), ctx)
	for _, l := range r.Locations {
		extra := []string{}
		if l.Via != "" {
			extra = append(extra, "via "+shortFunc(l.Via))
		}
		if l.CreatedAt != "" {
			extra = append(extra, "started at "+l.CreatedAt)
		} else {
			extra = append(extra, l.Goroutine)
		}
		fmt.Fprintf(w, "  %-13s %s\n  %13s %s\n", l.Op, locText(l), "", strings.Join(extra, "; "))
	}
	if showHints {
		for _, h := range r.Hints {
			fmt.Fprintf(w, "  %s %s\n        Try: %s\n", h.ID, h.Text, h.Try)
		}
	}
}

// WriteText prints a review for people and agents.
func WriteText(w io.Writer, s *Summary) {
	if len(s.Races) == 0 {
		fmt.Fprintln(w, "No data race reports found.")
		return
	}
	fmt.Fprintf(w, "%s from %s", plural(len(s.Races), "distinct race", "distinct races"), plural(s.Reports, "report", "reports"))
	if len(s.Tests) > 0 {
		fmt.Fprintf(w, ", in %s", plural(len(s.Tests), "test", "tests"))
	}
	if len(s.Packages) > 0 {
		fmt.Fprintf(w, " and %s", plural(len(s.Packages), "package", "packages"))
	}
	fmt.Fprintln(w)
	if s.Truncated > 0 {
		fmt.Fprintf(w, "%s cut off before its end.\n", plural(s.Truncated, "report was", "reports were"))
	}
	if len(s.HotSpots) > 0 {
		fmt.Fprintln(w, "\nLines in more than one race:")
		for _, h := range s.HotSpots {
			fmt.Fprintf(w, "  %3d  %s\n", h.Races, locText(Location{Func: h.Func, File: h.File, Line: h.Line}))
		}
	}
	for i, r := range s.Races {
		fmt.Fprintln(w)
		writeRace(w, i+1, r, true)
	}
}

// WriteComparison prints new, gone and unchanged races.
func WriteComparison(w io.Writer, c *Comparison) {
	fmt.Fprintf(w, "New: %d   Gone: %d   Still there: %d\n", len(c.New), len(c.Gone), len(c.Still))
	if len(c.New) > 0 {
		fmt.Fprintln(w, "\nNew races:")
		for i, r := range c.New {
			if i > 0 {
				fmt.Fprintln(w)
			}
			writeRace(w, i+1, r, true)
		}
	}
	for _, sec := range []struct {
		name  string
		races []*Race
	}{{"Gone", c.Gone}, {"Still there", c.Still}} {
		if len(sec.races) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s:\n", sec.name)
		for _, r := range sec.races {
			fmt.Fprintf(w, "  %s  <->  %s\n", locText(r.Locations[0]), locText(r.Locations[1]))
		}
	}
}

// ---------- command line ----------

func loadReports(name string, stdin io.Reader) ([]*Report, bool, error) {
	var r io.Reader
	if name == "-" {
		r = stdin
	} else {
		f, err := os.Open(name)
		if err != nil {
			return nil, false, err
		}
		defer f.Close()
		r = f
	}
	reports, isJSON, err := Parse(r, name)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	return reports, isJSON, nil
}

func load(name string, stdin io.Reader) (*Summary, error) {
	reports, isJSON, err := loadReports(name, stdin)
	if err != nil {
		return nil, err
	}
	s := Review(reports)
	s.JSONInput = isJSON
	return s, nil
}

func usage(w io.Writer) {
	fmt.Fprint(w, `racesift groups and ranks Go race detector reports.

Usage:
  racesift review [--json] [--fail] [FILE ...]   Group the races in one or more logs. Reads stdin with no FILE or "-".
  racesift compare [--json] [--fail] BASE HEAD   Show races that are new in HEAD, gone, or still there.
  racesift version

Get a log with:  go test -race ./... 2>&1 | tee race.log
"go test -json" output and GitHub Actions logs work too.

Exit codes: 0 done, 1 with --fail when review finds races or compare finds new ones, 2 bad usage or unreadable input.
`)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	cmd := args[0]
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(stdout, "racesift", version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	case "review", "compare":
		args = args[1:]
	default:
		cmd = "review"
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	fail := fs.Bool("fail", false, "exit 1 if races are found (review) or new (compare)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	files := fs.Args()
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if cmd == "compare" {
		if len(files) != 2 {
			fmt.Fprintln(stderr, "compare needs two logs: BASE HEAD")
			return 2
		}
		base, err := load(files[0], stdin)
		if err != nil {
			fmt.Fprintln(stderr, "racesift:", err)
			return 2
		}
		head, err := load(files[1], stdin)
		if err != nil {
			fmt.Fprintln(stderr, "racesift:", err)
			return 2
		}
		c := Compare(base, head)
		if *asJSON {
			enc.Encode(c)
		} else {
			WriteComparison(stdout, c)
		}
		if *fail && len(c.New) > 0 {
			return 1
		}
		return 0
	}
	if len(files) == 0 {
		files = []string{"-"}
	}
	var reports []*Report
	isJSON := false
	for _, name := range files {
		rs, j, err := loadReports(name, stdin)
		if err != nil {
			fmt.Fprintln(stderr, "racesift:", err)
			return 2
		}
		isJSON = isJSON || j
		reports = append(reports, rs...)
	}
	s := Review(reports)
	s.JSONInput = isJSON
	if *asJSON {
		enc.Encode(s)
	} else {
		WriteText(stdout, s)
	}
	if *fail && len(s.Races) > 0 {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
