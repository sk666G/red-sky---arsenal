// Package tui is the operator console. Phase 7: multi-pane layout with
// sessions, tasks, loot, events, command prompt, and status bar.
package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/sk666G/red-sky---arsenal/internal/planner"
	"github.com/sk666G/red-sky---arsenal/internal/session"
)

// ---- styling ----

var (
	crimsonStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#DC143C")).Bold(true)
	boneStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6DCD2"))
	ashStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#787878"))
	okStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#50C850"))
	errStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF2400"))
	borderStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#8B0000"))
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF2400")).Bold(true)
	promptStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#DC143C")).Bold(true)
	activeBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#FF2400"))
	inactiveBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#5A0000"))
)

// ---- messages ----

type tickMsg time.Time

// ---- focus pane ----

type pane int

const (
	paneSessions pane = iota
	paneTasks
	paneLoot
	paneEvents
	panePrompt
	paneCount
)

func (p pane) String() string {
	switch p {
	case paneSessions:
		return "sessions"
	case paneTasks:
		return "tasks"
	case paneLoot:
		return "loot"
	case paneEvents:
		return "events"
	case panePrompt:
		return "prompt"
	}
	return "?"
}

// ---- model ----

type Model struct {
	mgr        *session.Manager
	engagement string
	port       int
	started    time.Time

	selected int // session index

	sessCursor int // index into selected session's task list (for tasks pane)
	focus      pane

	events    []session.Event
	input     string
	inputHist []string
	histPos   int

	detailShown bool // task detail modal
	detailTask  *session.Task

	helpShown bool

	loot      []string
	lootPulse time.Time

	width, height int
	quitting      bool
	err           error

	planner      planner.Planner
	planShown    bool
	pendingPlan  *planner.Plan
	planError    string
	pendingGoal  string
}

// New builds the TUI model bound to a session manager.
func New(mgr *session.Manager, engagement string, port int, pl planner.Planner) Model {
	if pl == nil {
		pl = planner.RulePlanner{}
	}
	return Model{
		mgr:        mgr,
		engagement: engagement,
		port:       port,
		planner:    pl,
		started:    time.Now(),
		histPos:    -1,
	}
}

func (m Model) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		// drain events
		for {
			select {
			case ev := <-m.mgr.Events:
				m.events = append(m.events, ev)
				if len(m.events) > 500 {
					m.events = m.events[len(m.events)-500:]
				}
			default:
				goto drained
			}
		}
	drained:
		if m.pendingGoal != "" {
			goal := m.pendingGoal
			m.pendingGoal = ""
			return m, m.runPlanner(goal)
		}
		// refresh loot every 2 seconds
		if time.Since(m.lootPulse) > 2*time.Second {
			m.loot = m.scanLoot()
			m.lootPulse = time.Now()
		}
		return m, tick()

	case planMsg:
		m.showPlan(msg.plan, msg.err)
		return m, nil

	case tea.KeyMsg:
		// modals first
		if m.planShown {
			return m.planKey(msg)
		}
		if m.detailShown {
			if msg.String() == "esc" || msg.String() == "q" {
				m.detailShown = false
				m.detailTask = nil
			}
			return m, nil
		}
		if m.helpShown {
			if msg.String() == "esc" || msg.String() == "q" || msg.String() == "?" {
				m.helpShown = false
			}
			return m, nil
		}
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "esc":
			// if prompt non-empty, clear it; else quit
			if m.input != "" {
				m.input = ""
				return m, nil
			}
			m.quitting = true
			return m, tea.Quit
		case "?":
			m.helpShown = true
		case "tab":
			m.focus = (m.focus + 1) % paneCount
		case "shift+tab":
			if m.focus == 0 {
				m.focus = paneCount - 1
			} else {
				m.focus--
			}
		case "up", "ctrl+p":
			m.cursorUp()
		case "down", "ctrl+n":
			m.cursorDown()
		case "enter":
			if m.focus == paneSessions {
				// move to prompt
				m.focus = panePrompt
			} else if m.focus == paneTasks {
				// show task detail
				sess := m.mgr.Sessions()
				if m.selected < len(sess) {
					tasks := sess[m.selected].Tasks()
					if m.sessCursor < len(tasks) {
						m.detailTask = tasks[m.sessCursor]
						m.detailShown = true
					}
				}
			} else if m.focus == panePrompt {
				m.submit()
			}
		case "backspace":
			if len(m.input) > 0 {
				m.input = m.input[:len(m.input)-1]
			}
		default:
			// printable char
			if msg.Type == tea.KeyRunes {
				m.input += string(msg.Runes)
			}
		}
	}
	return m, nil
}

func (m *Model) cursorUp() {
	switch m.focus {
	case paneSessions, panePrompt:
		if m.selected > 0 {
			m.selected--
		}
	case paneTasks:
		if m.sessCursor > 0 {
			m.sessCursor--
		}
	case paneEvents, paneLoot:
		// no cursor
	}
}

func (m *Model) cursorDown() {
	switch m.focus {
	case paneSessions, panePrompt:
		if m.selected < len(m.mgr.Sessions())-1 {
			m.selected++
		}
	case paneTasks:
		sess := m.mgr.Sessions()
		if m.selected < len(sess) {
			n := len(sess[m.selected].Tasks())
			if m.sessCursor < n-1 {
				m.sessCursor++
			}
		}
	}
}

func (m *Model) submit() {
	cmd := strings.TrimSpace(m.input)
	if cmd == "" {
		return
	}
	m.inputHist = append(m.inputHist, cmd)
	m.histPos = -1
	m.input = ""

	if cmd == "help" {
		m.helpShown = true
		return
	}

	if strings.HasPrefix(cmd, ":") {
		goal := strings.TrimSpace(strings.TrimPrefix(cmd, ":"))
		if goal == "" {
			return
		}
		m.mgr.Events <- session.Event{TS: time.Now(), Kind: "plan", Text: "planning: " + goal}
		m.pendingGoal = goal
		return
	}

	sess := m.mgr.Sessions()
	if len(sess) == 0 {
		m.err = fmt.Errorf("no sessions connected")
		return
	}
	if m.selected >= len(sess) {
		m.selected = 0
	}

	// Send one shell command to the target; args split on whitespace.
	parts := strings.Fields(cmd)
	target := sess[m.selected]
	target.Send(parts[0], parts[1:], 60)
	m.sessCursor = len(target.Tasks()) - 1 // focus the new task
}

func (m Model) scanLoot() []string {
	root, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(root, ".redsky", "engagements", m.engagement, "loot")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, fmt.Sprintf("%s (%d B)", e.Name(), info.Size()))
	}
	sort.Strings(out)
	return out
}

// ---- render ----

func (m Model) View() string {
	if m.quitting {
		return crimsonStyle.Render("the sky goes dark.\n")
	}

	if m.planShown {
		return m.renderPlanModal()
	}
	if m.detailShown {
		return m.viewDetail()
	}
	if m.helpShown {
		return m.viewHelp()
	}

	sess := m.mgr.Sessions()

	// compute layout
	w := m.width
	if w == 0 {
		w = 100
	}
	h := m.height
	if h == 0 {
		h = 30
	}

	topH := h - 12
	if topH < 8 {
		topH = 8
	}

	// three top panes
	leftW := w / 4
	midW := w / 3
	rightW := w - leftW - midW - 6

	sessionsPane := m.renderSessions(sess, leftW, topH)
	tasksPane := m.renderTasks(sess, midW, topH)
	lootPane := m.renderLoot(rightW, topH)
	topRow := lipgloss.JoinHorizontal(lipgloss.Top, sessionsPane, tasksPane, lootPane)

	eventsBox := m.renderEvents(w-2, 8)
	promptBox := m.renderPrompt(w - 2)
	statusBox := m.renderStatus(w - 2, len(sess))

	return lipgloss.JoinVertical(lipgloss.Left,
		topRow,
		eventsBox,
		promptBox,
		statusBox,
	)
}

func (m Model) boxStyle(p pane, w, h int) lipgloss.Style {
	base := borderStyle
	if m.focus == p {
		base = activeBox
	}
	return base.Width(w).Height(h)
}

func (m Model) renderSessions(sess []*session.Session, w, h int) string {
	var b strings.Builder
	b.WriteString(crimsonStyle.Render("SESSIONS") + "\n\n")
	if len(sess) == 0 {
		b.WriteString(ashStyle.Render("(none connected)"))
	} else {
		for i, s := range sess {
			marker := "  "
			if i == m.selected {
				marker = "▶ "
			}
			line := fmt.Sprintf("%s%s\n  %s@%s\n  %s ago",
				marker, s.AgentID, s.Info.User, s.Info.Hostname,
				time.Since(s.LastSeen).Truncate(time.Second))
			if i == m.selected {
				b.WriteString(selectedStyle.Render(line))
			} else {
				b.WriteString(boneStyle.Render(line))
			}
			b.WriteString("\n\n")
		}
	}
	return m.boxStyle(paneSessions, w, h).Render(b.String())
}

func (m Model) renderTasks(sess []*session.Session, w, h int) string {
	var b strings.Builder
	b.WriteString(crimsonStyle.Render("TASKS") + "\n\n")
	if len(sess) == 0 || m.selected >= len(sess) {
		b.WriteString(ashStyle.Render("(no session selected)"))
	} else {
		tasks := sess[m.selected].Tasks()
		if len(tasks) == 0 {
			b.WriteString(ashStyle.Render("(no tasks yet)"))
		}
		for i, t := range tasks {
			marker := "  "
			if i == m.sessCursor {
				marker = "▶ "
			}
			status := string(t.State)
			var color lipgloss.Style
			switch t.State {
			case session.TaskDone:
				color = okStyle
			case session.TaskFailed, session.TaskTimeout:
				color = errStyle
			case session.TaskSent, session.TaskQueued:
				color = ashStyle
			}
			line := fmt.Sprintf("%s%s  [%s]", marker, t.Cmd, status)
			if i == m.sessCursor {
				b.WriteString(selectedStyle.Render(line))
			} else {
				b.WriteString(color.Render(line))
			}
			b.WriteString("\n")
		}
	}
	return m.boxStyle(paneTasks, w, h).Render(b.String())
}

func (m Model) renderLoot(w, h int) string {
	var b strings.Builder
	b.WriteString(crimsonStyle.Render("LOOT") + "\n\n")
	if len(m.loot) == 0 {
		b.WriteString(ashStyle.Render("(no loot yet)"))
	} else {
		for _, l := range m.loot {
			b.WriteString(boneStyle.Render(l) + "\n")
		}
	}
	return m.boxStyle(paneLoot, w, h).Render(b.String())
}

func (m Model) renderEvents(w, h int) string {
	var b strings.Builder
	b.WriteString(crimsonStyle.Render("EVENTS") + "\n")
	start := len(m.events) - (h - 3)
	if start < 0 {
		start = 0
	}
	for _, ev := range m.events[start:] {
		ts := ev.TS.Format("15:04:05")
		color := ashStyle
		switch ev.Kind {
		case "connect":
			color = okStyle
		case "disconnect", "error":
			color = errStyle
		case "result":
			color = boneStyle
		}
		b.WriteString(color.Render(fmt.Sprintf("%s [%s] %s", ts, ev.Kind, ev.Text)) + "\n")
	}
	return m.boxStyle(paneEvents, w-2, h).Render(b.String())
}

func (m Model) renderPrompt(w int) string {
	cursor := "█"
	p := promptStyle.Render("redsky> ") + m.input + cursor
	if m.err != nil {
		p += "  " + errStyle.Render(m.err.Error())
	}
	return p
}

func (m Model) renderStatus(w int, nSess int) string {
	elapsed := time.Since(m.started).Truncate(time.Second)
	left := fmt.Sprintf("engagement: %s  port: %d  sessions: %d  up: %s",
		m.engagement, m.port, nSess, elapsed)
	right := fmt.Sprintf("focus: %s  ? help", m.focus.String())
	pad := w - len(left) - len(right) - 4
	if pad < 1 {
		pad = 1
	}
	return ashStyle.Render(left + strings.Repeat(" ", pad) + right)
}

func (m Model) viewDetail() string {
	var b strings.Builder
	b.WriteString(crimsonStyle.Render("TASK DETAIL") + "\n\n")
	if m.detailTask == nil {
		b.WriteString("(no task selected)\n")
	} else {
		t := m.detailTask
		b.WriteString(boneStyle.Render(fmt.Sprintf("id:      %s", t.ID)) + "\n")
		b.WriteString(boneStyle.Render(fmt.Sprintf("cmd:     %s %s", t.Cmd, strings.Join(t.Args, " "))) + "\n")
		b.WriteString(boneStyle.Render(fmt.Sprintf("state:   %s", t.State)) + "\n")
		b.WriteString(boneStyle.Render(fmt.Sprintf("enqueued: %s", t.Enqueued.Format(time.RFC3339))) + "\n")
		if !t.Completed.IsZero() {
			b.WriteString(boneStyle.Render(fmt.Sprintf("completed: %s", t.Completed.Format(time.RFC3339))) + "\n")
		}
		b.WriteString("\n")
		if t.Result != nil {
			b.WriteString(crimsonStyle.Render("STDOUT") + "\n")
			b.WriteString(boneStyle.Render(t.Result.Stdout) + "\n")
			if t.Result.Stderr != "" {
				b.WriteString(crimsonStyle.Render("STDERR") + "\n")
				b.WriteString(errStyle.Render(t.Result.Stderr) + "\n")
			}
			b.WriteString(crimsonStyle.Render(fmt.Sprintf("EXIT: %d", t.Result.ExitCode)) + "\n")
		}
		if t.Error != "" {
			b.WriteString(errStyle.Render("error: " + t.Error) + "\n")
		}
	}
	b.WriteString("\n" + ashStyle.Render("esc close"))
	return borderStyle.Width(m.width - 4).Render(b.String())
}

func (m Model) viewHelp() string {
	help := []string{
		"KEYS",
		"",
		"  tab / shift+tab   cycle focus pane (sessions -> tasks -> loot -> events -> prompt)",
		"  ↑ / ↓             move cursor in focused pane",
		"  enter             sessions: jump to prompt | tasks: open detail | prompt: send",
		"  esc               clear input, close modal, or quit if empty",
		"  ?                 this help",
		"  ctrl+c            quit",
		"",
		"COMMANDS",
		"",
		"  any shell command  runs on the selected session",
		"  help               this screen",
		"",
		"STATUS",
		"",
		"  sessions:  live agents",
		"  tasks:     queued / sent / done tasks for the selected session",
		"  loot:      files under ~/.redsky/engagements/<name>/loot/",
		"  events:    connect / beacon / task / result / error log",
		"",
		"esc close",
	}
	return borderStyle.Width(m.width - 4).Render(strings.Join(help, "\n"))
}
