// Package tui is the operator console. Phase 5: three-pane layout with a
// sessions list, task log, and command input.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/sk666G/red-sky---arsenal/internal/session"
)

// ---- styling ----

var (
	bloodStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B0000"))
	crimsonStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#DC143C")).Bold(true)
	boneStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#E6DCD2"))
	ashStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#787878"))
	okStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#50C850"))
	errStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF2400"))
	borderStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#8B0000"))
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF2400")).Bold(true)
	promptStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#DC143C")).Bold(true)
)

// ---- messages ----

type tickMsg time.Time

// ---- model ----

type Model struct {
	mgr      *session.Manager
	selected int           // index into sessions
	events   []session.Event
	input    string
	width    int
	height   int
	err      error
	quitting bool
}

// New builds the TUI model bound to a session manager.
func New(mgr *session.Manager) Model {
	return Model{mgr: mgr}
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
		return m, tick()

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			sess := m.mgr.Sessions()
			if m.selected < len(sess)-1 {
				m.selected++
			}
		case "enter":
			// send command to selected session
			cmd := strings.TrimSpace(m.input)
			if cmd == "" {
				return m, nil
			}
			sess := m.mgr.Sessions()
			if len(sess) == 0 {
				m.err = fmt.Errorf("no sessions connected")
				m.input = ""
				return m, nil
			}
			if m.selected >= len(sess) {
				m.selected = 0
			}
			parts := strings.Fields(cmd)
			target := sess[m.selected]
			target.Send(parts[0], parts[1:], 60)
			m.input = ""
		case "backspace":
			if len(m.input) > 0 {
				m.input = m.input[:len(m.input)-1]
			}
		default:
			if len(msg.String()) == 1 {
				m.input += msg.String()
			}
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return bloodStyle.Render("the sky goes dark.\n")
	}
	sess := m.mgr.Sessions()

	// --- left: sessions ---
	var sessionsPane strings.Builder
	sessionsPane.WriteString(crimsonStyle.Render("SESSIONS") + "\n\n")
	if len(sess) == 0 {
		sessionsPane.WriteString(ashStyle.Render("(none connected)"))
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
				sessionsPane.WriteString(selectedStyle.Render(line))
			} else {
				sessionsPane.WriteString(boneStyle.Render(line))
			}
			sessionsPane.WriteString("\n\n")
		}
	}

	// --- right top: events ---
	var eventsPane strings.Builder
	eventsPane.WriteString(crimsonStyle.Render("EVENTS") + "\n\n")
	start := len(m.events) - 15
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
		eventsPane.WriteString(color.Render(fmt.Sprintf("%s [%s] %s", ts, ev.Kind, ev.Text)) + "\n")
	}

	// --- right bottom: prompt ---
	prompt := promptStyle.Render("redsky> ") + m.input + "█"

	// --- layout ---
	leftW := 40
	if m.width > 0 && m.width < 100 {
		leftW = m.width / 3
	}
	rightW := m.width - leftW - 4
	if rightW < 20 {
		rightW = 20
	}
	topH := 20
	left := borderStyle.Width(leftW).Height(topH + 3).Render(sessionsPane.String())
	right := borderStyle.Width(rightW).Height(topH + 3).Render(eventsPane.String())
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	footer := "\n" + prompt + "\n" +
		ashStyle.Render("↑/↓ select  enter send  esc quit")
	return body + "\n" + footer
}
