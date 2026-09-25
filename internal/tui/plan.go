// Plan-mode TUI: `:` prefix in the prompt runs the goal through the planner
// and shows a preview modal before executing.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/sk666G/red-sky---arsenal/internal/planner"
	"github.com/sk666G/red-sky---arsenal/internal/session"
)

// planMsg carries a planner result back into the model.
type planMsg struct {
	plan *planner.Plan
	err  error
}

// runPlanner invokes the planner async so the TUI stays responsive.
func (m *Model) runPlanner(goal string) tea.Cmd {
	p := m.planner
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		plan, err := p.Plan(ctx, goal)
		return planMsg{plan: plan, err: err}
	}
}

// showPlan opens the plan preview modal.
func (m *Model) showPlan(p *planner.Plan, err error) {
	m.planShown = true
	m.pendingPlan = p
	if err != nil && p == nil {
		m.planError = err.Error()
	} else {
		m.planError = ""
	}
}

// executePlan dispatches every step as a session task to the current agent.
// Returns the number of tasks queued.
func (m *Model) executePlan() int {
	if m.pendingPlan == nil || len(m.pendingPlan.Steps) == 0 {
		return 0
	}
	sess := m.mgr.Sessions()
	if len(sess) == 0 {
		m.err = fmt.Errorf("no sessions connected")
		return 0
	}
	if m.selected >= len(sess) {
		m.selected = 0
	}
	target := sess[m.selected]
	n := 0
	for _, step := range m.pendingPlan.Steps {
		// Framework-native modules go through the local plugin bridge; shell
		// commands go to the agent. For Phase 8 we route framework modules
		// through the agent as `redsky <module> <args>` shell calls, because
		// remote plugin execution is Phase 4.
		cmd := "redsky"
		args := append([]string{step.Module}, step.Args...)
		target.Send(cmd, args, 300)
		n++
		m.mgr.Events <- session.Event{
			TS:      time.Now(),
			Kind:    "plan",
			AgentID: target.AgentID,
			Text:    "queued " + step.Module + " " + strings.Join(step.Args, " "),
		}
	}
	return n
}

// renderPlanModal draws the plan preview.
func (m Model) renderPlanModal() string {
	var b strings.Builder
	b.WriteString(crimsonStyle.Render("PLAN PREVIEW") + "\n\n")
	if m.planError != "" {
		b.WriteString(errStyle.Render("planner error: "+m.planError) + "\n\n")
	}
	if m.pendingPlan == nil {
		b.WriteString(ashStyle.Render("(no plan)") + "\n")
	} else {
		b.WriteString(boneStyle.Render("goal:    "+m.pendingPlan.Goal) + "\n")
		b.WriteString(boneStyle.Render("backend: "+m.pendingPlan.Backend) + "\n\n")
		if len(m.pendingPlan.Steps) == 0 {
			b.WriteString(ashStyle.Render("(planner returned no steps)") + "\n")
		}
		for i, s := range m.pendingPlan.Steps {
			b.WriteString(selectedStyle.Render(fmt.Sprintf("%2d. %s %s", i+1, s.Module, strings.Join(s.Args, " "))) + "\n")
			if s.Reason != "" {
				b.WriteString(ashStyle.Render("    "+s.Reason) + "\n")
			}
		}
	}
	b.WriteString("\n" + ashStyle.Render("y execute   n cancel   esc close"))
	return borderStyle.Width(m.width - 4).Render(b.String())
}

// planKey handles input while the plan modal is open.
func (m *Model) planKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "n":
		m.planShown = false
		m.pendingPlan = nil
		m.planError = ""
	case "y":
		n := m.executePlan()
		if n > 0 {
			m.mgr.Events <- session.Event{
				TS:   time.Now(),
				Kind: "plan",
				Text: fmt.Sprintf("executing plan: %d task(s) queued", n),
			}
		}
		m.planShown = false
		m.pendingPlan = nil
		m.planError = ""
	}
	return m, nil
}

// Ensure lipgloss is referenced so imports don't break when only some views
// use it.
var _ = lipgloss.NewStyle
