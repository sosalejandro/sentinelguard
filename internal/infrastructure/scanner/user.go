package scanner

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

type UserScanner struct {
	BaseScanner
}

func NewUserScanner() *UserScanner {
	return &UserScanner{
		BaseScanner: NewBaseScanner("user", "Scans for suspicious user accounts and privilege configurations"),
	}
}

func (s *UserScanner) Category() entity.FindingCategory {
	return entity.CategoryUser
}

func (s *UserScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting user scan")

	var findings []*entity.Finding

	uid0Findings := s.scanUID0Users(ctx)
	findings = append(findings, uid0Findings...)

	shellFindings := s.scanUsersWithShell(ctx)
	findings = append(findings, shellFindings...)

	sudoersFindings := s.scanSudoers(ctx)
	findings = append(findings, sudoersFindings...)

	groupFindings := s.scanPrivilegedGroups(ctx)
	findings = append(findings, groupFindings...)

	s.Logger().Debug("user scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *UserScanner) scanUID0Users(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning for UID 0 users")

	var findings []*entity.Finding

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}

		if uid == 0 && username != "root" {
			finding := entity.NewFinding(
				entity.CategoryUser,
				entity.SeverityCritical,
				"Non-root user with UID 0",
				"User has root privileges (UID 0) but is not named 'root'",
			).WithDetail("username", username).
				WithDetail("uid", uid).
				WithDetail("home", parts[5]).
				WithDetail("shell", parts[6])
			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *UserScanner) scanUsersWithShell(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning users with login shells")

	var findings []*entity.Finding
	validShells := map[string]bool{
		"/bin/bash": true, "/bin/sh": true, "/bin/zsh": true,
		"/usr/bin/bash": true, "/usr/bin/zsh": true, "/usr/bin/fish": true,
	}

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer file.Close()

	systemUsers := map[string]bool{
		"root": true, "sync": true,
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uid, _ := strconv.Atoi(parts[2])
		shell := parts[6]

		if validShells[shell] {
			if uid < 1000 && !systemUsers[username] {
				finding := entity.NewFinding(
					entity.CategoryUser,
					entity.SeverityMedium,
					"System user with login shell",
					"System user (UID < 1000) has a valid login shell",
				).WithDetail("username", username).
					WithDetail("uid", uid).
					WithDetail("shell", shell)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (s *UserScanner) scanSudoers(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning sudoers configuration")

	var findings []*entity.Finding

	lines, err := s.ReadFile(ctx, "/etc/sudoers")
	if err != nil {
		return nil
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "NOPASSWD") && strings.Contains(line, "ALL") {
			finding := entity.NewFinding(
				entity.CategoryUser,
				entity.SeverityHigh,
				"Passwordless sudo with ALL commands",
				"User or group can run all commands without password",
			).WithPath("/etc/sudoers").
				WithDetail("rule", line)
			findings = append(findings, finding)
		}

		if strings.Contains(line, "!authenticate") {
			finding := entity.NewFinding(
				entity.CategoryUser,
				entity.SeverityHigh,
				"Sudo authentication disabled",
				"Sudo rule disables authentication",
			).WithPath("/etc/sudoers").
				WithDetail("rule", line)
			findings = append(findings, finding)
		}
	}

	entries, err := os.ReadDir("/etc/sudoers.d")
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			path := "/etc/sudoers.d/" + entry.Name()
			lines, err := s.ReadFile(ctx, path)
			if err != nil {
				continue
			}

			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				if strings.Contains(line, "NOPASSWD") && strings.Contains(line, "ALL") {
					finding := entity.NewFinding(
						entity.CategoryUser,
						entity.SeverityHigh,
						"Passwordless sudo with ALL commands",
						"User or group can run all commands without password",
					).WithPath(path).
						WithDetail("rule", line)
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

func (s *UserScanner) scanPrivilegedGroups(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning privileged groups")

	var findings []*entity.Finding
	privilegedGroups := []string{"sudo", "wheel", "admin", "root", "docker", "lxd"}

	file, err := os.Open("/etc/group")
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}

		groupName := parts[0]
		members := parts[3]

		for _, privGroup := range privilegedGroups {
			if groupName == privGroup && members != "" {
				memberList := strings.Split(members, ",")

				s.Logger().Debug("privileged group members",
					zap.String("group", groupName),
					zap.Strings("members", memberList),
				)

				if groupName == "docker" || groupName == "lxd" {
					for _, member := range memberList {
						finding := entity.NewFinding(
							entity.CategoryUser,
							entity.SeverityMedium,
							"User in container privileged group",
							"User can potentially escalate to root via "+groupName,
						).WithDetail("group", groupName).
							WithDetail("user", member)
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings
}
