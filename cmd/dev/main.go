package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const debounce = 150 * time.Millisecond

func main() {
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tsgo, err := findTSGo()
	if err != nil {
		log.Fatal(err)
	}

	changes := make(chan struct{}, 1)
	go watch(ctx, changes)

	var server *exec.Cmd
	restart := func() {
		stopProcess(server)
		if err := run(tsgo, "-p", "tsconfig.json"); err != nil {
			log.Printf("TypeScript build failed: %v", err)
			server = nil
			return
		}
		server = exec.Command("go", "run", ".")
		server.Stdout, server.Stderr = os.Stdout, os.Stderr
		server.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := server.Start(); err != nil {
			log.Printf("Server start failed: %v", err)
			server = nil
			return
		}
		log.Println("Development server restarted")
		go server.Wait()
	}

	restart()
	for {
		select {
		case <-ctx.Done():
			stopProcess(server)
			return
		case <-changes:
			timer := time.NewTimer(debounce)
			for {
				select {
				case <-changes:
					if !timer.Stop() {
						<-timer.C
					}
					timer.Reset(debounce)
				case <-timer.C:
					restart()
					goto restarted
				case <-ctx.Done():
					timer.Stop()
					stopProcess(server)
					return
				}
			}
		restarted:
		}
	}
}

func watch(ctx context.Context, changes chan<- struct{}) {
	previous := snapshot()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := snapshot()
			if different(previous, current) {
				previous = current
				select {
				case changes <- struct{}{}:
				default:
				}
			}
		}
	}
}

func snapshot() map[string]fileState {
	result := make(map[string]fileState)
	for _, root := range []string{"frontend", "public", "cmd", "."} {
		filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			if root == "." && filepath.Dir(path) != "." {
				return nil
			}
			if !watched(path) {
				return nil
			}
			info, err := entry.Info()
			if err == nil {
				result[path] = fileState{modified: info.ModTime(), size: info.Size()}
			}
			return nil
		})
	}
	return result
}

type fileState struct {
	modified time.Time
	size     int64
}

func watched(path string) bool {
	if path == filepath.Join("public", "app.js") {
		return false
	}
	switch filepath.Ext(path) {
	case ".go", ".ts", ".html", ".css":
		return true
	}
	return filepath.Base(path) == "tsconfig.json"
}

func different(left, right map[string]fileState) bool {
	if len(left) != len(right) {
		return true
	}
	for path, state := range left {
		if right[path] != state {
			return true
		}
	}
	return false
}

func findTSGo() (string, error) {
	if path, err := exec.LookPath("tsgo"); err == nil {
		return path, nil
	}
	output, err := exec.Command("go", "env", "GOPATH").Output()
	if err == nil {
		path := filepath.Join(stringTrimSpace(string(output)), "bin", "tsgo")
		if _, statErr := os.Stat(path); statErr == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("tsgo not found; run: go install github.com/microsoft/typescript-go/cmd/tsgo@latest")
}

func run(name string, args ...string) error {
	command := exec.Command(name, args...)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	return command.Run()
}

func stopProcess(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	for range 20 {
		if command.Process.Signal(syscall.Signal(0)) != nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
}

func stringTrimSpace(value string) string {
	for len(value) > 0 && (value[len(value)-1] == '\n' || value[len(value)-1] == '\r' || value[len(value)-1] == ' ' || value[len(value)-1] == '\t') {
		value = value[:len(value)-1]
	}
	return value
}
