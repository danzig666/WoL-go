//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "WoLGoAgent"
const serviceDisplay = "WoL-go sleep agent"

// --- Putting the machine to sleep ---

var (
	powrprof            = windows.NewLazySystemDLL("powrprof.dll")
	procSetSuspendState = powrprof.NewProc("SetSuspendState")
)

// suspend puts the computer to sleep.
//
// SetSuspendState needs SeShutdownPrivilege, which is present but disabled in
// the process token; it has to be enabled first. Running as LOCAL SYSTEM the
// privilege is held, which is why the service can sleep the machine even at
// the lock screen.
//
// force decides whether applications may veto. Without it, something holding a
// power request - a video playing, a backup running - can keep the machine up.
func suspend(force bool) error {
	if err := enableShutdownPrivilege(); err != nil {
		return fmt.Errorf("could not obtain the shutdown privilege: %w", err)
	}

	var forceFlag uintptr
	if force {
		forceFlag = 1
	}

	// hibernate = 0: sleep. The third argument disables wake events, which
	// must stay 0 or the machine could not be woken by a magic packet.
	ret, _, err := procSetSuspendState.Call(0, forceFlag, 0)
	if ret == 0 {
		return fmt.Errorf("the system refused to sleep: %w", err)
	}
	return nil
}

func enableShutdownPrivilege() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	name, err := windows.UTF16PtrFromString("SeShutdownPrivilege")
	if err != nil {
		return err
	}
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return err
	}

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	privileges.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}

	return windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)
}

// --- What the machine can tell us about waking ---

// wakeArmed reports whether any network adapter is allowed to wake the
// machine. This is the setting people forget, and the reason a correctly sent
// magic packet does nothing.
func wakeArmed() (bool, bool) {
	out, err := runHidden("powercfg", "/devicequery", "wake_armed")
	if err != nil {
		return false, false
	}
	text := strings.TrimSpace(out)
	if text == "" || strings.EqualFold(text, "NONE") {
		return false, true
	}
	// Anything listed is armed; network adapters are the ones that matter.
	return true, true
}

// fastStartupEnabled reports Windows fast startup, which stops a machine
// waking from a full shutdown however well everything else is configured.
func fastStartupEnabled() (bool, bool) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Power`, registry.QUERY_VALUE)
	if err != nil {
		return false, false
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("HiberbootEnabled")
	if err != nil {
		return false, false
	}
	return value != 0, true
}

// powerRequests reports what is currently keeping the machine awake, so the
// panel can explain a sleep that did not happen.
func powerRequests() string {
	out, err := runHidden("powercfg", "/requests")
	if err != nil {
		return ""
	}

	var holders []string
	var section string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(line, ":")
			continue
		}
		if strings.EqualFold(line, "None.") {
			continue
		}
		// Only the categories that actually prevent sleep.
		if section == "DISPLAY" || section == "SYSTEM" || section == "AWAYMODE" {
			holders = append(holders, strings.TrimSpace(line))
		}
	}
	if len(holders) == 0 {
		return ""
	}
	if len(holders) > 3 {
		holders = holders[:3]
	}
	return strings.Join(holders, "; ")
}

// runHidden runs a console tool without flashing a window, which matters
// because the service and any GUI build have no console of their own.
func runHidden(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	return string(out), err
}

// --- Windows service ---

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("%w (run this from an elevated prompt)", err)
	}
	defer manager.Disconnect()

	// Replace any previous installation rather than failing.
	if existing, err := manager.OpenService(serviceName); err == nil {
		existing.Control(svc.Stop)
		existing.Delete()
		existing.Close()
		time.Sleep(time.Second)
	}

	service, err := manager.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  serviceDisplay,
		Description:  "Lets WoL-go put this computer to sleep. Makes outbound requests only.",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, "run")
	if err != nil {
		return fmt.Errorf("%w (run this from an elevated prompt)", err)
	}
	defer service.Close()

	if err := service.Start(); err != nil {
		return fmt.Errorf("installed, but could not start: %w", err)
	}
	return nil
}

// stopService stops the service and waits for it to actually be stopped,
// because the executable stays locked until it is.
func stopService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("%w (run this from an elevated prompt)", err)
	}
	defer manager.Disconnect()

	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the service is not installed")
	}
	defer service.Close()

	status, err := service.Query()
	if err == nil && status.State == svc.Stopped {
		return nil
	}
	if _, err := service.Control(svc.Stop); err != nil {
		return err
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("it did not stop within 30 seconds")
}

func startService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("%w (run this from an elevated prompt)", err)
	}
	defer manager.Disconnect()

	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the service is not installed")
	}
	defer service.Close()

	if status, err := service.Query(); err == nil && status.State == svc.Running {
		return nil
	}
	return service.Start()
}

func uninstallService() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("%w (run this from an elevated prompt)", err)
	}
	defer manager.Disconnect()

	service, err := manager.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the service is not installed")
	}
	defer service.Close()

	service.Control(svc.Stop)
	return service.Delete()
}

// serviceStopChannel reports when the service manager asks us to stop. Run
// from a command prompt it never fires, and the process ends with Ctrl-C.
func serviceStopChannel() <-chan struct{} {
	stop := make(chan struct{})

	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return stop
	}

	go func() {
		if err := svc.Run(serviceName, &agentService{stop: stop}); err != nil {
			log.Printf("service ended: %v", err)
			close(stop)
		}
	}()
	return stop
}

type agentService struct {
	stop chan struct{}
}

func (s *agentService) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	// PowerEvent is accepted so the agent hears about resume and can poll
	// again immediately, rather than waiting for a dead connection to time out.
	const accepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent

	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			status <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(s.stop)
			return false, 0
		case svc.PowerEvent:
			log.Printf("power event %d", request.EventType)
		default:
		}
	}
	return false, 0
}
