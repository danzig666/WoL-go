//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"fyne.io/systray"
	"golang.org/x/sys/windows/registry"
)

//go:embed data/icon.ico
var trayIcon []byte

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runKeyName = "WoL-go"

// waitForShutdown shows the tray icon and blocks until the user chooses Quit.
// The systray event loop must own the main goroutine, which is why the HTTP
// server is started before this is called.
func waitForShutdown(url string) {
	if noTray {
		waitForSignal()
		return
	}

	systray.Run(func() { onTrayReady(url) }, func() {})
}

func onTrayReady(url string) {
	systray.SetIcon(trayIcon)
	systray.SetTitle("Wake-on-LAN")
	systray.SetTooltip("Wake-on-LAN\n" + url)

	open := systray.AddMenuItem("Open control panel", "Open the web interface in your browser")
	open.SetIcon(trayIcon)
	systray.AddSeparator()

	wakeAll := systray.AddMenuItem("Wake all computers", "Send a wake-up signal to every saved computer")
	systray.AddSeparator()

	address := systray.AddMenuItem(url, "The address of the control panel")
	address.Disable()
	showLog := systray.AddMenuItem("Open log file", "Open wol.log")

	startup := systray.AddMenuItemCheckbox("Start with Windows", "Run automatically when you sign in", startupEnabled())
	systray.AddSeparator()

	quit := systray.AddMenuItem("Quit", "Stop the service and close")

	go func() {
		for {
			select {
			case <-open.ClickedCh:
				openBrowser(url)

			case <-wakeAll.ClickedCh:
				woken, total := wakeEverything()
				notify("Wake-on-LAN",
					fmt.Sprintf("Sent a wake-up signal to %d of %d computers.", woken, total))

			case <-showLog.ClickedCh:
				openPath(logFilePath())

			case <-startup.ClickedCh:
				// Toggling only ever touches this user's own Run key, and only
				// when the menu item is clicked.
				if startup.Checked() {
					if err := setStartup(false); err != nil {
						log.Printf("Could not remove the startup entry: %v", err)
						notify("Wake-on-LAN", "Could not change the startup setting.")
						continue
					}
					startup.Uncheck()
				} else {
					if err := setStartup(true); err != nil {
						log.Printf("Could not add the startup entry: %v", err)
						notify("Wake-on-LAN", "Could not change the startup setting.")
						continue
					}
					startup.Check()
				}

			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// wakeEverything is the tray's own wake-all, calling straight into the wake
// code rather than looping back through HTTP and its authentication.
func wakeEverything() (woken int, total int) {
	devices, err := loadDevices()
	if err != nil {
		log.Printf("Could not load devices: %v", err)
		return 0, 0
	}
	for _, d := range devices {
		if err := sendMagicPacket(d.MAC, d.Broadcast, d.Port, d.IP); err != nil {
			log.Printf("Error waking %s: %v", d.Name, err)
			continue
		}
		recordWake(d.ID, "tray menu")
		woken++
	}
	return woken, len(devices)
}

func openBrowser(url string) {
	// rundll32 hands the URL to whatever the user's default browser is,
	// without going through a shell.
	if err := hiddenCommand("rundll32", "url.dll,FileProtocolHandler", url).Start(); err != nil {
		log.Printf("Could not open the browser: %v", err)
	}
}

func openPath(path string) {
	if err := hiddenCommand("rundll32", "url.dll,FileProtocolHandler", path).Start(); err != nil {
		log.Printf("Could not open %s: %v", path, err)
	}
}

func logFilePath() string {
	abs, err := filepath.Abs(dataPath("wol.log"))
	if err != nil {
		return dataPath("wol.log")
	}
	return abs
}

func startupEnabled() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	value, _, err := key.GetStringValue(runKeyName)
	return err == nil && value != ""
}

func setStartup(enabled bool) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if !enabled {
		err := key.DeleteValue(runKeyName)
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Quoted so a path containing spaces still starts correctly.
	return key.SetStringValue(runKeyName, `"`+exe+`"`)
}

// --- Message boxes ---

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procGetConsole  = kernel32.NewProc("GetConsoleWindow")
)

const (
	mbOK            = 0x00000000
	mbIconInfo      = 0x00000040
	mbSetForeground = 0x00010000
	mbTopMost       = 0x00040000
	mbSystemModal   = 0x00001000
)

func messageBox(caption, text string, flags uint32) {
	captionPtr, err := syscall.UTF16PtrFromString(caption)
	if err != nil {
		return
	}
	textPtr, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(textPtr)), uintptr(unsafe.Pointer(captionPtr)), uintptr(flags))
}

func notify(caption, text string) {
	go messageBox(caption, text, mbOK|mbIconInfo|mbSetForeground|mbTopMost)
}

// hasConsole reports whether a console window is attached. Built with
// -H windowsgui there is none, so anything printed to stdout is invisible.
func hasConsole() bool {
	handle, _, _ := procGetConsole.Call()
	return handle != 0
}

// announceFirstRun makes sure the generated password reaches the user even
// when the program was started without a console, where printing it would
// simply lose it.
func announceFirstRun(password, url string) {
	if password == "" || hasConsole() {
		return
	}
	text := strings.Join([]string{
		"A new administrator account has been created.",
		"",
		"",
		"    Address:   " + url,
		"    Username:  admin",
		"    Password:  " + password,
		"",
		"Write this password down now - it is shown only once,",
		"and you will be asked to change it when you first sign in.",
		"",
		"It has also been saved to " + logFilePath(),
	}, "\n")
	// Shown on its own thread: MessageBox runs a modal loop until it is
	// dismissed, and blocking here would hold up the tray icon.
	go messageBox("Wake-on-LAN - first run", text, mbOK|mbIconInfo|mbSetForeground|mbTopMost)
}
