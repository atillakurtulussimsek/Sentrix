package protocol

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestValidateRejectsUnknownAndRaw(t *testing.T) {
	cases := []Command{
		{ID: "a1", Action: "shell", Params: json.RawMessage(`{"cmd":"rm -rf /"}`)},
		{ID: "a1", Action: "exec"},
		{ID: "a1", Action: "run_command", Params: json.RawMessage(`"id"`)},
		{ID: "a1", Action: ""},
		{ID: "a1", Action: "REBOOT"},
	}
	for _, c := range cases {
		if err := c.Validate(); !errors.Is(err, ErrUnknownAction) {
			t.Errorf("%q: want ErrUnknownAction, got %v", c.Action, err)
		}
	}
}

func TestValidateParams(t *testing.T) {
	cases := []struct {
		name string
		cmd  Command
		ok   bool
	}{
		{"scan", Command{ID: "x", Action: ActionScan}, true},
		{"scan extra field", Command{ID: "x", Action: ActionScan, Params: json.RawMessage(`{"cmd":"id"}`)}, false},
		{"pkgs ok", Command{ID: "x", Action: ActionPatchPackages, Params: json.RawMessage(`{"packages":["openssl","libc6:amd64"]}`)}, false},
		{"pkgs ok2", Command{ID: "x", Action: ActionPatchPackages, Params: json.RawMessage(`{"packages":["openssl","g++-12"]}`)}, true},
		{"pkgs injection", Command{ID: "x", Action: ActionPatchPackages, Params: json.RawMessage(`{"packages":["openssl; rm -rf /"]}`)}, false},
		{"pkgs option", Command{ID: "x", Action: ActionPatchPackages, Params: json.RawMessage(`{"packages":["--allow-downgrades"]}`)}, false},
		{"pkgs empty", Command{ID: "x", Action: ActionPatchPackages, Params: json.RawMessage(`{"packages":[]}`)}, false},
		{"pkgs extra", Command{ID: "x", Action: ActionPatchPackages, Params: json.RawMessage(`{"packages":["a"],"args":"-y"}`)}, false},
		{"svc ok", Command{ID: "x", Action: ActionRestartService, Params: json.RawMessage(`{"name":"nginx.service"}`)}, true},
		{"svc inst", Command{ID: "x", Action: ActionRestartService, Params: json.RawMessage(`{"name":"getty@tty1.service"}`)}, true},
		{"svc bad", Command{ID: "x", Action: ActionRestartService, Params: json.RawMessage(`{"name":"nginx && reboot"}`)}, false},
		{"svc dash", Command{ID: "x", Action: ActionRestartService, Params: json.RawMessage(`{"name":"-H root@x"}`)}, false},
		{"reboot", Command{ID: "x", Action: ActionReboot}, true},
		{"reboot neg", Command{ID: "x", Action: ActionReboot, Params: json.RawMessage(`{"delay_seconds":-1}`)}, false},
		{"bad id", Command{ID: "../x", Action: ActionScan}, false},
	}
	for _, tc := range cases {
		err := tc.cmd.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: ok=%v err=%v", tc.name, tc.ok, err)
		}
	}
}
