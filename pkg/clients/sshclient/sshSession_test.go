package sshclient

import (
	"os"
	"testing"
)

func TestH3Client(t *testing.T) {
	client := NewSSHConnection("", "", "", 30)
	defer client.CloseConnection()
	session := client.NewSession("gbk")
	defer session.CloseSession()
	file, err := os.Create("log.txt")
	if err != nil {
		t.Errorf("Create file failed, error: %s", err)
	}
	defer file.Close()
	content, err := session.ExecuteShellCommand("display current-configuration", "---- More ----",
		"<TDL3F-H8-Eud1000E-1>", "")
	if err != nil {
		t.Errorf("ExecuteShellCommand failed, error: %s", err)
	}
	file.WriteString(content)
	session.SendShellCommand("display zone")
	content = session.GetShellCommandResult("<TDL3F-H8-Eud1000E-1>", "---- More ----", "")
	file.WriteString(content)
	session.CloseSession()
}
