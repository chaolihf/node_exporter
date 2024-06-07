package sshclient

import (
	"fmt"
	"log"
	"testing"
)

func TestH3Client(t *testing.T) {
	client := NewSSHConnection("134.95.237.121:2223", "nmread", "Siemens#202405", 30)
	defer client.CloseConnection()
	session := client.NewSession()
	// 请求创建伪终端
	// modes := ssh.TerminalModes{
	// 	ssh.ECHO:          0,     // disable echoing
	// 	ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
	// 	ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	// }
	// if err := session.session.RequestPty("xterm", 80, 40, modes); err != nil {
	// 	log.Fatalf("Failed to request pseudo-terminal: %v", err)
	// }
	session.BindInputOutput()
	if err := session.session.Shell(); err != nil {
		log.Fatalf("Failed to run command:%v", err)
	}
	session.GetShellCommandResult("<TDL_3FK5_6900>", "---- More ----", "")
	session.SendShellCommand("display arp")
	fmt.Println(session.GetShellCommandResult("<TDL_3FK5_6900>", "---- More ----", ""))
	session.SendShellCommand("display mac-address")
	fmt.Println(session.GetShellCommandResult("<TDL_3FK5_6900>", "---- More ----", ""))
	session.CloseSession()
}
