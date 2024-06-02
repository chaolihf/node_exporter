package sshclient

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bramvdbogaerde/go-scp"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type SSHSession struct {
	client     *ssh.Client
	session    *ssh.Session
	stdinPipe  io.WriteCloser
	stdoutPipe io.Reader
}

func NewSSHSession(hostNameAndPort string, userName string, password string, timeout int) *SSHSession {
	config := &ssh.ClientConfig{
		User: userName,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", hostNameAndPort, config)
	if err != nil {
		return nil
	}
	session, err := client.NewSession()
	if err != nil {
		return nil
	}
	return &SSHSession{
		session: session,
		client:  client,
	}
}

/*
ExecuteCommand
执行命令，当需要
huawei' clear line command is "\x1B[42D"
*/
func (thisSession *SSHSession) ExecuteShellCommand(command string, moreCommand string,
	prompt string, clearLine string) (string, error) {
	var result string
	var err error
	if thisSession.session != nil {
		if thisSession.stdinPipe == nil {
			thisSession.stdinPipe, err = thisSession.session.StdinPipe()
			if err != nil {
				return "Failed to create stdin pipe", err
			}
		}
		if thisSession.stdoutPipe == nil {
			thisSession.stdoutPipe, err = thisSession.session.StdoutPipe()
			if err != nil {
				return "Failed to create stdout pipe", err
			}
		}
		if err := thisSession.session.Shell(); err != nil {
			return "Failed to run command", err
		} else {
			thisSession.GetShellCommandResult(prompt, "", "")
			err = thisSession.SendShellCommand(command)
			if err != nil {
				return "Failed to send command ", err
			}
		}
		result = thisSession.GetShellCommandResult(prompt, moreCommand, clearLine)
		// if len(startLine) > 0 {
		// 	index := strings.Index(result, startLine)
		// 	if index != -1 {
		// 		result = result[index+len(startLine):]
		// 	}
		// }
		// if len(endLine) > 0 {
		// 	index := strings.Index(result, endLine)
		// 	if index != -1 {
		// 		result = result[:index]
		// 	}
		// }
	}
	return result, err
}

func (thisSesion *SSHSession) SendShellCommand(command string) error {
	stdin := thisSesion.stdinPipe
	_, err := fmt.Fprintln(stdin, command)
	return err
}

func (thisSesion *SSHSession) GetShellCommandResult(prompt string,
	moreCommand string, clearLine string) string {
	var result string
	buf := make([]byte, 1024)
	var output bytes.Buffer
	stdin := thisSesion.stdinPipe
	stdout := thisSesion.stdoutPipe
	for {
		n, err := stdout.Read(buf)
		if err != nil {
			if err == io.EOF {
				result = strings.Replace(output.String(), prompt, "", 1)
				break
			}
		}
		output.Write(buf[:n])
		bufferContent := output.String()
		if len(moreCommand) > 0 && strings.Contains(bufferContent, moreCommand) {
			result = result + strings.Replace(bufferContent, moreCommand, "", 1)
			fmt.Fprintf(stdin, " ")
			time.Sleep(100 * time.Millisecond)
			output.Reset()
		} else {
			firstIndex := strings.Index(bufferContent, prompt)
			if firstIndex != -1 {
				result = result + strings.Replace(bufferContent, prompt, "", 1)
				break
			}
		}
	}
	if len(clearLine) > 0 {
		result = strings.ReplaceAll(result, clearLine, "")
	}
	return result
}

func (thisSession *SSHSession) ExecuteSingleCommand(command string, startLine string) (string, error) {
	var output []byte
	var err error
	if thisSession.session != nil {
		output, err = thisSession.session.Output(command)
	}
	result := string(output)
	// if len(startLine) > 0 {
	// 	index := strings.Index(result, startLine)
	// 	if index != -1 {
	// 		result = result[index+len(startLine):]
	// 	}
	// }
	return result, err
}

func (thisSession *SSHSession) CloseSession() {
	if thisSession.session != nil {
		thisSession.stdinPipe.Close()
		thisSession.session.Close()
		thisSession.session = nil
		thisSession.stdoutPipe = nil
		thisSession.stdinPipe = nil
	}
}

func (thisSession *SSHSession) UploadFile(localFilePath string, remoteFilePath string) {
	sftpClient, err := sftp.NewClient(thisSession.client)
	if err != nil {
		return
	}
	defer sftpClient.Close()
	srcFile, err := os.Open(localFilePath)
	if err != nil {
		return
	}
	defer srcFile.Close()
}

func (thisSession *SSHSession) DownloadFile(remoteFilePath string, localFilePath string) {
	client, err := scp.NewClientBySSH(thisSession.client)
	if err != nil {
		fmt.Println("Error creating new SSH session from existing connection", err)
	} else {
		localFile, err := os.Open(localFilePath)
		if err != nil {
			fmt.Println("Error opening local file", err)
			return
		}
		client.CopyFromRemote(nil, localFile, remoteFilePath)
	}
}
