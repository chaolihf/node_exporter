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

type SshSession struct {
	client  *ssh.Client
	session *ssh.Session
}

func NewSshSession(hostNameAndPort string, userName string, password string, timeout int) *SshSession {
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
	return &SshSession{
		session: session,
		client:  client,
	}
}

/*
ExecuteCommand 执行命令，当需要
huawei' clear line command is "\x1B[42D"
*/
func (thisSession *SshSession) ExecuteMoreCommand(command string, moreCommand string,
	prompt string, clearLine string, startLine string, endLine string, ignoreEcho bool) (string, error) {
	var result string
	var err error
	if thisSession.session != nil {
		stdin, err := thisSession.session.StdinPipe()
		if err != nil {
			return "Failed to create stdin pipe", err
		}
		stdout, err := thisSession.session.StdoutPipe()
		if err != nil {
			return "Failed to create stdout pipe", err
		}
		if err := thisSession.session.Start(command); err != nil {
			return "Failed to start command", err
		}
		buf := make([]byte, 1024)
		var output bytes.Buffer
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
			if strings.Contains(bufferContent, moreCommand) {
				result = result + strings.Replace(bufferContent, moreCommand, "", 1)
				fmt.Fprintf(stdin, " ")
				time.Sleep(100 * time.Millisecond)
				output.Reset()
			} else {
				firstIndex := strings.Index(bufferContent, prompt)
				if firstIndex != -1 {
					if ignoreEcho {
						ignoreEcho = false
						lastIndex := strings.LastIndex(bufferContent, prompt)
						if firstIndex != lastIndex {
							result = result + strings.Replace(bufferContent, prompt, "", 1)
							break
						} else {
							output.Reset()
							output.WriteString(bufferContent[firstIndex+len(prompt):])
						}
					} else {
						result = result + strings.Replace(bufferContent, prompt, "", 1)
						break
					}
				}
			}
		}
		if len(clearLine) > 0 {
			result = strings.ReplaceAll(result, clearLine, "")
		}
		if len(startLine) > 0 {
			index := strings.Index(result, startLine)
			if index != -1 {
				result = result[index+len(startLine):]
			}
		}
		if len(endLine) > 0 {
			index := strings.Index(result, endLine)
			if index != -1 {
				result = result[:index]
			}
		}
	}
	return result, err
}

func (thisSession *SshSession) ExecuteCommand(command string, startLine string) (string, error) {
	var output []byte
	var err error
	if thisSession.session != nil {
		output, err = thisSession.session.Output(command)
	}
	result := string(output)
	if len(startLine) > 0 {
		index := strings.Index(result, startLine)
		if index != -1 {
			result = result[index+len(startLine):]
		}
	}
	return result, err
}

func (thisSession *SshSession) Close() {
	if thisSession.session != nil {
		thisSession.session.Close()
	}
}

func (thisSession *SshSession) UploadFile(localFilePath string, remoteFilePath string) {
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

func (thisSession *SshSession) DownloadFile(remoteFilePath string, localFilePath string) {
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
