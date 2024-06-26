/*
sshclient ssh client library
*/
package sshclient

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bramvdbogaerde/go-scp"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

type SSHConnection struct {
	client *ssh.Client
}

type SSHSession struct {
	client     *SSHConnection
	session    *ssh.Session
	stdinPipe  io.WriteCloser
	stdoutPipe io.Reader
	decoder    *encoding.Decoder
}

var logger log.Logger

func SetLogger(globalLogger log.Logger) {
	logger = globalLogger
}

func NewSSHConnection(hostNameAndPort string, userName string, password string, timeout int) *SSHConnection {
	config := &ssh.ClientConfig{
		User: userName,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeout) * time.Second,
	}
	client, err := ssh.Dial("tcp", hostNameAndPort, config)
	if err != nil {
		level.Error(logger).Log("err", fmt.Sprintf("fail to connect %s,err:%s", hostNameAndPort, err.Error()))
		return nil
	}
	return &SSHConnection{
		client: client,
	}
}

func (thisConnection *SSHConnection) NewSession(encoder string) *SSHSession {
	session, err := thisConnection.client.NewSession()
	if err != nil {
		return nil
	}
	var decoder *encoding.Decoder
	switch strings.ToLower(encoder) {
	case "gbk", "gb2312":
		decoder = simplifiedchinese.GBK.NewDecoder()
	case "GB18030":
		decoder = simplifiedchinese.GB18030.NewDecoder()
	}
	return &SSHSession{
		session: session,
		client:  thisConnection,
		decoder: decoder,
	}
}

func (thisConnection *SSHConnection) CloseConnection() {
	thisConnection.client.Close()
}

func (thisSession *SSHSession) BindInputOutput() error {
	var err error
	if thisSession.stdinPipe == nil {
		thisSession.stdinPipe, err = thisSession.session.StdinPipe()
		if err != nil {
			return err
		}
	}
	if thisSession.stdoutPipe == nil {
		thisSession.stdoutPipe, err = thisSession.session.StdoutPipe()
		if err != nil {
			return err
		}
	}
	return nil
}

/*
ExecuteShellCommand 执行命令，当需要
huawei' clear line command is "\x1B[42D"
*/
func (thisSession *SSHSession) ExecuteShellCommand(command string, moreCommand string,
	prompt string, clearLine string) (string, error) {
	var result string
	var err error
	if thisSession.session != nil {
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := thisSession.session.RequestPty("xterm", 80, 40, modes); err != nil {
			return "Failed to request pseudo-terminal", err
		}
		err = thisSession.BindInputOutput()
		if err != nil {
			return "Failed to create input and output pipe", err
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

func (thisSession *SSHSession) SendShellCommand(command string) error {
	stdin := thisSession.stdinPipe
	_, err := fmt.Fprintln(stdin, command)
	return err
}

func (thisSession *SSHSession) GetShellCommandResult(prompt string,
	moreCommand string, clearLine string) string {
	var result []byte
	buf := make([]byte, 1024)
	var output bytes.Buffer
	stdin := thisSession.stdinPipe
	stdout := thisSession.stdoutPipe
	bytePrompt := []byte(prompt)
	byteMoreCommand := []byte(moreCommand)
	byteClearLine := []byte(clearLine)
	for {
		n, err := stdout.Read(buf)
		if err != nil {
			if err == io.EOF {
				result = bytes.ReplaceAll(result, bytePrompt, nil)
				break
			}
		}
		output.Write(buf[:n])
		bufferContent := output.Bytes()
		if len(moreCommand) > 0 && bytes.Contains(bufferContent, byteMoreCommand) {
			result = append(result, bytes.Replace(bufferContent, byteMoreCommand, nil, 1)...)
			fmt.Fprintf(stdin, " ")
			output.Reset()
		} else {
			firstIndex := bytes.Index(bufferContent, bytePrompt)
			if firstIndex != -1 {
				result = append(result, bytes.Replace(bufferContent, bytePrompt, nil, 1)...)
				break
			}
		}
	}
	if len(clearLine) > 0 {
		result = bytes.ReplaceAll(result, byteClearLine, nil)
	}
	if thisSession.decoder != nil {
		stringResult, err := TranslateContent(result, thisSession.decoder)
		if err != nil {
			level.Error(logger).Log("err", "Error translate content "+err.Error())
			return ""
		} else {
			return stringResult
		}
	} else {
		return string(result)
	}

}

// TranslateContent 使用给定的解码器将字节缓冲区中的内容转换为UTF-8编码的字符串。
// 这个函数接受一个字节数组和一个解码器作为输入，解码器用于将特定编码的字节数组转换为UTF-8。
// 函数返回转换后的UTF-8字符串以及可能出现的错误。
//
// 参数:
//
//	output: 一个[]byte类型的实例，包含需要转换的字节数组。
//	decoder: 一个*encoding.Decoder类型的指针，用于将字节数组解码为UTF-8。
//
// 返回值:
//
//	string: 转换后的UTF-8编码字符串。
//	error: 如果在读取或转换过程中发生错误，则返回该错误；否则返回nil。
func TranslateContent(content []byte, decoder *encoding.Decoder) (string, error) {
	reader := transform.NewReader(bytes.NewReader(content), decoder)
	utfData, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(utfData), nil
}

func (thisSession *SSHSession) ExecuteSingleCommand(command string) (string, error) {
	var output []byte
	var err error
	if thisSession.session != nil {
		output, err = thisSession.session.Output(command)
	}
	result := string(output)
	return result, err
}

func (thisSession *SSHSession) CloseSession() {
	if thisSession.session != nil {
		if thisSession.stdinPipe != nil {
			thisSession.stdinPipe.Close()
		}
		thisSession.session.Close()
		thisSession.session = nil
		thisSession.stdoutPipe = nil
		thisSession.stdinPipe = nil

	}
}

func (thisSession *SSHSession) UploadFile(localFilePath string, remoteFilePath string) {
	sftpClient, err := sftp.NewClient(thisSession.client.client)
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
	client, err := scp.NewClientBySSH(thisSession.client.client)
	if err != nil {
		fmt.Println("Error creating new SSH session from existing connection", err)
	} else {
		localFile, err := os.Open(localFilePath)
		if err != nil {
			level.Error(logger).Log("err", "Error opening local file"+err.Error())
			return
		}
		client.CopyFromRemote(nil, localFile, remoteFilePath)
	}
}
