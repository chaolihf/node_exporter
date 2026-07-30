// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !nouuseraccounts
// +build !nouuseraccounts

package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const (
	userAccountsSubsystem = "user_accounts"
	passwdPath            = "/etc/passwd"
	shadowPath            = "/etc/shadow"
	sudoersPath           = "/etc/sudoers"
	sudoersDPath          = "/etc/sudoers.d"

	// 指标类型
	MT_All    = 0 // 全量采集
	MT_Add    = 1 // 新增
	MT_Update = 2 // 更新
	MT_Delete = 3 // 删除
)

var (
	// 用户基本信息
	userInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userAccountsSubsystem, "info"),
		"User account information. Value is metric_type, labels contain user details.",
		[]string{"username", "uid", "gid", "gecos", "home", "shell"}, nil,
	)

	// 密码最后修改时间 (Unix 时间戳)
	passwordLastChangeTimestampDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userAccountsSubsystem, "password_last_change_timestamp"),
		"Password last change time as Unix timestamp. Value is metric_type, labels contain username and timestamp.",
		[]string{"username", "timestamp"}, nil,
	)

	// Sudo 权限
	sudoPermissionDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userAccountsSubsystem, "sudo_permission"),
		"User sudo permission status. Value is metric_type, label contains username and permission (1=has sudo, 0=no sudo).",
		[]string{"username", "has_sudo"}, nil,
	)

	// 账户状态 (1=正常，0=锁定/过期)
	accountStatusDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, userAccountsSubsystem, "account_status"),
		"Account status. Value is metric_type, label contains username and status (1=active, 0=locked/expired).",
		[]string{"username", "status"}, nil,
	)
)

// UserAccountFullInfo 用户完整信息
type UserAccountFullInfo struct {
	username            string
	uid                 string
	gid                 string
	gecos               string
	home                string
	shell               string
	lastChangeTimestamp int64
	hasSudo             bool
	accountStatus       int
}

type userAccountInfo struct {
	username string
	uid      string
	gid      string
	gecos    string
	home     string
	shell    string
}

type shadowInfo struct {
	username   string
	lastChange int64 // 天数 (从 1970-01-01 开始)
	minAge     int64
	maxAge     int64
	warnAge    int64
	inactive   int64
	expireDate int64
}

type UserAccountsConfig struct {
	Enable        int  `json:"enable"`   // 0=禁用，1=全量采集，2=增量采集
	Interval      int  `json:"interval"` // 全量采集间隔 (秒)
	CollectUsers  bool `json:"collect_users"`
	CollectShadow bool `json:"collect_shadow"`
	CollectSudo   bool `json:"collect_sudo"`
}

type userAccountsCollector struct {
	logger              log.Logger
	config              UserAccountsConfig
	lineParser          *regexp.Regexp
	lastCollectTime     int64
	lastFullCollectTime int64
	lastUserAccounts    []UserAccountFullInfo
}

func init() {
	registerCollector("user_accounts", defaultEnabled, NewUserAccountsCollector)
}

// NewUserAccountsCollector returns a new Collector exposing user account information.
func NewUserAccountsCollector(logger log.Logger) (Collector, error) {
	// 默认配置
	config := UserAccountsConfig{
		Enable:        1,    // 默认全量采集
		Interval:      3600, // 默认 1 小时全量采集
		CollectUsers:  true,
		CollectShadow: true,
		CollectSudo:   true,
	}

	// 读取配置文件 (可选)
	filePath := "config.json"
	content, err := os.ReadFile(filePath)
	if err != nil {
		level.Debug(logger).Log("msg", "Config file not found, using defaults", "file", filePath)
	} else {
		jsonConfig, err := jjson.NewJsonObject(content)
		if err != nil {
			level.Warn(logger).Log("msg", "Failed to parse config JSON", "err", err)
		} else {
			// 读取 userAccounts 配置
			if jsonUserAccounts := jsonConfig.GetJsonObject("userAccounts"); jsonUserAccounts != nil {
				if jsonEnable := jsonUserAccounts.GetJsonObject("enable"); jsonEnable != nil {
					config.Enable = jsonEnable.GetIntValue()
				}
				if jsonInterval := jsonUserAccounts.GetJsonObject("interval"); jsonInterval != nil {
					config.Interval = jsonInterval.GetIntValue()
				}
				if jsonCollectUsers := jsonUserAccounts.GetJsonObject("collect_users"); jsonCollectUsers != nil {
					config.CollectUsers = jsonCollectUsers.GetBool("")
				}
				if jsonCollectShadow := jsonUserAccounts.GetJsonObject("collect_shadow"); jsonCollectShadow != nil {
					config.CollectShadow = jsonCollectShadow.GetBool("")
				}
				if jsonCollectSudo := jsonUserAccounts.GetJsonObject("collect_sudo"); jsonCollectSudo != nil {
					config.CollectSudo = jsonCollectSudo.GetBool("")
				}
			}
		}
	}

	return &userAccountsCollector{
		logger:              logger,
		config:              config,
		lastCollectTime:     0,
		lastFullCollectTime: 0,
		lastUserAccounts:    nil,
	}, nil
}

func (c *userAccountsCollector) Update(ch chan<- prometheus.Metric) error {
	currentTime := time.Now().Unix()
	var isFullCollect bool

	// 判断是否进行全量采集
	// enable=1: 全量采集; enable=2: 增量采集
	if c.config.Enable == 1 {
		// 全量采集模式：每次都是全量
		isFullCollect = true
	} else if c.config.Enable == 2 {
		// 增量采集模式：根据间隔判断是否全量
		if c.lastFullCollectTime == 0 || currentTime-c.lastFullCollectTime > int64(c.config.Interval) {
			isFullCollect = true
		} else {
			isFullCollect = false
		}
	} else {
		// enable=0: 禁用采集
		return nil
	}

	// Collect user accounts
	users, err := c.readPasswd()
	if err != nil {
		level.Warn(c.logger).Log("msg", "Failed to read passwd file", "err", err)
		return nil
	}

	// Try to read shadow file (may require root)
	shadowMap := make(map[string]*shadowInfo)
	if c.config.CollectShadow && canReadShadow() {
		shadowData, err := c.readShadow()
		if err != nil {
			level.Warn(c.logger).Log("msg", "Failed to read shadow file", "err", err)
		} else {
			for i := range shadowData {
				shadowMap[shadowData[i].username] = &shadowData[i]
			}
		}
	} else if c.config.CollectShadow {
		level.Debug(c.logger).Log("msg", "Cannot read shadow file, insufficient permissions")
	}

	// Check sudo permissions
	sudoUsers := make(map[string]bool)
	if c.config.CollectSudo {
		sudoUsers = c.checkSudoPermissions()
	}

	// 构建当前用户完整信息列表
	currentUsers := make([]UserAccountFullInfo, 0)
	for _, user := range users {
		fullUser := UserAccountFullInfo{
			username: user.username,
			uid:      user.uid,
			gid:      user.gid,
			gecos:    user.gecos,
			home:     user.home,
			shell:    user.shell,
		}

		// 密码最后修改时间 (Unix 时间戳)
		if shadow, ok := shadowMap[user.username]; ok {
			if shadow.lastChange > 0 {
				fullUser.lastChangeTimestamp = shadow.lastChange * 86400
			}
			fullUser.accountStatus = int(c.getAccountStatus(shadow))
		}

		// Sudo 权限
		fullUser.hasSudo = sudoUsers[user.username]

		currentUsers = append(currentUsers, fullUser)
	}

	// 按用户名排序
	sort.Slice(currentUsers, func(i, j int) bool {
		return currentUsers[i].username < currentUsers[j].username
	})

	if isFullCollect {
		// 全量采集：输出所有用户，指标值为 0
		for _, user := range currentUsers {
			c.emitUserMetrics(ch, user, MT_All)
		}
		c.lastFullCollectTime = currentTime
		c.lastUserAccounts = currentUsers
	} else {
		// 增量采集：对比新老数据，输出变化
		addedUsers, updatedUsers, deletedUsers := c.getChangedUsers(currentUsers)

		// 新增用户：指标值为 1
		for _, user := range addedUsers {
			c.emitUserMetrics(ch, user, MT_Add)
		}

		// 更新用户：指标值为 2
		for _, user := range updatedUsers {
			c.emitUserMetrics(ch, user, MT_Update)
		}

		// 删除用户：指标值为 3
		for _, user := range deletedUsers {
			c.emitUserMetrics(ch, user, MT_Delete)
		}

		c.lastUserAccounts = currentUsers
	}

	c.lastCollectTime = currentTime
	return nil
}

// readPasswd reads and parses /etc/passwd file
func (c *userAccountsCollector) readPasswd() ([]userAccountInfo, error) {
	file, err := os.Open(passwdPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open passwd file: %w", err)
	}
	defer file.Close()

	var users []userAccountInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		user := userAccountInfo{
			username: parts[0],
			uid:      parts[1],
			gid:      parts[2],
			gecos:    parts[3],
			home:     parts[4],
			shell:    parts[6],
		}
		users = append(users, user)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading passwd file: %w", err)
	}

	return users, nil
}

// readShadow reads and parses /etc/shadow file
func (c *userAccountsCollector) readShadow() ([]shadowInfo, error) {
	file, err := os.Open(shadowPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open shadow file: %w", err)
	}
	defer file.Close()

	var shadows []shadowInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		shadow := shadowInfo{
			username: parts[0],
		}

		// Parse last change date (days since epoch) - field index 2
		if len(parts) > 2 && parts[2] != "" && parts[2] != "-" {
			if days, err := strconv.ParseInt(parts[2], 10, 64); err == nil {
				shadow.lastChange = days
			}
		}

		// Parse minimum age - field index 3
		if len(parts) > 3 && parts[3] != "" && parts[3] != "-" {
			if days, err := strconv.ParseInt(parts[3], 10, 64); err == nil {
				shadow.minAge = days
			}
		}

		// Parse maximum age - field index 4
		if len(parts) > 4 && parts[4] != "" && parts[4] != "-" {
			if days, err := strconv.ParseInt(parts[4], 10, 64); err == nil {
				shadow.maxAge = days
			}
		}

		// Parse warning age - field index 5
		if len(parts) > 5 && parts[5] != "" && parts[5] != "-" {
			if days, err := strconv.ParseInt(parts[5], 10, 64); err == nil {
				shadow.warnAge = days
			}
		}

		// Parse inactive period - field index 6
		if len(parts) > 6 && parts[6] != "" && parts[6] != "-" {
			if days, err := strconv.ParseInt(parts[6], 10, 64); err == nil {
				shadow.inactive = days
			}
		}

		// Parse expire date - field index 7
		if len(parts) > 7 && parts[7] != "" && parts[7] != "-" {
			if days, err := strconv.ParseInt(parts[7], 10, 64); err == nil {
				shadow.expireDate = days
			}
		}

		shadows = append(shadows, shadow)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading shadow file: %w", err)
	}

	return shadows, nil
}

// canReadShadow checks if the shadow file is readable
func canReadShadow() bool {
	file, err := os.Open(shadowPath)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

// checkSudoPermissions checks which users have sudo permissions
func (c *userAccountsCollector) checkSudoPermissions() map[string]bool {
	sudoUsers := make(map[string]bool)

	// Check main sudoers file
	c.parseSudoersFile(sudoersPath, sudoUsers)

	// Check sudoers.d directory
	if info, err := os.Stat(sudoersDPath); err == nil && info.IsDir() {
		entries, err := os.ReadDir(sudoersDPath)
		if err != nil {
			level.Debug(c.logger).Log("msg", "Failed to read sudoers.d directory", "err", err)
		} else {
			for _, entry := range entries {
				if !entry.IsDir() {
					sudoersFile := filepath.Join(sudoersDPath, entry.Name())
					c.parseSudoersFile(sudoersFile, sudoUsers)
				}
			}
		}
	}

	return sudoUsers
}

// parseSudoersFile parses a sudoers file to find users with sudo permissions
func (c *userAccountsCollector) parseSudoersFile(filePath string, sudoUsers map[string]bool) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip lines that don't contain sudo permissions
		if !strings.Contains(line, "sudo") && !strings.Contains(line, "ALL") {
			continue
		}

		// Parse sudoers format: username/host=(runas) commands
		// Examples:
		//   username ALL=(ALL) ALL
		//   %groupname ALL=(ALL) ALL
		//   username ALL=(ALL:ALL) ALL

		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}

		username := parts[0]
		// Skip group entries (start with %)
		if strings.HasPrefix(username, "%") {
			// For groups, we would need to resolve group members
			// For now, we skip group entries
			continue
		}

		// Check if this line grants sudo permissions
		// Look for pattern: username HOST=(...) commands
		for i, part := range parts {
			if strings.Contains(part, "(") && strings.Contains(part, ")") {
				// Found the runas specification, previous part is username
				if i > 0 {
					sudoUsers[parts[0]] = true
				}
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		level.Debug(c.logger).Log("msg", "Error reading sudoers file", "file", filePath, "err", err)
	}
}

// getAccountStatus determines account status based on shadow info
// Returns: 1 = active, 0 = locked/expired
func (c *userAccountsCollector) getAccountStatus(shadow *shadowInfo) float64 {
	now := time.Now()
	currentDays := int64(now.Sub(time.Unix(0, 0)).Hours() / 24)

	// Check if account is expired
	if shadow.expireDate > 0 && currentDays > shadow.expireDate {
		return 0
	}

	// Check if password has expired
	if shadow.lastChange > 0 && shadow.maxAge > 0 {
		if currentDays > shadow.lastChange+shadow.maxAge {
			return 0
		}
	}

	// Check if account is inactive
	if shadow.inactive > 0 && shadow.lastChange > 0 {
		if currentDays > shadow.lastChange+shadow.maxAge+shadow.inactive {
			return 0
		}
	}

	// Assume active if we can't determine otherwise
	return 1
}

// Check file permissions using unix package
func checkFilePermission(path string) bool {
	// Try to access the file
	return unix.Access(path, unix.R_OK) == nil
}

// emitUserMetrics 输出用户指标
func (c *userAccountsCollector) emitUserMetrics(ch chan<- prometheus.Metric, user UserAccountFullInfo, metricType int) {
	metricTypeFloat := float64(metricType)

	// 用户基本信息 - 值为 metric_type，标签包含用户详情
	ch <- prometheus.MustNewConstMetric(
		userInfoDesc, prometheus.GaugeValue, metricTypeFloat,
		user.username, user.uid, user.gid, user.gecos, user.home, user.shell,
	)

	// 密码最后修改时间 (Unix 时间戳) - 值为 metric_type，标签包含用户名和时间戳
	if user.lastChangeTimestamp > 0 {
		ch <- prometheus.MustNewConstMetric(
			passwordLastChangeTimestampDesc, prometheus.GaugeValue, metricTypeFloat,
			user.username, fmt.Sprintf("%d", user.lastChangeTimestamp),
		)
	}

	// Sudo 权限 - 值为 metric_type，标签包含用户名和权限状态
	hasSudoStr := "0"
	if user.hasSudo {
		hasSudoStr = "1"
	}
	ch <- prometheus.MustNewConstMetric(
		sudoPermissionDesc, prometheus.GaugeValue, metricTypeFloat,
		user.username, hasSudoStr,
	)

	// 账户状态 - 值为 metric_type，标签包含用户名和状态
	statusStr := fmt.Sprintf("%d", user.accountStatus)
	ch <- prometheus.MustNewConstMetric(
		accountStatusDesc, prometheus.GaugeValue, metricTypeFloat,
		user.username, statusStr,
	)
}

// getChangedUsers 比较新老用户数据，获取增量变化
// 返回：新增用户，更新用户，删除用户
func (c *userAccountsCollector) getChangedUsers(newUsers []UserAccountFullInfo) ([]UserAccountFullInfo, []UserAccountFullInfo, []UserAccountFullInfo) {
	var addedUsers []UserAccountFullInfo
	var updatedUsers []UserAccountFullInfo
	var deletedUsers []UserAccountFullInfo

	oldUsers := c.lastUserAccounts
	oldIndex := 0
	newIndex := 0

	for oldIndex < len(oldUsers) && newIndex < len(newUsers) {
		oldUsername := oldUsers[oldIndex].username
		newUsername := newUsers[newIndex].username

		if oldUsername == newUsername {
			// 检查用户信息是否发生变化
			if c.isUserChanged(&oldUsers[oldIndex], &newUsers[newIndex]) {
				updatedUsers = append(updatedUsers, newUsers[newIndex])
			}
			oldIndex++
			newIndex++
		} else if oldUsername < newUsername {
			// 用户被删除
			deletedUsers = append(deletedUsers, oldUsers[oldIndex])
			oldIndex++
		} else {
			// 新增用户
			addedUsers = append(addedUsers, newUsers[newIndex])
			newIndex++
		}
	}

	// 处理剩余的老用户（已删除）
	for oldIndex < len(oldUsers) {
		deletedUsers = append(deletedUsers, oldUsers[oldIndex])
		oldIndex++
	}

	// 处理剩余的新用户（新增）
	for newIndex < len(newUsers) {
		addedUsers = append(addedUsers, newUsers[newIndex])
		newIndex++
	}

	return addedUsers, updatedUsers, deletedUsers
}

// isUserChanged 检查用户信息是否发生变化
func (c *userAccountsCollector) isUserChanged(oldUser, newUser *UserAccountFullInfo) bool {
	// 检查基本信息
	if oldUser.uid != newUser.uid ||
		oldUser.gid != newUser.gid ||
		oldUser.gecos != newUser.gecos ||
		oldUser.home != newUser.home ||
		oldUser.shell != newUser.shell {
		return true
	}

	// 检查密码最后修改时间
	if oldUser.lastChangeTimestamp != newUser.lastChangeTimestamp {
		return true
	}

	// 检查 sudo 权限
	if oldUser.hasSudo != newUser.hasSudo {
		return true
	}

	// 检查账户状态
	if oldUser.accountStatus != newUser.accountStatus {
		return true
	}

	return false
}
