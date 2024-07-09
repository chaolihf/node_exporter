/*
Package utils for node_exporter
*/
package utils

import (
	"os"
	"strconv"
	"time"

	"github.com/gofrs/uuid"
)

func ReadStringFromFile(fileName string) (string, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ReadDataFromFile(fileName string) ([]byte, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func GetUUID() string {
	uuid, err := uuid.NewV7()
	if err != nil {
		return strconv.FormatInt(time.Now().UnixMilli(), 10)
	}
	return uuid.String()
}
