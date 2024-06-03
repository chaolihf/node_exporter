/*
Package utils for node_exporter
*/
package utils

import (
	"os"
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
