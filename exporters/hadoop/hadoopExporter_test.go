package hadoop

import (
	"fmt"
	"os"
	"testing"
)

func TestGetMetrics(t *testing.T) {
	data, err := os.ReadFile("test/namenode.txt")
	if err != nil {
		t.Fatal(err)
	}
	metrics := ParseContent(data, "NN", false)
	fmt.Println(metrics)
}
