package firewall

import (
	"testing"

	"github.com/chaolihf/node_exporter/pkg/utils"
)

func TestFormat(t *testing.T) {
	metricInfo, err := utils.ReadStringFromFile("test/firewallMetrics.json")
	if err != nil {
		t.Error(err)
	}
	FormatConfigInfo(metricInfo)
}
