package policyreason

import "testing"

func TestBuildStableMatcherOrderAndSanitization(t *testing.T) {
	rule := Rule{APN: "Enterprise..APN/_One", QCI: 8, ARPPriorityMin: 4, ARPPriorityMax: 6, BearerType: "Dedicated", IdleSeconds: 300}
	want := "bearer-inactivity-cleanup-apn-enterprise-apn-one-qci-8-arp-4-6-dedicated-idle-300"
	if got := Build("Bearer Inactivity", "Cleanup", rule); got != want {
		t.Fatalf("Build() = %q, want %q", got, want)
	}
}

func TestBuildExamples(t *testing.T) {
	tests := []struct {
		feature, action string
		rule            Rule
		want            string
	}{
		{"mme-restoration", "preserve", Rule{APN: "ims"}, "mme-restoration-preserve-apn-ims"},
		{"mme-restoration", "preserve", Rule{QCI: 1}, "mme-restoration-preserve-qci-1"},
		{"mme-restoration", "preserve", Rule{ARPPriorityMin: 1, ARPPriorityMax: 3}, "mme-restoration-preserve-arp-1-3"},
		{"mme-restoration", "delete", Rule{APN: "internet", QCI: 9}, "mme-restoration-delete-apn-internet-qci-9"},
		{"ddn", "high-priority", Rule{APN: "ims"}, "ddn-high-priority-apn-ims"},
		{"ddn", "high-priority", Rule{QCI: 1}, "ddn-high-priority-qci-1"},
		{"ddn", "high-priority", Rule{ARPPriorityMin: 1, ARPPriorityMax: 3}, "ddn-high-priority-arp-1-3"},
		{"ddn", "low-priority", Rule{APN: "internet", QCI: 9}, "ddn-low-priority-apn-internet-qci-9"},
		{"idle-downlink", "high-priority", Rule{APN: "ims"}, "idle-downlink-high-priority-apn-ims"},
		{"idle-downlink", "suppress", Rule{APN: "internet", QCI: 9}, "idle-downlink-suppress-apn-internet-qci-9"},
		{"bearer-inactivity", "preserve", Rule{APN: "ims", QCI: 5, BearerType: "default"}, "bearer-inactivity-preserve-apn-ims-qci-5-default"},
		{"bearer-inactivity", "cleanup", Rule{BearerType: "dedicated", IdleSeconds: 300}, "bearer-inactivity-cleanup-dedicated-idle-300"},
	}
	for _, tt := range tests {
		if got := Build(tt.feature, tt.action, tt.rule); got != tt.want {
			t.Errorf("Build(%s,%s) = %q, want %q", tt.feature, tt.action, got, tt.want)
		}
	}
}
