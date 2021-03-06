package test

import corev1 "k8s.io/api/core/v1"

func AssertNodeCoherency(received, expected *corev1.Node) bool {
	if received.Name != expected.Name {
		return false
	}

	if len(received.Status.Capacity) != len(expected.Status.Capacity) {
		return false
	}

	if len(received.Status.Allocatable) != len(expected.Status.Allocatable) {
		return false
	}

	for r1, q1 := range received.Status.Capacity {
		if q2, ok := expected.Status.Capacity[r1]; !ok || q1.Value() != q2.Value() {
			return false
		}
	}

	for r1, q1 := range received.Status.Allocatable {
		if q2, ok := expected.Status.Allocatable[r1]; !ok || q1.Value() != q2.Value() {
			return false
		}
	}

	if len(received.Status.Conditions) != len(expected.Status.Conditions) {
		return false
	}

	for _, c1 := range received.Status.Conditions {
		for _, c2 := range expected.Status.Conditions {
			if c1.Type == c2.Type && c1.Status != c2.Status {
				return false
			}
		}
	}

	return true
}
