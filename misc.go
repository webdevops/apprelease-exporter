package main

import (
	"time"
)

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func timeToFloat64(v time.Time) float64 {
	return float64(v.Unix())
}
