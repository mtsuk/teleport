/*
Copyright 2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package service

import (
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	auditDiskUsed = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "audit_percentage_disk_space_used",
			Help: "Percentage disk space used.",
		},
	)

	auditFailedDisk = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "audit_failed_disk_monitoring",
			Help: "Number of times disk monitoring failed.",
		},
	)
)

func init() {
	// Prometheus metrics have to be registered to be exposed.
	prometheus.MustRegister(auditDiskUsed)
	prometheus.MustRegister(auditFailedDisk)
}

func startDiskMonitor(process *TeleportProcess) {
	ticker := time.NewTicker(defaults.DiskAlertInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Find out what percentage of disk space is used. If the syscall fails,
			// emit that to Prometheus as well.
			usedPercent, err := utils.DiskUsed(process.Config.DataDir)
			if err != nil {
				auditFailedDisk.Inc()
				log.Warnf("Disk space monitoring failed: %v.", err)
				continue
			}

			// Update prometheus gauge with the percentage disk space used.
			auditDiskUsed.Set(usedPercent)

			// If used percentage goes above the alerting level, write to logs as well.
			if usedPercent > float64(defaults.DiskAlertThreshold) {
				log.Warnf("Free disk space for Teleport running low, %v%% of %v used.",
					usedPercent, process.Config.DataDir)
			}
		case <-process.ExitContext().Done():
			return
		}
	}
}
